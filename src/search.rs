use std::sync::Arc;
use crate::apis::{PaperResult, PaperSource};

/// Perform federated search across multiple sources in parallel,
/// deduplicate by DOI and title similarity, and rank results.
pub async fn federated_search(
    sources: &[Arc<dyn PaperSource>],
    query: &str,
    max_results: u32,
    source_filter: Option<&[String]>,
) -> Vec<PaperResult> {
    let active_sources: Vec<_> = sources
        .iter()
        .filter(|s| {
            source_filter
                .map(|f| f.iter().any(|name| name.eq_ignore_ascii_case(s.name())))
                .unwrap_or(true)
        })
        .collect();

    if active_sources.is_empty() {
        return Vec::new();
    }

    // Query all sources in parallel
    let per_source = (max_results * 2 / active_sources.len() as u32).max(5);
    let futures: Vec<_> = active_sources
        .iter()
        .map(|source| {
            let source = Arc::clone(source);
            let query = query.to_string();
            tokio::spawn(async move { source.search(&query, per_source).await })
        })
        .collect();

    let mut all_results = Vec::new();
    for handle in futures {
        match handle.await {
            Ok(Ok(results)) => all_results.extend(results),
            Ok(Err(e)) => tracing::warn!("Source search failed: {}", e),
            Err(e) => tracing::warn!("Source task panicked: {}", e),
        }
    }

    // Deduplicate and rank
    deduplicate_and_rank(all_results, max_results as usize)
}

/// Deduplicate results by DOI (exact) and title similarity, then rank.
fn deduplicate_and_rank(mut results: Vec<PaperResult>, limit: usize) -> Vec<PaperResult> {
    if results.is_empty() {
        return results;
    }

    let mut seen_dois: std::collections::HashSet<String> = std::collections::HashSet::new();
    let mut deduped: Vec<PaperResult> = Vec::new();

    // Sort by metadata richness first (prefer papers with more fields filled)
    results.sort_by(|a, b| metadata_score(b).cmp(&metadata_score(a)));

    for paper in results {
        // Check DOI dedup
        if let Some(ref doi) = paper.doi {
            let doi_lower = doi.to_lowercase();
            if seen_dois.contains(&doi_lower) {
                continue;
            }
            seen_dois.insert(doi_lower);
        } else {
            // Check title similarity against existing
            let normalized = normalize_title(&paper.title);
            if deduped.iter().any(|p| {
                let d = strsim::levenshtein(&normalized, &normalize_title(&p.title));
                d < 5
            }) {
                continue;
            }
        }
        deduped.push(paper);
    }

    // Rank: citation count descending, then year descending
    deduped.sort_by(|a, b| {
        let ca = a.citation_count.unwrap_or(0);
        let cb = b.citation_count.unwrap_or(0);
        cb.cmp(&ca)
            .then_with(|| b.year.unwrap_or(0).cmp(&a.year.unwrap_or(0)))
    });

    deduped.truncate(limit);
    deduped
}

/// Score metadata richness (higher = more complete).
fn metadata_score(p: &PaperResult) -> u32 {
    let mut score = 0u32;
    if !p.title.is_empty() { score += 1; }
    if !p.authors.is_empty() { score += 1; }
    if p.abstract_text.is_some() { score += 2; }
    if p.year.is_some() { score += 1; }
    if p.doi.is_some() { score += 2; }
    if p.citation_count.is_some() { score += 1; }
    if p.pdf_url.is_some() { score += 1; }
    score
}

fn normalize_title(title: &str) -> String {
    title
        .to_lowercase()
        .chars()
        .filter(|c| c.is_alphanumeric() || c.is_whitespace())
        .collect::<String>()
        .split_whitespace()
        .collect::<Vec<_>>()
        .join(" ")
}

#[cfg(test)]
mod tests {
    use super::*;

    fn paper(id: &str, title: &str, doi: Option<&str>, citations: Option<u32>) -> PaperResult {
        PaperResult {
            id: id.to_string(),
            title: title.to_string(),
            authors: vec![],
            abstract_text: None,
            year: Some(2024),
            source: "test".to_string(),
            doi: doi.map(|s| s.to_string()),
            arxiv_id: None,
            url: "".to_string(),
            pdf_url: None,
            citation_count: citations,
        }
    }

    #[test]
    fn test_dedup_by_doi() {
        let results = vec![
            paper("s2:1", "Paper A", Some("10.1234/a"), Some(10)),
            paper("arxiv:1", "Paper A (arxiv)", Some("10.1234/a"), None),
            paper("s2:2", "Paper B", Some("10.1234/b"), Some(5)),
        ];
        let deduped = deduplicate_and_rank(results, 10);
        assert_eq!(deduped.len(), 2);
    }

    #[test]
    fn test_dedup_by_title() {
        let results = vec![
            paper("s2:1", "Quantum Error Correction Codes", None, Some(10)),
            paper("arxiv:1", "Quantum Error Correction codes", None, None),
        ];
        let deduped = deduplicate_and_rank(results, 10);
        assert_eq!(deduped.len(), 1);
    }

    #[test]
    fn test_rank_by_citations() {
        let results = vec![
            paper("a", "Low Cited", None, Some(1)),
            paper("b", "High Cited Different Title", None, Some(100)),
            paper("c", "Medium Cited Unique Paper", None, Some(50)),
        ];
        let ranked = deduplicate_and_rank(results, 10);
        assert_eq!(ranked[0].id, "b");
        assert_eq!(ranked[1].id, "c");
        assert_eq!(ranked[2].id, "a");
    }
}
