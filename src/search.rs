use crate::apis::{normalize_date_string, PaperResult, PaperSource, SearchOptions, SearchSort};
use chrono::{Datelike, NaiveDate, Utc};
use std::collections::HashMap;
use std::sync::Arc;

const RRF_K: f32 = 60.0;
const HYBRID_TAU_DAYS: f32 = 30.0;

#[derive(Debug)]
struct AggregatedPaper {
    canonical: PaperResult,
    relevance_score: f32,
    citation_count: u32,
    ranking_date: Option<NaiveDate>,
}

/// Perform federated search across multiple sources in parallel,
/// deduplicate by DOI and title similarity, and rank.
pub async fn federated_search(
    sources: &[Arc<dyn PaperSource>],
    query: &str,
    max_results: u32,
    source_filter: Option<&[String]>,
    options: &SearchOptions,
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

    let per_source = (max_results * 3 / active_sources.len() as u32).max(10);
    let futures: Vec<_> = active_sources
        .iter()
        .map(|source| {
            let source = Arc::clone(source);
            let query = query.to_string();
            let options = options.clone();
            tokio::spawn(async move { source.search(&query, per_source, &options).await })
        })
        .collect();

    let mut all_results = Vec::new();
    for handle in futures {
        match handle.await {
            Ok(Ok(results)) => all_results.push(results),
            Ok(Err(e)) => tracing::warn!("Source search failed: {}", e),
            Err(e) => tracing::warn!("Source task panicked: {}", e),
        }
    }

    deduplicate_and_rank(all_results, max_results as usize, options)
}

fn deduplicate_and_rank(
    source_results: Vec<Vec<PaperResult>>,
    limit: usize,
    options: &SearchOptions,
) -> Vec<PaperResult> {
    if source_results.is_empty() {
        return Vec::new();
    }

    let mut grouped: HashMap<String, AggregatedPaper> = HashMap::new();

    for results in source_results {
        for (rank, mut paper) in results.into_iter().enumerate() {
            normalize_paper_dates(&mut paper);
            let key = dedupe_key(&paper);
            let ranking_date = parse_rank_date(&paper);
            let entry = grouped.entry(key).or_insert_with(|| AggregatedPaper {
                citation_count: paper.citation_count.unwrap_or(0),
                ranking_date,
                relevance_score: 0.0,
                canonical: paper.clone(),
            });

            entry.relevance_score += reciprocal_rank(rank);
            entry.citation_count = entry
                .citation_count
                .max(paper.citation_count.unwrap_or_default());
            entry.ranking_date = choose_ranking_date(entry.ranking_date, ranking_date);

            if metadata_score(&paper) > metadata_score(&entry.canonical) {
                entry.canonical = paper;
            }
        }
    }

    let mut deduped: Vec<AggregatedPaper> = grouped
        .into_values()
        .filter_map(|mut item| {
            item.ranking_date = choose_ranking_date(item.ranking_date, parse_rank_date(&item.canonical));
            if !matches_date_filter(item.ranking_date, options) {
                return None;
            }

            if let Some(date) = item.ranking_date {
                let normalized = date.format("%Y-%m-%d").to_string();
                item.canonical.published_at = Some(normalized.clone());
                item.canonical.ranking_date = Some(normalized);
                if item.canonical.year.is_none() {
                    item.canonical.year = Some(date.year() as u32);
                }
            }

            Some(item)
        })
        .collect();

    sort_results(&mut deduped, options);
    deduped
        .into_iter()
        .take(limit)
        .map(|item| item.canonical)
        .collect()
}

fn reciprocal_rank(rank: usize) -> f32 {
    1.0 / (RRF_K + rank as f32 + 1.0)
}

fn dedupe_key(paper: &PaperResult) -> String {
    if let Some(ref doi) = paper.doi {
        format!("doi:{}", doi.to_lowercase())
    } else {
        format!("title:{}", normalize_title(&paper.title))
    }
}

fn metadata_score(p: &PaperResult) -> u32 {
    let mut score = 0u32;
    if !p.title.is_empty() {
        score += 1;
    }
    if !p.authors.is_empty() {
        score += 1;
    }
    if p.abstract_text.is_some() {
        score += 2;
    }
    if p.year.is_some() {
        score += 1;
    }
    if p.published_at.is_some() {
        score += 1;
    }
    if p.doi.is_some() {
        score += 2;
    }
    if p.citation_count.is_some() {
        score += 1;
    }
    if p.pdf_url.is_some() {
        score += 1;
    }
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

fn normalize_paper_dates(paper: &mut PaperResult) {
    if let Some(date) = paper
        .published_at
        .as_deref()
        .and_then(normalize_date_string)
        .or_else(|| {
            paper.year.and_then(|year| {
                NaiveDate::from_ymd_opt(year as i32, 1, 1)
                    .map(|d| d.format("%Y-%m-%d").to_string())
            })
        })
    {
        paper.published_at = Some(date.clone());
        paper.ranking_date = Some(date);
    } else {
        paper.ranking_date = None;
    }
}

fn parse_rank_date(paper: &PaperResult) -> Option<NaiveDate> {
    paper
        .ranking_date
        .as_deref()
        .or(paper.published_at.as_deref())
        .and_then(normalize_date_string)
        .and_then(|s| NaiveDate::parse_from_str(&s, "%Y-%m-%d").ok())
        .or_else(|| {
            paper
                .year
                .and_then(|year| NaiveDate::from_ymd_opt(year as i32, 1, 1))
        })
}

fn choose_ranking_date(a: Option<NaiveDate>, b: Option<NaiveDate>) -> Option<NaiveDate> {
    match (a, b) {
        (Some(left), Some(right)) => Some(left.min(right)),
        (Some(left), None) => Some(left),
        (None, Some(right)) => Some(right),
        (None, None) => None,
    }
}

fn matches_date_filter(date: Option<NaiveDate>, options: &SearchOptions) -> bool {
    if options.date_from.is_none() && options.date_to.is_none() {
        return true;
    }
    let Some(date) = date else {
        return false;
    };
    if let Some(from) = options.date_from {
        if date < from {
            return false;
        }
    }
    if let Some(to) = options.date_to {
        if date > to {
            return false;
        }
    }
    true
}

fn sort_results(results: &mut [AggregatedPaper], options: &SearchOptions) {
    let today = Utc::now().date_naive();
    let max_relevance = results
        .iter()
        .map(|item| item.relevance_score)
        .fold(0.0_f32, f32::max)
        .max(1.0);

    results.sort_by(|a, b| match options.sort {
        SearchSort::Relevance => b
            .relevance_score
            .partial_cmp(&a.relevance_score)
            .unwrap_or(std::cmp::Ordering::Equal)
            .then_with(|| b.citation_count.cmp(&a.citation_count))
            .then_with(|| b.ranking_date.cmp(&a.ranking_date)),
        SearchSort::DateDesc => b
            .ranking_date
            .cmp(&a.ranking_date)
            .then_with(|| {
                b.relevance_score
                    .partial_cmp(&a.relevance_score)
                    .unwrap_or(std::cmp::Ordering::Equal)
            })
            .then_with(|| b.citation_count.cmp(&a.citation_count)),
        SearchSort::DateAsc => a
            .ranking_date
            .cmp(&b.ranking_date)
            .then_with(|| {
                b.relevance_score
                    .partial_cmp(&a.relevance_score)
                    .unwrap_or(std::cmp::Ordering::Equal)
            })
            .then_with(|| b.citation_count.cmp(&a.citation_count)),
        SearchSort::Hybrid => hybrid_score(b, today, max_relevance)
            .partial_cmp(&hybrid_score(a, today, max_relevance))
            .unwrap_or(std::cmp::Ordering::Equal)
            .then_with(|| b.ranking_date.cmp(&a.ranking_date))
            .then_with(|| b.citation_count.cmp(&a.citation_count)),
    });
}

fn hybrid_score(item: &AggregatedPaper, today: NaiveDate, max_relevance: f32) -> f32 {
    let relevance = item.relevance_score / max_relevance;
    let freshness = item
        .ranking_date
        .map(|date| {
            let age_days = (today - date).num_days().max(0) as f32;
            (-age_days / HYBRID_TAU_DAYS).exp()
        })
        .unwrap_or(0.0);
    0.7 * relevance + 0.3 * freshness
}

#[cfg(test)]
mod tests {
    use super::*;

    fn paper(
        id: &str,
        title: &str,
        doi: Option<&str>,
        citations: Option<u32>,
        published_at: Option<&str>,
    ) -> PaperResult {
        PaperResult {
            id: id.to_string(),
            title: title.to_string(),
            authors: vec![],
            abstract_text: None,
            year: published_at.and_then(|s| s.get(..4)).and_then(|y| y.parse().ok()),
            source: "test".to_string(),
            doi: doi.map(|s| s.to_string()),
            arxiv_id: None,
            url: "".to_string(),
            pdf_url: None,
            citation_count: citations,
            published_at: published_at.map(|s| s.to_string()),
            ranking_date: None,
        }
    }

    #[test]
    fn test_dedup_by_doi_keeps_earliest_ranking_date() {
        let results = vec![vec![
            paper("s2:1", "Paper A", Some("10.1234/a"), Some(10), Some("2024-03-15")),
            paper("arxiv:1", "Paper A", Some("10.1234/a"), None, Some("2024-02-01")),
        ]];
        let deduped = deduplicate_and_rank(results, 10, &SearchOptions::default());
        assert_eq!(deduped.len(), 1);
        assert_eq!(deduped[0].ranking_date.as_deref(), Some("2024-02-01"));
    }

    #[test]
    fn test_relevance_prefers_higher_source_rank() {
        let results = vec![vec![
            paper("a", "Most Relevant", None, Some(1), Some("2024-01-01")),
            paper("b", "Less Relevant", None, Some(100), Some("2024-01-02")),
        ]];
        let ranked = deduplicate_and_rank(results, 10, &SearchOptions::default());
        assert_eq!(ranked[0].id, "a");
    }

    #[test]
    fn test_date_filter_excludes_out_of_range_items() {
        let results = vec![vec![
            paper("a", "Older", None, None, Some("2024-01-01")),
            paper("b", "Newer", None, None, Some("2024-02-01")),
        ]];
        let ranked = deduplicate_and_rank(
            results,
            10,
            &SearchOptions {
                sort: SearchSort::Relevance,
                date_from: Some(NaiveDate::from_ymd_opt(2024, 1, 15).unwrap()),
                date_to: Some(NaiveDate::from_ymd_opt(2024, 12, 31).unwrap()),
            },
        );
        assert_eq!(ranked.len(), 1);
        assert_eq!(ranked[0].id, "b");
    }

    #[test]
    fn test_date_desc_sorting() {
        let results = vec![vec![
            paper("a", "Older", None, None, Some("2024-01-01")),
            paper("b", "Newest", None, None, Some("2024-03-01")),
            paper("c", "Middle", None, None, Some("2024-02-01")),
        ]];
        let ranked = deduplicate_and_rank(
            results,
            10,
            &SearchOptions {
                sort: SearchSort::DateDesc,
                ..SearchOptions::default()
            },
        );
        assert_eq!(ranked[0].id, "b");
        assert_eq!(ranked[2].id, "a");
    }

    #[test]
    fn test_hybrid_prefers_recent_when_relevance_is_close() {
        let recent = AggregatedPaper {
            canonical: paper("recent", "Recent", None, None, Some("2024-03-01")),
            relevance_score: 0.015,
            citation_count: 0,
            ranking_date: Some(NaiveDate::from_ymd_opt(2024, 3, 1).unwrap()),
        };
        let old = AggregatedPaper {
            canonical: paper("old", "Old", None, None, Some("2023-01-01")),
            relevance_score: 0.016,
            citation_count: 0,
            ranking_date: Some(NaiveDate::from_ymd_opt(2023, 1, 1).unwrap()),
        };
        let today = NaiveDate::from_ymd_opt(2024, 3, 15).unwrap();
        assert!(hybrid_score(&recent, today, 0.016) > hybrid_score(&old, today, 0.016));
    }
}
