use std::collections::HashMap;
use anyhow::Result;

use crate::apis::PaperResult;
use super::fulltext::FulltextIndex;
use super::vectordb::VectorStore;

/// RRF constant (standard value from the original paper).
const RRF_K: f32 = 60.0;

/// Search mode for hybrid queries.
pub enum SearchMode<'a> {
    /// Only keyword/BM25 search (no embedding needed).
    KeywordOnly { query: &'a str },
    /// Only vector similarity search.
    VectorOnly { embedding: &'a [f32] },
    /// Hybrid: BM25 + vector with reciprocal rank fusion.
    Hybrid { query: &'a str, embedding: &'a [f32] },
}

/// Perform hybrid search combining Tantivy BM25 and LanceDB vector results
/// via reciprocal rank fusion (RRF).
///
/// RRF score for a document = sum over rankings r: 1 / (k + rank_in_r)
pub async fn hybrid_search(
    fulltext: &FulltextIndex,
    vector: &VectorStore,
    mode: SearchMode<'_>,
    limit: usize,
) -> Result<Vec<ScoredResult>> {
    // Fetch more candidates than needed to improve fusion quality
    let fetch_limit = limit * 3;

    match mode {
        SearchMode::KeywordOnly { query } => {
            let bm25_results = fulltext.search(query, fetch_limit)?;
            let mut scored: Vec<ScoredResult> = bm25_results
                .into_iter()
                .enumerate()
                .map(|(rank, (id, bm25_score))| ScoredResult {
                    id,
                    rrf_score: 1.0 / (RRF_K + rank as f32 + 1.0),
                    bm25_score: Some(bm25_score),
                    vector_distance: None,
                })
                .collect();
            scored.truncate(limit);
            Ok(scored)
        }
        SearchMode::VectorOnly { embedding } => {
            let vec_results = vector.search_similar(embedding, fetch_limit).await?;
            let mut scored: Vec<ScoredResult> = vec_results
                .into_iter()
                .enumerate()
                .map(|(rank, (id, distance))| ScoredResult {
                    id,
                    rrf_score: 1.0 / (RRF_K + rank as f32 + 1.0),
                    bm25_score: None,
                    vector_distance: Some(distance),
                })
                .collect();
            scored.truncate(limit);
            Ok(scored)
        }
        SearchMode::Hybrid { query, embedding } => {
            // Run both searches in parallel (BM25 is sync, vector is async)
            let bm25_results = fulltext.search(query, fetch_limit)?;
            let vec_results = vector.search_similar(embedding, fetch_limit).await?;

            // Build RRF scores
            let mut doc_scores: HashMap<String, RrfAccumulator> = HashMap::new();

            for (rank, (id, score)) in bm25_results.into_iter().enumerate() {
                let entry = doc_scores.entry(id).or_default();
                entry.rrf_score += 1.0 / (RRF_K + rank as f32 + 1.0);
                entry.bm25_score = Some(score);
            }

            for (rank, (id, distance)) in vec_results.into_iter().enumerate() {
                let entry = doc_scores.entry(id).or_default();
                entry.rrf_score += 1.0 / (RRF_K + rank as f32 + 1.0);
                entry.vector_distance = Some(distance);
            }

            // Sort by RRF score descending
            let mut results: Vec<ScoredResult> = doc_scores
                .into_iter()
                .map(|(id, acc)| ScoredResult {
                    id,
                    rrf_score: acc.rrf_score,
                    bm25_score: acc.bm25_score,
                    vector_distance: acc.vector_distance,
                })
                .collect();
            results.sort_by(|a, b| b.rrf_score.partial_cmp(&a.rrf_score).unwrap_or(std::cmp::Ordering::Equal));
            results.truncate(limit);
            Ok(results)
        }
    }
}

/// Resolve scored results to full PaperResult structs by looking them up in the vector store.
pub async fn resolve_results(
    vector: &VectorStore,
    scored: &[ScoredResult],
) -> Result<Vec<PaperResult>> {
    let mut papers = Vec::with_capacity(scored.len());
    for result in scored {
        if let Some(paper) = vector.get_paper(&result.id).await? {
            papers.push(paper);
        }
    }
    Ok(papers)
}

#[derive(Debug, Clone)]
pub struct ScoredResult {
    pub id: String,
    pub rrf_score: f32,
    pub bm25_score: Option<f32>,
    pub vector_distance: Option<f32>,
}

#[derive(Default)]
struct RrfAccumulator {
    rrf_score: f32,
    bm25_score: Option<f32>,
    vector_distance: Option<f32>,
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::apis::PaperResult;
    use crate::embed::specter::mock_embedding;
    use crate::index::fulltext::FulltextIndex;
    use crate::index::vectordb::VectorStore;
    use tempfile::TempDir;

    fn sample_paper(id: &str, title: &str, abstract_text: &str) -> PaperResult {
        PaperResult {
            id: id.to_string(),
            title: title.to_string(),
            authors: vec!["Test Author".to_string()],
            abstract_text: Some(abstract_text.to_string()),
            year: Some(2024),
            source: "test".to_string(),
            doi: None,
            arxiv_id: None,
            url: "https://example.com".to_string(),
            pdf_url: None,
            citation_count: None,
        }
    }

    #[tokio::test]
    async fn test_hybrid_search() {
        let ft_dir = TempDir::new().unwrap();
        let vec_dir = TempDir::new().unwrap();

        let mut ft_index = FulltextIndex::create_or_open(ft_dir.path()).unwrap();
        let vec_store = VectorStore::create_or_open(vec_dir.path()).await.unwrap();

        let papers = vec![
            sample_paper("p1", "Holographic Entanglement Entropy in AdS/CFT", "We compute entanglement entropy using the Ryu-Takayanagi formula in anti-de Sitter spacetime."),
            sample_paper("p2", "Quantum Error Correction with Topological Codes", "A review of surface codes and their application to fault-tolerant quantum computation."),
            sample_paper("p3", "Black Hole Information Paradox and Holography", "The information paradox is revisited in the context of holographic duality and island formula."),
        ];

        for paper in &papers {
            let emb = mock_embedding(&paper.title);
            ft_index.add_paper(
                &paper.id,
                &paper.title,
                paper.abstract_text.as_deref(),
                &paper.authors,
                paper.year,
            ).unwrap();
            vec_store.add_paper(paper, &emb).await.unwrap();
        }
        ft_index.commit().unwrap();

        // Keyword-only search
        let results = hybrid_search(
            &ft_index,
            &vec_store,
            SearchMode::KeywordOnly { query: "holographic entanglement" },
            10,
        ).await.unwrap();
        assert!(!results.is_empty());
        assert_eq!(results[0].id, "p1");
        assert!(results[0].bm25_score.is_some());

        // Vector-only search
        let query_emb = mock_embedding("Holographic Entanglement Entropy in AdS/CFT");
        let results = hybrid_search(
            &ft_index,
            &vec_store,
            SearchMode::VectorOnly { embedding: &query_emb },
            10,
        ).await.unwrap();
        assert!(!results.is_empty());

        // Hybrid search
        let results = hybrid_search(
            &ft_index,
            &vec_store,
            SearchMode::Hybrid {
                query: "holographic entanglement",
                embedding: &query_emb,
            },
            10,
        ).await.unwrap();
        assert!(!results.is_empty());
        // Paper appearing in both rankings should have higher RRF score
        assert!(results[0].rrf_score > 0.0);

        // Resolve to full papers
        let resolved = resolve_results(&vec_store, &results).await.unwrap();
        assert!(!resolved.is_empty());
    }
}
