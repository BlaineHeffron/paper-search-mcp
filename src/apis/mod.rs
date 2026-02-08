pub mod ads;
pub mod arxiv;
pub mod crossref;
pub mod doaj;
pub mod europepmc;
pub mod inspire;
pub mod openalex;
pub mod semantic_scholar;
pub mod unpaywall;
pub mod vixra;

use async_trait::async_trait;
use serde::{Deserialize, Serialize};
use thiserror::Error;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PaperResult {
    pub id: String,
    pub title: String,
    pub authors: Vec<String>,
    pub abstract_text: Option<String>,
    pub year: Option<u32>,
    pub source: String,
    pub doi: Option<String>,
    pub arxiv_id: Option<String>,
    pub url: String,
    pub pdf_url: Option<String>,
    pub citation_count: Option<u32>,
}

#[derive(Debug, Error)]
pub enum SourceError {
    #[error("HTTP request failed: {0}")]
    Http(#[from] reqwest::Error),
    #[error("Parse error: {0}")]
    Parse(String),
    #[error("API error: {0}")]
    Api(String),
    #[error("Missing API key: {0}")]
    MissingKey(String),
}

#[async_trait]
pub trait PaperSource: Send + Sync {
    fn name(&self) -> &str;
    async fn search(&self, query: &str, max_results: u32) -> Result<Vec<PaperResult>, SourceError>;
    async fn get_paper(&self, id: &str) -> Result<Option<PaperResult>, SourceError>;
    async fn get_citations(&self, id: &str) -> Result<Vec<PaperResult>, SourceError>;
    async fn get_references(&self, id: &str) -> Result<Vec<PaperResult>, SourceError>;
}
