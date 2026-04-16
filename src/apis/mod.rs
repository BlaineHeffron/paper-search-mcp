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
use chrono::NaiveDate;
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
    pub published_at: Option<String>,
    pub ranking_date: Option<String>,
}

#[derive(Debug, Clone, Copy, Default, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum SearchSort {
    #[default]
    Relevance,
    DateDesc,
    DateAsc,
    Hybrid,
}

#[derive(Debug, Clone, Default)]
pub struct SearchOptions {
    pub sort: SearchSort,
    pub date_from: Option<NaiveDate>,
    pub date_to: Option<NaiveDate>,
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
    async fn search(
        &self,
        query: &str,
        max_results: u32,
        options: &SearchOptions,
    ) -> Result<Vec<PaperResult>, SourceError>;
    async fn get_paper(&self, id: &str) -> Result<Option<PaperResult>, SourceError>;
    async fn get_citations(&self, id: &str) -> Result<Vec<PaperResult>, SourceError>;
    async fn get_references(&self, id: &str) -> Result<Vec<PaperResult>, SourceError>;
}

pub fn normalize_date_string(value: &str) -> Option<String> {
    let value = value.trim();
    if value.is_empty() {
        return None;
    }

    if let Ok(date) = chrono::DateTime::parse_from_rfc3339(value) {
        return Some(date.date_naive().format("%Y-%m-%d").to_string());
    }

    for fmt in [
        "%Y-%m-%d",
        "%Y/%m/%d",
        "%Y-%m-%dT%H:%M:%S",
        "%Y-%m-%d %H:%M:%S",
    ] {
        if let Ok(date) = NaiveDate::parse_from_str(value, fmt) {
            return Some(date.format("%Y-%m-%d").to_string());
        }
        if let Ok(datetime) = chrono::NaiveDateTime::parse_from_str(value, fmt) {
            return Some(datetime.date().format("%Y-%m-%d").to_string());
        }
    }

    if value.len() == 7 {
        if let Ok(date) = NaiveDate::parse_from_str(&format!("{value}-01"), "%Y-%m-%d") {
            return Some(date.format("%Y-%m-%d").to_string());
        }
    }

    if value.len() == 4 && value.chars().all(|c| c.is_ascii_digit()) {
        if let Ok(year) = value.parse::<i32>() {
            return NaiveDate::from_ymd_opt(year, 1, 1).map(|d| d.format("%Y-%m-%d").to_string());
        }
    }

    None
}

pub fn normalize_date_parts(parts: &[u32]) -> Option<String> {
    let year = *parts.first()? as i32;
    let month = parts.get(1).copied().unwrap_or(1);
    let day = parts.get(2).copied().unwrap_or(1);
    NaiveDate::from_ymd_opt(year, month, day).map(|d| d.format("%Y-%m-%d").to_string())
}
