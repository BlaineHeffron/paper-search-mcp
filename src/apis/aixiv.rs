use super::{normalize_date_string, PaperResult, PaperSource, SearchOptions, SourceError};
use async_trait::async_trait;
use serde::Deserialize;

const BASE_URL: &str = "https://aixiv.science";
/// aiXiv has no search endpoint; fetch one bounded page of recent submissions and filter locally.
const PAGE_LIMIT: u32 = 200;

pub struct AixivClient {
    client: reqwest::Client,
}

impl AixivClient {
    pub fn new() -> Self {
        Self {
            client: reqwest::Client::builder()
                .user_agent("paper-search-mcp/0.1")
                .timeout(std::time::Duration::from_secs(30))
                .build()
                .unwrap(),
        }
    }

    async fn recent(&self) -> Result<Vec<Submission>, SourceError> {
        Ok(self
            .client
            .get(format!("{}/api/submissions/public", BASE_URL))
            .query(&[("limit", PAGE_LIMIT)])
            .send()
            .await?
            .error_for_status()?
            .json()
            .await?)
    }
}

#[derive(Deserialize)]
struct Submission {
    aixiv_id: String,
    title: String,
    #[serde(default)]
    authors: serde_json::Value,
    authorship_type: Option<String>,
    #[serde(rename = "abstract")]
    abstract_text: Option<String>,
    #[serde(default)]
    category: serde_json::Value,
    doi: Option<String>,
}

fn submission_to_paper(s: Submission) -> PaperResult {
    let authors = match s.authors {
        serde_json::Value::String(a) => a.split(',').map(|a| a.trim().to_string()).collect(),
        serde_json::Value::Array(a) => a
            .iter()
            .filter_map(|a| a.as_str().or_else(|| a.get("name")?.as_str()))
            .map(str::to_string)
            .collect(),
        _ => vec![],
    };
    let category = match s.category {
        serde_json::Value::String(c) => c,
        serde_json::Value::Array(c) => c
            .iter()
            .filter_map(|c| c.as_str())
            .collect::<Vec<_>>()
            .join(", "),
        _ => String::new(),
    };
    let note = format!(
        "[aiXiv: authorship={}; category={}; AI review only]",
        s.authorship_type.as_deref().unwrap_or("unknown"),
        if category.is_empty() {
            "unknown"
        } else {
            &category
        }
    );
    let abstract_text = match s.abstract_text.as_deref().map(str::trim) {
        Some(a) if !a.is_empty() => format!("{a}\n\n{note}"),
        _ => note,
    };
    // IDs encode the submission date: aixiv.YYMMDD.NNNNNN
    let date = s
        .aixiv_id
        .split('.')
        .nth(1)
        .filter(|d| d.len() == 6)
        .and_then(|d| normalize_date_string(&format!("20{}-{}-{}", &d[..2], &d[2..4], &d[4..])));
    let pdf = format!("{}/api/pdf/{}", BASE_URL, s.aixiv_id);
    PaperResult {
        id: format!("aixiv:{}", s.aixiv_id),
        title: s.title,
        authors,
        abstract_text: Some(abstract_text),
        year: date.as_deref().and_then(|d| d.get(..4)?.parse().ok()),
        source: "aixiv".to_string(),
        doi: s.doi.filter(|d| !d.is_empty()),
        arxiv_id: None,
        url: pdf.clone(),
        pdf_url: Some(pdf),
        citation_count: None,
        published_at: date.clone(),
        ranking_date: date,
    }
}

pub(super) fn matches_query(p: &PaperResult, query: &str) -> bool {
    let haystack = format!(
        "{} {} {}",
        p.title,
        p.authors.join(" "),
        p.abstract_text.as_deref().unwrap_or("")
    )
    .to_lowercase();
    query
        .split_whitespace()
        .all(|term| haystack.contains(&term.to_lowercase()))
}

#[async_trait]
impl PaperSource for AixivClient {
    fn name(&self) -> &str {
        "aixiv"
    }

    async fn search(
        &self,
        query: &str,
        max_results: u32,
        _options: &SearchOptions,
    ) -> Result<Vec<PaperResult>, SourceError> {
        Ok(self
            .recent()
            .await?
            .into_iter()
            .map(submission_to_paper)
            .filter(|p| matches_query(p, query))
            .take(max_results as usize)
            .collect())
    }

    async fn get_paper(&self, id: &str) -> Result<Option<PaperResult>, SourceError> {
        let id = id.strip_prefix("aixiv:").unwrap_or(id);
        Ok(self
            .recent()
            .await?
            .into_iter()
            .find(|s| s.aixiv_id == id)
            .map(submission_to_paper))
    }

    async fn get_citations(&self, _id: &str) -> Result<Vec<PaperResult>, SourceError> {
        Ok(vec![])
    }
    async fn get_references(&self, _id: &str) -> Result<Vec<PaperResult>, SourceError> {
        Ok(vec![])
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const SAMPLE: &str = r#"[{"aixiv_id":"aixiv.261026.000001","title":"Protein Folding by Agents","authors":["Agent One","Agent Two"],"authorship_type":"ai-only","abstract":"We fold proteins.","category":["Life Sciences","Biology"],"doi":null,"license":"CC-BY-4.0","s3_url":"s3://x"},{"aixiv_id":"aixiv.261027.000002","title":"Other","authors":"A, B","abstract":"Unrelated.","category":"physics"}]"#;

    #[test]
    fn parses_and_filters_submissions() {
        let subs: Vec<Submission> = serde_json::from_str(SAMPLE).unwrap();
        let papers: Vec<_> = subs.into_iter().map(submission_to_paper).collect();
        let p = &papers[0];
        assert_eq!(p.id, "aixiv:aixiv.261026.000001");
        assert_eq!(p.authors, vec!["Agent One", "Agent Two"]);
        assert_eq!(p.published_at.as_deref(), Some("2026-10-26"));
        assert_eq!(
            p.pdf_url.as_deref(),
            Some("https://aixiv.science/api/pdf/aixiv.261026.000001")
        );
        assert!(p
            .abstract_text
            .as_deref()
            .unwrap()
            .contains("authorship=ai-only"));
        assert_eq!(papers[1].authors, vec!["A", "B"]);
        assert!(matches_query(p, "protein FOLD"));
        assert!(!matches_query(&papers[1], "protein"));
    }
}
