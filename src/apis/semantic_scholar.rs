use super::{PaperResult, PaperSource, SourceError};
use async_trait::async_trait;
use serde::Deserialize;

const BASE_URL: &str = "https://api.semanticscholar.org/graph/v1";

pub struct SemanticScholarClient {
    client: reqwest::Client,
    api_key: Option<String>,
}

impl SemanticScholarClient {
    pub fn new(api_key: Option<String>) -> Self {
        Self {
            client: reqwest::Client::builder()
                .user_agent("paper-search-mcp/0.1")
                .build()
                .unwrap(),
            api_key,
        }
    }

    fn add_auth(&self, req: reqwest::RequestBuilder) -> reqwest::RequestBuilder {
        match &self.api_key {
            Some(key) => req.header("x-api-key", key),
            None => req,
        }
    }
}

#[derive(Deserialize)]
struct S2SearchResponse {
    data: Option<Vec<S2Paper>>,
}

#[derive(Deserialize)]
struct S2CitationResponse {
    data: Option<Vec<S2CitationEdge>>,
}

#[derive(Deserialize)]
struct S2CitationEdge {
    #[serde(alias = "citingPaper", alias = "citedPaper")]
    #[serde(flatten)]
    paper: std::collections::HashMap<String, serde_json::Value>,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct S2Paper {
    paper_id: Option<String>,
    title: Option<String>,
    authors: Option<Vec<S2Author>>,
    #[serde(rename = "abstract")]
    abstract_text: Option<String>,
    year: Option<u32>,
    external_ids: Option<S2ExternalIds>,
    citation_count: Option<u32>,
    url: Option<String>,
    open_access_pdf: Option<S2Pdf>,
}

#[derive(Deserialize)]
struct S2Author {
    name: Option<String>,
}

#[derive(Deserialize)]
#[serde(rename_all = "PascalCase")]
struct S2ExternalIds {
    #[serde(rename = "DOI")]
    doi: Option<String>,
    #[serde(rename = "ArXiv")]
    arxiv: Option<String>,
}

#[derive(Deserialize)]
struct S2Pdf {
    url: Option<String>,
}

fn s2_to_paper(p: &S2Paper) -> PaperResult {
    PaperResult {
        id: format!("s2:{}", p.paper_id.as_deref().unwrap_or("")),
        title: p.title.clone().unwrap_or_default(),
        authors: p.authors.as_ref()
            .map(|a| a.iter().filter_map(|a| a.name.clone()).collect())
            .unwrap_or_default(),
        abstract_text: p.abstract_text.clone(),
        year: p.year,
        source: "semantic_scholar".to_string(),
        doi: p.external_ids.as_ref().and_then(|e| e.doi.clone()),
        arxiv_id: p.external_ids.as_ref().and_then(|e| e.arxiv.clone()),
        url: p.url.clone().unwrap_or_default(),
        pdf_url: p.open_access_pdf.as_ref().and_then(|pdf| pdf.url.clone()),
        citation_count: p.citation_count,
    }
}

const FIELDS: &str = "title,authors,abstract,year,externalIds,citationCount,url,openAccessPdf";

#[async_trait]
impl PaperSource for SemanticScholarClient {
    fn name(&self) -> &str {
        "semantic_scholar"
    }

    async fn search(&self, query: &str, max_results: u32) -> Result<Vec<PaperResult>, SourceError> {
        let url = format!("{}/paper/search", BASE_URL);
        let limit = max_results.min(100).to_string();
        let resp: S2SearchResponse = self.add_auth(
            self.client.get(&url)
                .query(&[
                    ("query", query),
                    ("limit", limit.as_str()),
                    ("fields", FIELDS),
                ])
        ).send().await?.json().await?;
        Ok(resp.data.unwrap_or_default().iter().map(s2_to_paper).collect())
    }

    async fn get_paper(&self, id: &str) -> Result<Option<PaperResult>, SourceError> {
        let paper_id = id.strip_prefix("s2:").unwrap_or(id);
        let url = format!("{}/paper/{}", BASE_URL, paper_id);
        let resp = self.add_auth(
            self.client.get(&url).query(&[("fields", FIELDS)])
        ).send().await?;
        if resp.status() == 404 {
            return Ok(None);
        }
        let paper: S2Paper = resp.json().await?;
        Ok(Some(s2_to_paper(&paper)))
    }

    async fn get_citations(&self, id: &str) -> Result<Vec<PaperResult>, SourceError> {
        let paper_id = id.strip_prefix("s2:").unwrap_or(id);
        let url = format!("{}/paper/{}/citations", BASE_URL, paper_id);
        let fields = format!("citingPaper.{}", FIELDS);
        let resp: S2CitationResponse = self.add_auth(
            self.client.get(&url)
                .query(&[("fields", fields.as_str()), ("limit", "25")])
        ).send().await?.json().await?;
        let papers: Vec<PaperResult> = resp.data.unwrap_or_default()
            .iter()
            .filter_map(|edge| {
                let val = edge.paper.get("citingPaper")?;
                let p: S2Paper = serde_json::from_value(val.clone()).ok()?;
                Some(s2_to_paper(&p))
            })
            .collect();
        Ok(papers)
    }

    async fn get_references(&self, id: &str) -> Result<Vec<PaperResult>, SourceError> {
        let paper_id = id.strip_prefix("s2:").unwrap_or(id);
        let url = format!("{}/paper/{}/references", BASE_URL, paper_id);
        let fields = format!("citedPaper.{}", FIELDS);
        let resp: S2CitationResponse = self.add_auth(
            self.client.get(&url)
                .query(&[("fields", fields.as_str()), ("limit", "25")])
        ).send().await?.json().await?;
        let papers: Vec<PaperResult> = resp.data.unwrap_or_default()
            .iter()
            .filter_map(|edge| {
                let val = edge.paper.get("citedPaper")?;
                let p: S2Paper = serde_json::from_value(val.clone()).ok()?;
                Some(s2_to_paper(&p))
            })
            .collect();
        Ok(papers)
    }
}
