use super::{PaperResult, PaperSource, SourceError};
use async_trait::async_trait;
use serde::Deserialize;

const BASE_URL: &str = "https://api.crossref.org/works";

pub struct CrossRefClient {
    client: reqwest::Client,
}

impl CrossRefClient {
    pub fn new() -> Self {
        Self {
            client: reqwest::Client::builder()
                .user_agent("paper-search-mcp/0.1 (mailto:research@example.com)")
                .build()
                .unwrap(),
        }
    }
}

#[derive(Deserialize)]
struct CRResponse {
    message: CRMessage,
}
#[derive(Deserialize)]
struct CRMessage {
    items: Option<Vec<CRItem>>,
    // For single work lookup
    #[serde(rename = "DOI")]
    doi: Option<String>,
    title: Option<Vec<String>>,
    author: Option<Vec<CRAuthor>>,
    #[serde(rename = "is-referenced-by-count")]
    citation_count: Option<u32>,
    published: Option<CRDate>,
}
#[derive(Deserialize)]
struct CRItem {
    #[serde(rename = "DOI")]
    doi: Option<String>,
    title: Option<Vec<String>>,
    author: Option<Vec<CRAuthor>>,
    #[serde(rename = "is-referenced-by-count")]
    citation_count: Option<u32>,
    published: Option<CRDate>,
    link: Option<Vec<CRLink>>,
}
#[derive(Deserialize)]
struct CRAuthor {
    given: Option<String>,
    family: Option<String>,
}
#[derive(Deserialize)]
struct CRDate {
    #[serde(rename = "date-parts")]
    date_parts: Option<Vec<Vec<u32>>>,
}
#[derive(Deserialize)]
struct CRLink {
    #[serde(rename = "URL")]
    url: Option<String>,
    #[serde(rename = "content-type")]
    content_type: Option<String>,
}

fn item_to_paper(item: &CRItem) -> PaperResult {
    let doi = item.doi.clone();
    let title = item.title.as_ref()
        .and_then(|t| t.first())
        .cloned()
        .unwrap_or_default();
    let authors = item.author.as_ref()
        .map(|a| a.iter().map(|a| {
            format!("{} {}",
                a.given.as_deref().unwrap_or(""),
                a.family.as_deref().unwrap_or("")).trim().to_string()
        }).collect())
        .unwrap_or_default();
    let year = item.published.as_ref()
        .and_then(|d| d.date_parts.as_ref())
        .and_then(|p| p.first())
        .and_then(|p| p.first())
        .copied();
    let pdf_url = item.link.as_ref()
        .and_then(|links| links.iter().find(|l| {
            l.content_type.as_deref() == Some("application/pdf")
        }))
        .and_then(|l| l.url.clone());

    let url = format!("https://doi.org/{}", doi.as_deref().unwrap_or(""));
    PaperResult {
        id: format!("doi:{}", doi.as_deref().unwrap_or("")),
        title,
        authors,
        abstract_text: None,
        year,
        source: "crossref".to_string(),
        doi,
        arxiv_id: None,
        url,
        pdf_url,
        citation_count: item.citation_count,
    }
}

#[async_trait]
impl PaperSource for CrossRefClient {
    fn name(&self) -> &str { "crossref" }

    async fn search(&self, query: &str, max_results: u32) -> Result<Vec<PaperResult>, SourceError> {
        let rows = max_results.min(100).to_string();
        let resp: CRResponse = self.client
            .get(BASE_URL)
            .query(&[
                ("query", query),
                ("rows", rows.as_str()),
                ("select", "DOI,title,author,published,is-referenced-by-count,link"),
            ])
            .send().await?.json().await?;
        Ok(resp.message.items.unwrap_or_default().iter().map(item_to_paper).collect())
    }

    async fn get_paper(&self, id: &str) -> Result<Option<PaperResult>, SourceError> {
        let doi = id.strip_prefix("doi:").unwrap_or(id);
        let url = format!("{}/{}", BASE_URL, doi);
        let resp = self.client.get(&url).send().await?;
        if resp.status() == 404 { return Ok(None); }
        let cr: CRResponse = resp.json().await?;
        // Single work returns in message directly
        let item = CRItem {
            doi: cr.message.doi,
            title: cr.message.title,
            author: cr.message.author,
            citation_count: cr.message.citation_count,
            published: cr.message.published,
            link: None,
        };
        Ok(Some(item_to_paper(&item)))
    }

    async fn get_citations(&self, _id: &str) -> Result<Vec<PaperResult>, SourceError> {
        Ok(vec![]) // CrossRef doesn't easily provide citing papers
    }

    async fn get_references(&self, _id: &str) -> Result<Vec<PaperResult>, SourceError> {
        Ok(vec![]) // Would need a separate request
    }
}
