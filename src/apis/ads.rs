use super::{PaperResult, PaperSource, SourceError};
use async_trait::async_trait;
use serde::Deserialize;

const BASE_URL: &str = "https://api.adsabs.harvard.edu/v1";

pub struct AdsClient {
    client: reqwest::Client,
    api_key: String,
}

impl AdsClient {
    pub fn new(api_key: String) -> Self {
        Self {
            client: reqwest::Client::builder()
                .user_agent("paper-search-mcp/0.1")
                .build()
                .unwrap(),
            api_key,
        }
    }
}

#[derive(Deserialize)]
struct AdsResponse {
    response: AdsBody,
}
#[derive(Deserialize)]
struct AdsBody {
    docs: Vec<AdsDoc>,
}
#[derive(Deserialize)]
struct AdsDoc {
    bibcode: Option<String>,
    title: Option<Vec<String>>,
    author: Option<Vec<String>>,
    #[serde(rename = "abstract")]
    abstract_text: Option<String>,
    year: Option<String>,
    doi: Option<Vec<String>>,
    citation_count: Option<u32>,
}

fn doc_to_paper(doc: &AdsDoc) -> PaperResult {
    let bibcode = doc.bibcode.clone().unwrap_or_default();
    PaperResult {
        id: format!("ads:{}", bibcode),
        title: doc.title.as_ref().and_then(|t| t.first()).cloned().unwrap_or_default(),
        authors: doc.author.clone().unwrap_or_default(),
        abstract_text: doc.abstract_text.clone(),
        year: doc.year.as_ref().and_then(|y| y.parse::<u32>().ok()),
        source: "ads".to_string(),
        doi: doc.doi.as_ref().and_then(|d| d.first()).cloned(),
        arxiv_id: None,
        url: format!("https://ui.adsabs.harvard.edu/abs/{}", bibcode),
        pdf_url: None,
        citation_count: doc.citation_count,
    }
}

#[async_trait]
impl PaperSource for AdsClient {
    fn name(&self) -> &str { "ads" }

    async fn search(&self, query: &str, max_results: u32) -> Result<Vec<PaperResult>, SourceError> {
        let rows = max_results.min(200).to_string();
        let resp: AdsResponse = self.client
            .get(&format!("{}/search/query", BASE_URL))
            .header("Authorization", format!("Bearer {}", self.api_key))
            .query(&[
                ("q", query),
                ("fl", "bibcode,title,author,abstract,year,doi,citation_count"),
                ("rows", rows.as_str()),
            ])
            .send().await?.json().await?;
        Ok(resp.response.docs.iter().map(doc_to_paper).collect())
    }

    async fn get_paper(&self, id: &str) -> Result<Option<PaperResult>, SourceError> {
        let bibcode = id.strip_prefix("ads:").unwrap_or(id);
        let q = format!("bibcode:{}", bibcode);
        let resp: AdsResponse = self.client
            .get(&format!("{}/search/query", BASE_URL))
            .header("Authorization", format!("Bearer {}", self.api_key))
            .query(&[
                ("q", q.as_str()),
                ("fl", "bibcode,title,author,abstract,year,doi,citation_count"),
            ])
            .send().await?.json().await?;
        Ok(resp.response.docs.first().map(doc_to_paper))
    }

    async fn get_citations(&self, id: &str) -> Result<Vec<PaperResult>, SourceError> {
        let bibcode = id.strip_prefix("ads:").unwrap_or(id);
        let q = format!("citations(bibcode:{})", bibcode);
        let resp: AdsResponse = self.client
            .get(&format!("{}/search/query", BASE_URL))
            .header("Authorization", format!("Bearer {}", self.api_key))
            .query(&[
                ("q", q.as_str()),
                ("fl", "bibcode,title,author,abstract,year,doi,citation_count"),
                ("rows", "25"),
            ])
            .send().await?.json().await?;
        Ok(resp.response.docs.iter().map(doc_to_paper).collect())
    }

    async fn get_references(&self, id: &str) -> Result<Vec<PaperResult>, SourceError> {
        let bibcode = id.strip_prefix("ads:").unwrap_or(id);
        let q = format!("references(bibcode:{})", bibcode);
        let resp: AdsResponse = self.client
            .get(&format!("{}/search/query", BASE_URL))
            .header("Authorization", format!("Bearer {}", self.api_key))
            .query(&[
                ("q", q.as_str()),
                ("fl", "bibcode,title,author,abstract,year,doi,citation_count"),
                ("rows", "25"),
            ])
            .send().await?.json().await?;
        Ok(resp.response.docs.iter().map(doc_to_paper).collect())
    }
}
