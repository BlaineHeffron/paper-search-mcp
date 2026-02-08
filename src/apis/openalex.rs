use super::{PaperResult, PaperSource, SourceError};
use async_trait::async_trait;
use serde::Deserialize;

const BASE_URL: &str = "https://api.openalex.org";

pub struct OpenAlexClient {
    client: reqwest::Client,
}

impl OpenAlexClient {
    pub fn new(email: Option<String>) -> Self {
        let ua = match email {
            Some(ref e) => format!("paper-search-mcp/0.1 (mailto:{})", e),
            None => "paper-search-mcp/0.1".to_string(),
        };
        Self {
            client: reqwest::Client::builder()
                .user_agent(ua)
                .build()
                .unwrap(),
        }
    }
}

#[derive(Deserialize)]
struct OAResponse {
    results: Vec<OAWork>,
}

#[derive(Deserialize)]
struct OAWork {
    id: Option<String>,
    title: Option<String>,
    authorships: Option<Vec<OAAuthorship>>,
    publication_year: Option<u32>,
    doi: Option<String>,
    open_access: Option<OAOpenAccess>,
    cited_by_count: Option<u32>,
}

#[derive(Deserialize)]
struct OAAuthorship {
    author: OAAuthor,
}
#[derive(Deserialize)]
struct OAAuthor {
    display_name: Option<String>,
}
#[derive(Deserialize)]
struct OAOpenAccess {
    oa_url: Option<String>,
}

fn oa_to_paper(w: &OAWork) -> PaperResult {
    let doi = w.doi.as_ref().map(|d| d.replace("https://doi.org/", ""));
    PaperResult {
        id: format!("openalex:{}", w.id.as_deref().unwrap_or("")),
        title: w.title.clone().unwrap_or_default(),
        authors: w.authorships.as_ref()
            .map(|a| a.iter().filter_map(|a| a.author.display_name.clone()).collect())
            .unwrap_or_default(),
        abstract_text: None, // OpenAlex doesn't return abstracts in search by default
        year: w.publication_year,
        source: "openalex".to_string(),
        doi,
        arxiv_id: None,
        url: w.id.clone().unwrap_or_default(),
        pdf_url: w.open_access.as_ref().and_then(|oa| oa.oa_url.clone()),
        citation_count: w.cited_by_count,
    }
}

#[async_trait]
impl PaperSource for OpenAlexClient {
    fn name(&self) -> &str { "openalex" }

    async fn search(&self, query: &str, max_results: u32) -> Result<Vec<PaperResult>, SourceError> {
        let per_page = max_results.min(200).to_string();
        let resp: OAResponse = self.client
            .get(&format!("{}/works", BASE_URL))
            .query(&[
                ("search", query),
                ("per_page", per_page.as_str()),
                ("select", "id,title,authorships,publication_year,doi,open_access,cited_by_count"),
            ])
            .send().await?.json().await?;
        Ok(resp.results.iter().map(oa_to_paper).collect())
    }

    async fn get_paper(&self, id: &str) -> Result<Option<PaperResult>, SourceError> {
        let oa_id = id.strip_prefix("openalex:").unwrap_or(id);
        let resp = self.client
            .get(&format!("{}/works/{}", BASE_URL, oa_id))
            .send().await?;
        if resp.status() == 404 { return Ok(None); }
        let w: OAWork = resp.json().await?;
        Ok(Some(oa_to_paper(&w)))
    }

    async fn get_citations(&self, id: &str) -> Result<Vec<PaperResult>, SourceError> {
        let oa_id = id.strip_prefix("openalex:").unwrap_or(id);
        let filter = format!("cites:{}", oa_id);
        let resp: OAResponse = self.client
            .get(&format!("{}/works", BASE_URL))
            .query(&[
                ("filter", filter.as_str()),
                ("per_page", "25"),
                ("select", "id,title,authorships,publication_year,doi,open_access,cited_by_count"),
            ])
            .send().await?.json().await?;
        Ok(resp.results.iter().map(oa_to_paper).collect())
    }

    async fn get_references(&self, id: &str) -> Result<Vec<PaperResult>, SourceError> {
        let oa_id = id.strip_prefix("openalex:").unwrap_or(id);
        let filter = format!("cited_by:{}", oa_id);
        let resp: OAResponse = self.client
            .get(&format!("{}/works", BASE_URL))
            .query(&[
                ("filter", filter.as_str()),
                ("per_page", "25"),
                ("select", "id,title,authorships,publication_year,doi,open_access,cited_by_count"),
            ])
            .send().await?.json().await?;
        Ok(resp.results.iter().map(oa_to_paper).collect())
    }
}
