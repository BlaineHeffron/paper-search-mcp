use super::{PaperResult, PaperSource, SourceError};
use async_trait::async_trait;
use serde::Deserialize;

const BASE_URL: &str = "https://www.ebi.ac.uk/europepmc/webservices/rest";

pub struct EuropePmcClient {
    client: reqwest::Client,
}

impl EuropePmcClient {
    pub fn new() -> Self {
        Self {
            client: reqwest::Client::builder()
                .user_agent("paper-search-mcp/0.1")
                .build()
                .unwrap(),
        }
    }
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct EpmcResponse {
    result_list: Option<EpmcResultList>,
}
#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct EpmcResultList {
    result: Vec<EpmcResult>,
}
#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct EpmcResult {
    id: Option<String>,
    title: Option<String>,
    author_string: Option<String>,
    abstract_text: Option<String>,
    pub_year: Option<String>,
    doi: Option<String>,
    cited_by_count: Option<u32>,
    pmid: Option<String>,
}

fn epmc_to_paper(r: &EpmcResult) -> PaperResult {
    let authors = r.author_string.as_ref()
        .map(|a| a.split(", ").map(|s| s.to_string()).collect())
        .unwrap_or_default();
    let id = r.pmid.as_ref()
        .map(|p| format!("pmid:{}", p))
        .or_else(|| r.doi.as_ref().map(|d| format!("doi:{}", d)))
        .unwrap_or_else(|| format!("epmc:{}", r.id.as_deref().unwrap_or("")));

    PaperResult {
        id,
        title: r.title.clone().unwrap_or_default(),
        authors,
        abstract_text: r.abstract_text.clone(),
        year: r.pub_year.as_ref().and_then(|y| y.parse::<u32>().ok()),
        source: "europepmc".to_string(),
        doi: r.doi.clone(),
        arxiv_id: None,
        url: r.pmid.as_ref()
            .map(|p| format!("https://europepmc.org/article/MED/{}", p))
            .unwrap_or_default(),
        pdf_url: None,
        citation_count: r.cited_by_count,
    }
}

#[async_trait]
impl PaperSource for EuropePmcClient {
    fn name(&self) -> &str { "europepmc" }

    async fn search(&self, query: &str, max_results: u32) -> Result<Vec<PaperResult>, SourceError> {
        let resp: EpmcResponse = self.client
            .get(&format!("{}/search", BASE_URL))
            .query(&[
                ("query", query),
                ("resultType", "core"),
                ("format", "json"),
                ("pageSize", &max_results.min(100).to_string()),
            ])
            .send().await?.json().await?;
        Ok(resp.result_list
            .map(|rl| rl.result.iter().map(epmc_to_paper).collect())
            .unwrap_or_default())
    }

    async fn get_paper(&self, id: &str) -> Result<Option<PaperResult>, SourceError> {
        let pmid = id.strip_prefix("pmid:").unwrap_or(id);
        let results = self.search(&format!("EXT_ID:{}", pmid), 1).await?;
        Ok(results.into_iter().next())
    }

    async fn get_citations(&self, id: &str) -> Result<Vec<PaperResult>, SourceError> {
        let pmid = id.strip_prefix("pmid:").unwrap_or(id);
        self.search(&format!("CITES:{}", pmid), 25).await
    }

    async fn get_references(&self, _id: &str) -> Result<Vec<PaperResult>, SourceError> {
        Ok(vec![])
    }
}
