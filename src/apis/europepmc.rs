use super::{normalize_date_string, PaperResult, PaperSource, SearchOptions, SearchSort, SourceError};
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
    first_publication_date: Option<String>,
    doi: Option<String>,
    cited_by_count: Option<u32>,
    pmid: Option<String>,
}

fn epmc_to_paper(r: &EpmcResult) -> PaperResult {
    let authors = r
        .author_string
        .as_ref()
        .map(|a| a.split(", ").map(|s| s.to_string()).collect())
        .unwrap_or_default();
    let id = r
        .pmid
        .as_ref()
        .map(|p| format!("pmid:{}", p))
        .or_else(|| r.doi.as_ref().map(|d| format!("doi:{}", d)))
        .unwrap_or_else(|| format!("epmc:{}", r.id.as_deref().unwrap_or("")));

    let published_at = r
        .first_publication_date
        .as_deref()
        .and_then(normalize_date_string)
        .or_else(|| r.pub_year.as_deref().and_then(normalize_date_string));

    PaperResult {
        id,
        title: r.title.clone().unwrap_or_default(),
        authors,
        abstract_text: r.abstract_text.clone(),
        year: published_at
            .as_deref()
            .and_then(|d| d.get(..4))
            .and_then(|y| y.parse::<u32>().ok()),
        source: "europepmc".to_string(),
        doi: r.doi.clone(),
        arxiv_id: None,
        url: r
            .pmid
            .as_ref()
            .map(|p| format!("https://europepmc.org/article/MED/{}", p))
            .unwrap_or_default(),
        pdf_url: None,
        citation_count: r.cited_by_count,
        published_at: published_at.clone(),
        ranking_date: published_at,
    }
}

#[async_trait]
impl PaperSource for EuropePmcClient {
    fn name(&self) -> &str {
        "europepmc"
    }

    async fn search(
        &self,
        query: &str,
        max_results: u32,
        options: &SearchOptions,
    ) -> Result<Vec<PaperResult>, SourceError> {
        let query = europepmc_query(query, options);
        let page_size = max_results.min(100).to_string();
        let mut request = self.client.get(format!("{}/search", BASE_URL)).query(&[
            ("query", query.as_str()),
            ("resultType", "core"),
            ("format", "json"),
            ("pageSize", page_size.as_str()),
        ]);
        match options.sort {
            SearchSort::DateAsc => request = request.query(&[("sort", "FIRST_PDATE asc")]),
            SearchSort::DateDesc | SearchSort::Hybrid => {
                request = request.query(&[("sort", "FIRST_PDATE desc")])
            }
            SearchSort::Relevance => {}
        }
        let resp: EpmcResponse = request.send().await?.json().await?;
        Ok(resp
            .result_list
            .map(|rl| rl.result.iter().map(epmc_to_paper).collect())
            .unwrap_or_default())
    }

    async fn get_paper(&self, id: &str) -> Result<Option<PaperResult>, SourceError> {
        let pmid = id.strip_prefix("pmid:").unwrap_or(id);
        let results = self
            .search(&format!("EXT_ID:{}", pmid), 1, &SearchOptions::default())
            .await?;
        Ok(results.into_iter().next())
    }

    async fn get_citations(&self, id: &str) -> Result<Vec<PaperResult>, SourceError> {
        let pmid = id.strip_prefix("pmid:").unwrap_or(id);
        self.search(&format!("CITES:{}", pmid), 25, &SearchOptions::default())
            .await
    }

    async fn get_references(&self, _id: &str) -> Result<Vec<PaperResult>, SourceError> {
        Ok(vec![])
    }
}

fn europepmc_query(query: &str, options: &SearchOptions) -> String {
    match (options.date_from, options.date_to) {
        (None, None) => query.to_string(),
        (from, to) => {
            let from = from
                .unwrap_or_else(|| chrono::NaiveDate::from_ymd_opt(1900, 1, 1).unwrap())
                .format("%Y-%m-%d")
                .to_string();
            let to = to
                .unwrap_or_else(|| chrono::NaiveDate::from_ymd_opt(2100, 12, 31).unwrap())
                .format("%Y-%m-%d")
                .to_string();
            format!("({}) AND FIRST_PDATE:[{} TO {}]", query, from, to)
        }
    }
}
