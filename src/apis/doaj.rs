use super::{PaperResult, PaperSource, SourceError};
use async_trait::async_trait;
use serde::Deserialize;

const BASE_URL: &str = "https://doaj.org/api/search/articles";

pub struct DoajClient {
    client: reqwest::Client,
}

impl DoajClient {
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
struct DoajResponse {
    results: Option<Vec<DoajResult>>,
}
#[derive(Deserialize)]
struct DoajResult {
    bibjson: DoajBibJson,
    id: Option<String>,
}
#[derive(Deserialize)]
struct DoajBibJson {
    title: Option<String>,
    author: Option<Vec<DoajAuthor>>,
    #[serde(rename = "abstract")]
    abstract_text: Option<String>,
    year: Option<String>,
    identifier: Option<Vec<DoajIdentifier>>,
    link: Option<Vec<DoajLink>>,
}
#[derive(Deserialize)]
struct DoajAuthor {
    name: Option<String>,
}
#[derive(Deserialize)]
struct DoajIdentifier {
    #[serde(rename = "type")]
    id_type: Option<String>,
    id: Option<String>,
}
#[derive(Deserialize)]
struct DoajLink {
    url: Option<String>,
    #[serde(rename = "type")]
    link_type: Option<String>,
}

fn doaj_to_paper(r: &DoajResult) -> PaperResult {
    let bib = &r.bibjson;
    let doi = bib.identifier.as_ref()
        .and_then(|ids| ids.iter().find(|i| i.id_type.as_deref() == Some("doi")))
        .and_then(|i| i.id.clone());
    let url = bib.link.as_ref()
        .and_then(|links| links.first())
        .and_then(|l| l.url.clone())
        .unwrap_or_default();

    PaperResult {
        id: format!("doaj:{}", r.id.as_deref().unwrap_or("")),
        title: bib.title.clone().unwrap_or_default(),
        authors: bib.author.as_ref()
            .map(|a| a.iter().filter_map(|a| a.name.clone()).collect())
            .unwrap_or_default(),
        abstract_text: bib.abstract_text.clone(),
        year: bib.year.as_ref().and_then(|y| y.parse::<u32>().ok()),
        source: "doaj".to_string(),
        doi,
        arxiv_id: None,
        url,
        pdf_url: bib.link.as_ref()
            .and_then(|links| links.iter().find(|l| l.link_type.as_deref() == Some("fulltext")))
            .and_then(|l| l.url.clone()),
        citation_count: None,
    }
}

#[async_trait]
impl PaperSource for DoajClient {
    fn name(&self) -> &str { "doaj" }

    async fn search(&self, query: &str, max_results: u32) -> Result<Vec<PaperResult>, SourceError> {
        let url = format!("{}/{}", BASE_URL, urlencoded(query));
        let resp: DoajResponse = self.client
            .get(&url)
            .query(&[("pageSize", &max_results.min(100).to_string())])
            .send().await?.json().await?;
        Ok(resp.results.unwrap_or_default().iter().map(doaj_to_paper).collect())
    }

    async fn get_paper(&self, id: &str) -> Result<Option<PaperResult>, SourceError> {
        let doaj_id = id.strip_prefix("doaj:").unwrap_or(id);
        let results = self.search(doaj_id, 1).await?;
        Ok(results.into_iter().next())
    }

    async fn get_citations(&self, _id: &str) -> Result<Vec<PaperResult>, SourceError> { Ok(vec![]) }
    async fn get_references(&self, _id: &str) -> Result<Vec<PaperResult>, SourceError> { Ok(vec![]) }
}

fn urlencoded(s: &str) -> String {
    s.replace(' ', "%20")
}
