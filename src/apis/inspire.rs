use super::{PaperResult, PaperSource, SourceError};
use async_trait::async_trait;
use serde::Deserialize;

const BASE_URL: &str = "https://inspirehep.net/api/literature";

pub struct InspireClient {
    client: reqwest::Client,
}

impl InspireClient {
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
struct InspireResponse {
    hits: InspireHits,
}

#[derive(Deserialize)]
struct InspireHits {
    hits: Vec<InspireHit>,
}

#[derive(Deserialize)]
struct InspireHit {
    id: String,
    metadata: InspireMetadata,
}

#[derive(Deserialize)]
struct InspireMetadata {
    titles: Option<Vec<InspireTitle>>,
    authors: Option<Vec<InspireAuthor>>,
    abstracts: Option<Vec<InspireAbstract>>,
    dois: Option<Vec<InspireDoi>>,
    arxiv_eprints: Option<Vec<InspireArxiv>>,
    citation_count: Option<u32>,
    urls: Option<Vec<InspireUrl>>,
    earliest_date: Option<String>,
}

#[derive(Deserialize)]
struct InspireTitle {
    title: String,
}
#[derive(Deserialize)]
struct InspireAuthor {
    full_name: String,
}
#[derive(Deserialize)]
struct InspireAbstract {
    value: String,
}
#[derive(Deserialize)]
struct InspireDoi {
    value: String,
}
#[derive(Deserialize)]
struct InspireArxiv {
    value: String,
}
#[derive(Deserialize)]
struct InspireUrl {
    value: String,
}

fn hit_to_paper(hit: &InspireHit) -> PaperResult {
    let m = &hit.metadata;
    let title = m.titles.as_ref()
        .and_then(|t| t.first())
        .map(|t| t.title.clone())
        .unwrap_or_default();
    let authors = m.authors.as_ref()
        .map(|a| a.iter().map(|a| a.full_name.clone()).collect())
        .unwrap_or_default();
    let abstract_text = m.abstracts.as_ref()
        .and_then(|a| a.first())
        .map(|a| a.value.clone());
    let doi = m.dois.as_ref()
        .and_then(|d| d.first())
        .map(|d| d.value.clone());
    let arxiv_id = m.arxiv_eprints.as_ref()
        .and_then(|a| a.first())
        .map(|a| a.value.clone());
    let year = m.earliest_date.as_ref()
        .and_then(|d| d.get(..4))
        .and_then(|y| y.parse::<u32>().ok());
    let url = format!("https://inspirehep.net/literature/{}", hit.id);

    PaperResult {
        id: format!("inspire:{}", hit.id),
        title,
        authors,
        abstract_text,
        year,
        source: "inspire".to_string(),
        doi,
        arxiv_id,
        url,
        pdf_url: None,
        citation_count: m.citation_count,
    }
}

#[async_trait]
impl PaperSource for InspireClient {
    fn name(&self) -> &str {
        "inspire"
    }

    async fn search(&self, query: &str, max_results: u32) -> Result<Vec<PaperResult>, SourceError> {
        let size = max_results.to_string();
        let resp: InspireResponse = self.client
            .get(BASE_URL)
            .query(&[
                ("q", query),
                ("size", size.as_str()),
                ("fields", "titles,authors,abstracts,dois,arxiv_eprints,citation_count,urls,earliest_date"),
            ])
            .send()
            .await?
            .json()
            .await?;
        Ok(resp.hits.hits.iter().map(hit_to_paper).collect())
    }

    async fn get_paper(&self, id: &str) -> Result<Option<PaperResult>, SourceError> {
        let recid = id.strip_prefix("inspire:").unwrap_or(id);
        let url = format!("{}/{}", BASE_URL, recid);
        let resp = self.client.get(&url).send().await?;
        if resp.status() == 404 {
            return Ok(None);
        }
        let hit: InspireHit = resp.json().await?;
        Ok(Some(hit_to_paper(&hit)))
    }

    async fn get_citations(&self, id: &str) -> Result<Vec<PaperResult>, SourceError> {
        let recid = id.strip_prefix("inspire:").unwrap_or(id);
        let q = format!("refersto:recid:{}", recid);
        let resp: InspireResponse = self.client
            .get(BASE_URL)
            .query(&[
                ("q", q.as_str()),
                ("size", "25"),
                ("fields", "titles,authors,abstracts,dois,arxiv_eprints,citation_count,urls,earliest_date"),
            ])
            .send()
            .await?
            .json()
            .await?;
        Ok(resp.hits.hits.iter().map(hit_to_paper).collect())
    }

    async fn get_references(&self, id: &str) -> Result<Vec<PaperResult>, SourceError> {
        let recid = id.strip_prefix("inspire:").unwrap_or(id);
        let url = format!("{}/{}/references", BASE_URL, recid);
        let resp: InspireResponse = self.client
            .get(&url)
            .query(&[("fields", "titles,authors,abstracts,dois,arxiv_eprints,citation_count,urls,earliest_date")])
            .send()
            .await?
            .json()
            .await?;
        Ok(resp.hits.hits.iter().map(hit_to_paper).collect())
    }
}
