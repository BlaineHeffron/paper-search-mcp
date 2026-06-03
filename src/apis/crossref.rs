use super::{
    normalize_date_parts, PaperResult, PaperSource, SearchOptions, SearchSort, SourceError,
};
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
    issued: Option<CRDate>,
    #[serde(rename = "published-print")]
    published_print: Option<CRDate>,
    #[serde(rename = "published-online")]
    published_online: Option<CRDate>,
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
    issued: Option<CRDate>,
    #[serde(rename = "published-print")]
    published_print: Option<CRDate>,
    #[serde(rename = "published-online")]
    published_online: Option<CRDate>,
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
    date_parts: Option<Vec<Vec<Option<u32>>>>,
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
    let title = item
        .title
        .as_ref()
        .and_then(|t| t.first())
        .cloned()
        .unwrap_or_default();
    let authors = item
        .author
        .as_ref()
        .map(|a| {
            a.iter()
                .map(|a| {
                    format!(
                        "{} {}",
                        a.given.as_deref().unwrap_or(""),
                        a.family.as_deref().unwrap_or("")
                    )
                    .trim()
                    .to_string()
                })
                .collect()
        })
        .unwrap_or_default();
    let published_at = earliest_crossref_date(item);
    let year = published_at
        .as_deref()
        .and_then(|d| d.get(..4))
        .and_then(|y| y.parse::<u32>().ok());
    let pdf_url = item
        .link
        .as_ref()
        .and_then(|links| {
            links
                .iter()
                .find(|l| l.content_type.as_deref() == Some("application/pdf"))
        })
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
        published_at: published_at.clone(),
        ranking_date: published_at,
    }
}

fn date_to_string(date: &CRDate) -> Option<String> {
    date.date_parts
        .as_ref()
        .and_then(|parts| parts.first())
        .and_then(|parts| {
            let year = parts.first().copied().flatten()?;
            let month = parts.get(1).copied().flatten().unwrap_or(1);
            let day = parts.get(2).copied().flatten().unwrap_or(1);
            normalize_date_parts(&[year, month, day])
        })
}

fn earliest_crossref_date(item: &CRItem) -> Option<String> {
    [
        item.published_online.as_ref().and_then(date_to_string),
        item.published_print.as_ref().and_then(date_to_string),
        item.published.as_ref().and_then(date_to_string),
        item.issued.as_ref().and_then(date_to_string),
    ]
    .into_iter()
    .flatten()
    .min()
}

#[async_trait]
impl PaperSource for CrossRefClient {
    fn name(&self) -> &str {
        "crossref"
    }

    async fn search(
        &self,
        query: &str,
        max_results: u32,
        options: &SearchOptions,
    ) -> Result<Vec<PaperResult>, SourceError> {
        let rows = max_results.min(100).to_string();
        let mut request = self.client.get(BASE_URL).query(&[
            ("query", query),
            ("rows", rows.as_str()),
            (
                "select",
                "DOI,title,author,published,issued,published-print,published-online,is-referenced-by-count,link",
            ),
        ]);

        let mut filters = Vec::new();
        if let Some(from) = options.date_from {
            filters.push(format!("from-pub-date:{}", from.format("%Y-%m-%d")));
        }
        if let Some(to) = options.date_to {
            filters.push(format!("until-pub-date:{}", to.format("%Y-%m-%d")));
        }
        if !filters.is_empty() {
            request = request.query(&[("filter", filters.join(","))]);
        }
        match options.sort {
            SearchSort::DateDesc => {
                request = request.query(&[("sort", "published"), ("order", "desc")]);
            }
            SearchSort::DateAsc => {
                request = request.query(&[("sort", "published"), ("order", "asc")]);
            }
            _ => {}
        }

        let resp: CRResponse = request.send().await?.json().await?;
        Ok(resp
            .message
            .items
            .unwrap_or_default()
            .iter()
            .map(item_to_paper)
            .collect())
    }

    async fn get_paper(&self, id: &str) -> Result<Option<PaperResult>, SourceError> {
        let doi = id.strip_prefix("doi:").unwrap_or(id);
        let url = format!("{}/{}", BASE_URL, doi);
        let resp = self.client.get(&url).send().await?;
        if resp.status() == 404 {
            return Ok(None);
        }
        let cr: CRResponse = resp.json().await?;
        // Single work returns in message directly
        let item = CRItem {
            doi: cr.message.doi,
            title: cr.message.title,
            author: cr.message.author,
            citation_count: cr.message.citation_count,
            published: cr.message.published,
            issued: cr.message.issued,
            published_print: cr.message.published_print,
            published_online: cr.message.published_online,
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn crossref_response_tolerates_null_date_parts() {
        let json = r#"{
            "message": {
                "items": [
                    {
                        "DOI": "10.1007/978-3-7643-7978-0_11",
                        "title": ["Topological Quantum Field Theory as Topological Quantum Gravity"],
                        "issued": { "date-parts": [[null]] },
                        "is-referenced-by-count": 0
                    },
                    {
                        "DOI": "10.1103/physrevd.79.084008",
                        "title": ["Quantum gravity at a Lifshitz point"],
                        "issued": { "date-parts": [[2009, 4, 6]] },
                        "is-referenced-by-count": 2199
                    }
                ]
            }
        }"#;

        let response: CRResponse = serde_json::from_str(json).unwrap();
        let papers: Vec<_> = response
            .message
            .items
            .unwrap()
            .iter()
            .map(item_to_paper)
            .collect();

        assert_eq!(papers.len(), 2);
        assert_eq!(papers[0].published_at, None);
        assert_eq!(papers[1].published_at.as_deref(), Some("2009-04-06"));
    }
}
