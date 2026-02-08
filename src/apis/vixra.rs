use super::{PaperResult, PaperSource, SourceError};
use async_trait::async_trait;
use scraper::{Html, Selector};

const BASE_URL: &str = "https://vixra.org";

pub struct VixraClient {
    client: reqwest::Client,
}

impl VixraClient {
    pub fn new() -> Self {
        Self {
            client: reqwest::Client::builder()
                .user_agent("paper-search-mcp/0.1")
                .build()
                .unwrap(),
        }
    }
}

#[async_trait]
impl PaperSource for VixraClient {
    fn name(&self) -> &str { "vixra" }

    async fn search(&self, query: &str, max_results: u32) -> Result<Vec<PaperResult>, SourceError> {
        let url = format!("{}/find?text={}", BASE_URL, urlencoded(query));
        let html = self.client.get(&url).send().await?.text().await?;
        parse_vixra_html(&html, max_results)
    }

    async fn get_paper(&self, id: &str) -> Result<Option<PaperResult>, SourceError> {
        let vixra_id = id.strip_prefix("vixra:").unwrap_or(id);
        let url = format!("{}/abs/{}", BASE_URL, vixra_id);
        let html = self.client.get(&url).send().await?.text().await?;
        let document = Html::parse_document(&html);
        // Parse single paper page
        let title_sel = Selector::parse("h1").map_err(|e| SourceError::Parse(format!("{:?}", e)))?;
        let title = document.select(&title_sel)
            .next()
            .map(|el| el.text().collect::<String>())
            .unwrap_or_default();
        if title.is_empty() {
            return Ok(None);
        }
        Ok(Some(PaperResult {
            id: format!("vixra:{}", vixra_id),
            title: title.trim().to_string(),
            authors: vec![],
            abstract_text: None,
            year: None,
            source: "vixra".to_string(),
            doi: None,
            arxiv_id: None,
            url: format!("{}/abs/{}", BASE_URL, vixra_id),
            pdf_url: Some(format!("{}/pdf/{}.pdf", BASE_URL, vixra_id)),
            citation_count: None,
        }))
    }

    async fn get_citations(&self, _id: &str) -> Result<Vec<PaperResult>, SourceError> { Ok(vec![]) }
    async fn get_references(&self, _id: &str) -> Result<Vec<PaperResult>, SourceError> { Ok(vec![]) }
}

fn urlencoded(s: &str) -> String {
    s.replace(' ', "+")
}

fn parse_vixra_html(html: &str, max_results: u32) -> Result<Vec<PaperResult>, SourceError> {
    let document = Html::parse_document(html);
    let mut papers = Vec::new();

    // viXra search results are typically in <b> tags with links
    let link_sel = Selector::parse("a[href*='/abs/']").map_err(|e| SourceError::Parse(format!("{:?}", e)))?;

    for link in document.select(&link_sel).take(max_results as usize) {
        let href = link.value().attr("href").unwrap_or("");
        let title = link.text().collect::<String>();
        let title = title.trim().to_string();

        if title.is_empty() || !href.contains("/abs/") {
            continue;
        }

        let vixra_id = href.rsplit("/abs/").next().unwrap_or("").to_string();
        if vixra_id.is_empty() {
            continue;
        }

        papers.push(PaperResult {
            id: format!("vixra:{}", vixra_id),
            title,
            authors: vec![],
            abstract_text: None,
            year: None,
            source: "vixra".to_string(),
            doi: None,
            arxiv_id: None,
            url: format!("{}/abs/{}", BASE_URL, vixra_id),
            pdf_url: Some(format!("{}/pdf/{}.pdf", BASE_URL, vixra_id)),
            citation_count: None,
        });
    }

    Ok(papers)
}
