use super::{PaperResult, PaperSource, SourceError};
use async_trait::async_trait;
use quick_xml::events::Event;
use quick_xml::Reader;

const BASE_URL: &str = "https://export.arxiv.org/api/query";

pub struct ArxivClient {
    client: reqwest::Client,
}

impl ArxivClient {
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
impl PaperSource for ArxivClient {
    fn name(&self) -> &str {
        "arxiv"
    }

    async fn search(&self, query: &str, max_results: u32) -> Result<Vec<PaperResult>, SourceError> {
        let url = format!(
            "{}?search_query=all:{}&start=0&max_results={}&sortBy=relevance&sortOrder=descending",
            BASE_URL,
            urlencoded(query),
            max_results
        );
        let resp = self.client.get(&url).send().await?.text().await?;
        // Respect rate limit: 1 req / 3s
        tokio::time::sleep(std::time::Duration::from_secs(3)).await;
        parse_atom_feed(&resp)
    }

    async fn get_paper(&self, id: &str) -> Result<Option<PaperResult>, SourceError> {
        let arxiv_id = id.strip_prefix("arxiv:").unwrap_or(id);
        let url = format!("{}?id_list={}", BASE_URL, arxiv_id);
        let resp = self.client.get(&url).send().await?.text().await?;
        let results = parse_atom_feed(&resp)?;
        Ok(results.into_iter().next())
    }

    async fn get_citations(&self, _id: &str) -> Result<Vec<PaperResult>, SourceError> {
        Ok(vec![]) // arXiv doesn't provide citation data
    }

    async fn get_references(&self, _id: &str) -> Result<Vec<PaperResult>, SourceError> {
        Ok(vec![]) // arXiv doesn't provide reference data
    }
}

fn urlencoded(s: &str) -> String {
    s.replace(' ', "+")
        .replace(':', "%3A")
        .replace('/', "%2F")
}

fn parse_atom_feed(xml: &str) -> Result<Vec<PaperResult>, SourceError> {
    let mut reader = Reader::from_str(xml);
    let mut papers = Vec::new();
    let mut in_entry = false;
    let mut current_tag = String::new();
    let mut title = String::new();
    let mut summary = String::new();
    let mut arxiv_id = String::new();
    let mut authors: Vec<String> = Vec::new();
    let mut published = String::new();
    let mut link_pdf = String::new();
    let mut link_abs = String::new();
    let mut author_name = String::new();
    let mut in_author = false;
    let mut doi: Option<String> = None;
    let mut buf = Vec::new();

    loop {
        match reader.read_event_into(&mut buf) {
            Ok(Event::Start(e)) => {
                let tag = String::from_utf8_lossy(e.name().as_ref()).to_string();
                if tag == "entry" {
                    in_entry = true;
                    title.clear();
                    summary.clear();
                    arxiv_id.clear();
                    authors.clear();
                    published.clear();
                    link_pdf.clear();
                    link_abs.clear();
                    doi = None;
                } else if in_entry {
                    current_tag = tag.clone();
                    if tag == "author" {
                        in_author = true;
                        author_name.clear();
                    }
                    if tag == "link" {
                        let mut href = String::new();
                        let mut title_attr = String::new();
                        for attr in e.attributes().flatten() {
                            let key = String::from_utf8_lossy(attr.key.as_ref()).to_string();
                            let val = String::from_utf8_lossy(&attr.value).to_string();
                            if key == "href" {
                                href = val;
                            } else if key == "title" {
                                title_attr = val;
                            }
                        }
                        if title_attr == "pdf" {
                            link_pdf = href;
                        } else if link_abs.is_empty() && href.contains("abs") {
                            link_abs = href;
                        }
                    }
                    // Check for arxiv:doi
                    if tag == "doi" || current_tag.contains("doi") {
                        // Will be captured in text
                    }
                }
            }
            Ok(Event::Empty(e)) if in_entry => {
                let tag = String::from_utf8_lossy(e.name().as_ref()).to_string();
                if tag == "link" {
                    let mut href = String::new();
                    let mut title_attr = String::new();
                    for attr in e.attributes().flatten() {
                        let key = String::from_utf8_lossy(attr.key.as_ref()).to_string();
                        let val = String::from_utf8_lossy(&attr.value).to_string();
                        if key == "href" {
                            href = val;
                        } else if key == "title" {
                            title_attr = val;
                        }
                    }
                    if title_attr == "pdf" {
                        link_pdf = href;
                    } else if link_abs.is_empty() && href.contains("abs") {
                        link_abs = href;
                    }
                }
            }
            Ok(Event::Text(e)) if in_entry => {
                let text = e.unescape().unwrap_or_default().to_string();
                match current_tag.as_str() {
                    "title" => title.push_str(&text),
                    "summary" => summary.push_str(&text),
                    "id" if arxiv_id.is_empty() => arxiv_id = text,
                    "published" => published.push_str(&text),
                    "name" if in_author => author_name.push_str(&text),
                    _ if current_tag.contains("doi") => doi = Some(text),
                    _ => {}
                }
            }
            Ok(Event::End(e)) => {
                let tag = String::from_utf8_lossy(e.name().as_ref()).to_string();
                if tag == "entry" && in_entry {
                    in_entry = false;
                    // Extract arXiv ID from URL
                    let id = arxiv_id
                        .rsplit('/')
                        .next()
                        .unwrap_or(&arxiv_id)
                        .to_string();
                    if !id.is_empty() && !title.trim().is_empty() {
                        let year = published
                            .get(..4)
                            .and_then(|y| y.parse::<u32>().ok());
                        papers.push(PaperResult {
                            id: format!("arxiv:{}", id),
                            title: title.trim().replace('\n', " "),
                            authors: authors.clone(),
                            abstract_text: if summary.trim().is_empty() {
                                None
                            } else {
                                Some(summary.trim().replace('\n', " "))
                            },
                            year,
                            source: "arxiv".to_string(),
                            doi: doi.clone(),
                            arxiv_id: Some(id),
                            url: if link_abs.is_empty() {
                                arxiv_id.clone()
                            } else {
                                link_abs.clone()
                            },
                            pdf_url: if link_pdf.is_empty() {
                                None
                            } else {
                                Some(link_pdf.clone())
                            },
                            citation_count: None,
                        });
                    }
                } else if tag == "author" && in_author {
                    in_author = false;
                    if !author_name.trim().is_empty() {
                        authors.push(author_name.trim().to_string());
                    }
                }
                if tag == current_tag {
                    current_tag.clear();
                }
            }
            Ok(Event::Eof) => break,
            Err(e) => return Err(SourceError::Parse(format!("XML parse error: {}", e))),
            _ => {}
        }
        buf.clear();
    }
    Ok(papers)
}

#[cfg(test)]
mod tests {
    use super::*;

    const SAMPLE_ATOM: &str = r#"<?xml version="1.0" encoding="UTF-8"?>
<feed xmlns="http://www.w3.org/2005/Atom">
  <entry>
    <id>http://arxiv.org/abs/2301.12345v1</id>
    <title>Test Paper on AdS/CFT</title>
    <summary>This is a test abstract about AdS/CFT correspondence.</summary>
    <published>2023-01-15T00:00:00Z</published>
    <author><name>John Doe</name></author>
    <author><name>Jane Smith</name></author>
    <link href="http://arxiv.org/abs/2301.12345v1" rel="alternate" type="text/html"/>
    <link href="http://arxiv.org/pdf/2301.12345v1" title="pdf" type="application/pdf"/>
  </entry>
</feed>"#;

    #[test]
    fn test_parse_atom_feed() {
        let papers = parse_atom_feed(SAMPLE_ATOM).unwrap();
        assert_eq!(papers.len(), 1);
        let p = &papers[0];
        assert_eq!(p.id, "arxiv:2301.12345v1");
        assert!(p.title.contains("AdS/CFT"));
        assert_eq!(p.authors.len(), 2);
        assert_eq!(p.year, Some(2023));
        assert!(p.pdf_url.is_some());
    }
}
