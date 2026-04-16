use super::{normalize_date_string, PaperResult, PaperSource, SearchOptions, SourceError};
use async_trait::async_trait;
use futures::{stream, StreamExt};
use scraper::{ElementRef, Html, Selector};

const BASE_URL: &str = "https://vixra.org";
const ARCHIVE_URL: &str = "https://vixra.org/all";
const MAX_ARCHIVE_CONCURRENCY: usize = 8;

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
    fn name(&self) -> &str {
        "vixra"
    }

    async fn search(
        &self,
        query: &str,
        max_results: u32,
        _options: &SearchOptions,
    ) -> Result<Vec<PaperResult>, SourceError> {
        let archive_html = self.client.get(ARCHIVE_URL).send().await?.text().await?;
        let mut matches = search_archive_page(&archive_html, query);
        let month_paths = parse_month_paths(&archive_html);

        let month_results: Vec<Vec<ScoredPaper>> =
            stream::iter(month_paths.into_iter().map(|path| {
                let client = self.client.clone();
                async move {
                    let url = format!("{}/{}", ARCHIVE_URL, path);
                    let html = client.get(&url).send().await?.text().await?;
                    Ok::<_, reqwest::Error>(search_archive_page(&html, query))
                }
            }))
            .buffer_unordered(MAX_ARCHIVE_CONCURRENCY)
            .filter_map(|result| async move {
                match result {
                    Ok(papers) => Some(papers),
                    Err(err) => {
                        tracing::warn!("viXra archive fetch failed: {}", err);
                        None
                    }
                }
            })
            .collect()
            .await;

        for papers in month_results {
            matches.extend(papers);
        }

        matches.sort_by(|a, b| {
            b.score
                .cmp(&a.score)
                .then_with(|| b.paper.year.unwrap_or(0).cmp(&a.paper.year.unwrap_or(0)))
                .then_with(|| b.paper.id.cmp(&a.paper.id))
        });

        Ok(dedupe_scored_papers(matches)
            .into_iter()
            .take(max_results as usize)
            .collect::<Vec<_>>())
    }

    async fn get_paper(&self, id: &str) -> Result<Option<PaperResult>, SourceError> {
        let vixra_id = id.strip_prefix("vixra:").unwrap_or(id);
        let url = format!("{}/abs/{}", BASE_URL, vixra_id);
        let html = self.client.get(&url).send().await?.text().await?;
        Ok(parse_paper_page(&html, vixra_id))
    }

    async fn get_citations(&self, _id: &str) -> Result<Vec<PaperResult>, SourceError> {
        Ok(vec![])
    }
    async fn get_references(&self, _id: &str) -> Result<Vec<PaperResult>, SourceError> {
        Ok(vec![])
    }
}

#[derive(Clone, Debug)]
struct ScoredPaper {
    paper: PaperResult,
    score: u32,
}

fn search_archive_page(html: &str, query: &str) -> Vec<ScoredPaper> {
    parse_listing_entries(html)
        .into_iter()
        .filter_map(|paper| score_paper(paper, query))
        .collect()
}

fn parse_month_paths(html: &str) -> Vec<String> {
    let document = Html::parse_document(html);
    let link_sel = Selector::parse("a[href]").unwrap();
    let mut months = document
        .select(&link_sel)
        .filter_map(|link| link.value().attr("href"))
        .filter_map(normalize_month_path)
        .collect::<Vec<_>>();

    months.sort();
    months.dedup();
    months.reverse();
    months
}

fn normalize_month_path(href: &str) -> Option<String> {
    let trimmed = href.trim_matches('/');
    let code = trimmed.strip_prefix("all/").unwrap_or(trimmed);
    if code.len() == 4 && code.chars().all(|c| c.is_ascii_digit()) {
        Some(code.to_string())
    } else {
        None
    }
}

fn parse_listing_entries(html: &str) -> Vec<PaperResult> {
    let document = Html::parse_document(html);
    let entry_sel = Selector::parse("div#flow > p").unwrap();
    let title_sel = Selector::parse("h3").unwrap();
    let abstract_sel = Selector::parse("p").unwrap();
    let author_sel = Selector::parse("a[href^='/author/']").unwrap();
    let id_link_sel = Selector::parse("a[href^='/abs/']").unwrap();

    let mut papers = Vec::new();
    let mut entry_iter = document.select(&entry_sel);

    while let Some(entry) = entry_iter.next() {
        let Some(id_link) = entry
            .select(&id_link_sel)
            .find(|link| link.text().collect::<String>().trim().starts_with("viXra:"))
        else {
            continue;
        };

        let id_text = id_link.text().collect::<String>().trim().to_string();
        let vixra_id = id_text.strip_prefix("viXra:").unwrap_or("").to_string();
        if vixra_id.is_empty() {
            continue;
        }

        let abstract_block = next_abstract_block(entry);

        let Some(abstract_block) = abstract_block else {
            continue;
        };

        let title = abstract_block
            .select(&title_sel)
            .next()
            .map(text_of)
            .unwrap_or_default();
        if title.is_empty() {
            continue;
        }

        let authors = abstract_block
            .select(&author_sel)
            .map(text_of)
            .filter(|author| !author.is_empty())
            .collect::<Vec<_>>();

        let abstract_text = abstract_block
            .select(&abstract_sel)
            .last()
            .map(text_of)
            .filter(|text| !text.is_empty());

        let year = year_from_vixra_id(&vixra_id);

        papers.push(PaperResult {
            id: format!("vixra:{}", vixra_id),
            title,
            authors,
            abstract_text,
            year,
            source: "vixra".to_string(),
            doi: None,
            arxiv_id: None,
            url: format!("{}/abs/{}", BASE_URL, vixra_id),
            pdf_url: Some(format!("{}/pdf/{}v1.pdf", BASE_URL, vixra_id)),
            citation_count: None,
            published_at: year.and_then(|y| normalize_date_string(&y.to_string())),
            ranking_date: year.and_then(|y| normalize_date_string(&y.to_string())),
        });
    }

    papers
}

fn next_abstract_block(entry: ElementRef<'_>) -> Option<ElementRef<'_>> {
    let mut sibling = entry.next_sibling();
    while let Some(node) = sibling {
        sibling = node.next_sibling();
        let Some(element) = ElementRef::wrap(node) else {
            continue;
        };
        if element.value().id() == Some("abstract") {
            return Some(element);
        }
        if element.value().name() == "p" {
            return None;
        }
    }
    None
}

fn parse_paper_page(html: &str, vixra_id: &str) -> Option<PaperResult> {
    let document = Html::parse_document(html);
    let title = meta_content(&document, "citation_title")
        .or_else(|| first_text(&document, "div#flow h2"))
        .unwrap_or_default();
    if title.is_empty() {
        return None;
    }

    let authors = meta_contents(&document, "citation_author");
    let abstract_text = first_text(&document, "div#abstract p");
    let year = meta_content(&document, "citation_online_date")
        .and_then(|date| date.get(..4).and_then(|year| year.parse::<u32>().ok()))
        .or_else(|| year_from_vixra_id(vixra_id));
    let published_at = meta_content(&document, "citation_online_date")
        .and_then(|date| normalize_date_string(&date))
        .or_else(|| year.and_then(|y| normalize_date_string(&y.to_string())));
    let pdf_url = meta_content(&document, "citation_pdf_url")
        .map(|url| url.replace("http://", "https://"))
        .or_else(|| Some(format!("{}/pdf/{}v1.pdf", BASE_URL, vixra_id)));

    Some(PaperResult {
        id: format!("vixra:{}", vixra_id),
        title,
        authors,
        abstract_text,
        year,
        source: "vixra".to_string(),
        doi: None,
        arxiv_id: None,
        url: format!("{}/abs/{}", BASE_URL, vixra_id),
        pdf_url,
        citation_count: None,
        published_at: published_at.clone(),
        ranking_date: published_at,
    })
}

fn meta_content(document: &Html, name: &str) -> Option<String> {
    let selector = Selector::parse(&format!("meta[name='{}']", name)).ok()?;
    document
        .select(&selector)
        .next()
        .and_then(|meta| meta.value().attr("content"))
        .map(|value| value.trim().to_string())
        .filter(|value| !value.is_empty())
}

fn meta_contents(document: &Html, name: &str) -> Vec<String> {
    let Ok(selector) = Selector::parse(&format!("meta[name='{}']", name)) else {
        return Vec::new();
    };

    document
        .select(&selector)
        .filter_map(|meta| meta.value().attr("content"))
        .map(|value| value.trim().to_string())
        .filter(|value| !value.is_empty())
        .collect()
}

fn first_text(document: &Html, selector: &str) -> Option<String> {
    let selector = Selector::parse(selector).ok()?;
    document
        .select(&selector)
        .next()
        .map(text_of)
        .filter(|value| !value.is_empty())
}

fn text_of(node: ElementRef<'_>) -> String {
    node.text()
        .collect::<Vec<_>>()
        .join(" ")
        .split_whitespace()
        .collect::<Vec<_>>()
        .join(" ")
}

fn year_from_vixra_id(vixra_id: &str) -> Option<u32> {
    let prefix = vixra_id.get(..2)?;
    let year = prefix.parse::<u32>().ok()?;
    Some(2000 + year)
}

fn score_paper(paper: PaperResult, query: &str) -> Option<ScoredPaper> {
    let query_lower = query.to_lowercase();
    let terms = query_lower
        .split_whitespace()
        .filter(|term| term.len() >= 2)
        .collect::<Vec<_>>();

    if terms.is_empty() {
        return None;
    }

    let title = paper.title.to_lowercase();
    let authors = paper.authors.join(" ").to_lowercase();
    let abstract_text = paper
        .abstract_text
        .clone()
        .unwrap_or_default()
        .to_lowercase();
    let id = paper.id.to_lowercase();

    let mut score = 0;
    if title.contains(&query_lower) {
        score += 80;
    }
    if authors.contains(&query_lower) {
        score += 60;
    }
    if abstract_text.contains(&query_lower) {
        score += 30;
    }
    if id.contains(&query_lower) {
        score += 100;
    }

    for term in &terms {
        if title.contains(term) {
            score += 20;
        }
        if authors.contains(term) {
            score += 12;
        }
        if abstract_text.contains(term) {
            score += 6;
        }
        if id.contains(term) {
            score += 25;
        }
    }

    if score == 0 {
        None
    } else {
        Some(ScoredPaper { paper, score })
    }
}

fn dedupe_scored_papers(papers: Vec<ScoredPaper>) -> Vec<PaperResult> {
    let mut seen = std::collections::HashSet::new();
    let mut deduped = Vec::new();

    for scored in papers {
        if seen.insert(scored.paper.id.clone()) {
            deduped.push(scored.paper);
        }
    }

    deduped
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_month_links_from_archive() {
        let html = r#"
        <div id="flow">
          <p><b>Previous months:</b>
            <a href="2601">2601</a>
            <a href="2602">2602</a>
            <a href="2603">2603</a>
          </p>
        </div>
        "#;
        assert_eq!(parse_month_paths(html), vec!["2603", "2602", "2601"]);
    }

    #[test]
    fn parses_listing_entries() {
        let html = r#"
        <div id="flow">
          <p>[1] <b><a href="/abs/2603.0090">viXra:2603.0090</a> [<a href="/pdf/2603.0090v1.pdf">pdf</a>]</b></p>
          <div id="abstract">
            <h3>A Table of Pisano Period Lengths</h3>
            <p><b>Authors:</b> <a href="/author/richard_j_mathar">Richard J. Mathar</a></p>
            <p>A Pisano period is the period of an integer sequence.</p>
          </div>
        </div>
        "#;
        let papers = parse_listing_entries(html);
        assert_eq!(papers.len(), 1);
        assert_eq!(papers[0].id, "vixra:2603.0090");
        assert_eq!(papers[0].title, "A Table of Pisano Period Lengths");
        assert_eq!(papers[0].authors, vec!["Richard J. Mathar"]);
        assert_eq!(papers[0].year, Some(2026));
        assert_eq!(papers[0].published_at.as_deref(), Some("2026-01-01"));
    }

    #[test]
    fn parses_paper_page_metadata() {
        let html = r#"
        <html>
          <head>
            <meta name="citation_title" content="A Table of Pisano Period Lengths">
            <meta name="citation_author" content="Richard J. Mathar">
            <meta name="citation_online_date" content="2026/03/01">
            <meta name="citation_pdf_url" content="http://vixra.org/pdf/2603.0090v1.pdf">
          </head>
          <body>
            <div id="flow">
              <h2>A Table of Pisano Period Lengths</h2>
            </div>
            <div id="abstract">
              <p>A Pisano period is the period of an integer sequence.</p>
            </div>
          </body>
        </html>
        "#;
        let paper = parse_paper_page(html, "2603.0090").unwrap();
        assert_eq!(paper.title, "A Table of Pisano Period Lengths");
        assert_eq!(paper.authors, vec!["Richard J. Mathar"]);
        assert_eq!(paper.year, Some(2026));
        assert_eq!(paper.published_at.as_deref(), Some("2026-03-01"));
        assert_eq!(
            paper.pdf_url.as_deref(),
            Some("https://vixra.org/pdf/2603.0090v1.pdf")
        );
    }
}
