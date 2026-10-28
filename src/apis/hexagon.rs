use super::{normalize_date_string, PaperResult, PaperSource, SearchOptions, SourceError};
use async_trait::async_trait;
use serde::Deserialize;

const BASE_URL: &str = "https://hexagonmath.org";

pub struct HexagonClient {
    client: reqwest::Client,
}

impl HexagonClient {
    pub fn new() -> Self {
        Self {
            client: reqwest::Client::builder()
                .user_agent("paper-search-mcp/0.1")
                .timeout(std::time::Duration::from_secs(30))
                .build()
                .unwrap(),
        }
    }
}

#[derive(Deserialize)]
struct WorksResponse {
    works: Vec<Work>,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct Work {
    identifier: String,
    title: String,
    #[serde(rename = "abstract")]
    abstract_text: Option<String>,
    authorship_mode: Option<String>,
    human_understanding: Option<String>,
    published_at: Option<String>,
    doi: Option<String>,
    arxiv_id: Option<String>,
    #[serde(default)]
    authors: Vec<Named>,
    #[serde(default)]
    tools: Vec<Tool>,
}

#[derive(Deserialize)]
struct Named {
    name: String,
}

#[derive(Deserialize)]
struct Tool {
    provider: Option<String>,
    name: Option<String>,
}

fn work_to_paper(w: Work) -> PaperResult {
    let tools = w
        .tools
        .iter()
        .map(|t| {
            [t.provider.as_deref(), t.name.as_deref()]
                .into_iter()
                .flatten()
                .collect::<Vec<_>>()
                .join(" ")
        })
        .collect::<Vec<_>>()
        .join(", ");
    let note = format!(
        "[Hexagon AI provenance: authorship={}; human understanding={}; tools={}]",
        w.authorship_mode.as_deref().unwrap_or("unknown"),
        w.human_understanding.as_deref().unwrap_or("unknown"),
        if tools.is_empty() { "unknown" } else { &tools }
    );
    let abstract_text = match w.abstract_text.as_deref().map(str::trim) {
        Some(a) if !a.is_empty() => format!("{a}\n\n{note}"),
        _ => note,
    };
    let date = w.published_at.as_deref().and_then(normalize_date_string);
    PaperResult {
        id: format!("hexagon:{}", w.identifier),
        title: w.title,
        authors: w.authors.into_iter().map(|a| a.name).collect(),
        abstract_text: Some(abstract_text),
        year: date.as_deref().and_then(|d| d.get(..4)?.parse().ok()),
        source: "hexagon".to_string(),
        doi: w.doi,
        arxiv_id: w.arxiv_id,
        url: format!("{}/abs/{}", BASE_URL, w.identifier),
        pdf_url: Some(format!("{}/pdf/{}", BASE_URL, w.identifier)),
        citation_count: None,
        published_at: date.clone(),
        ranking_date: date,
    }
}

#[async_trait]
impl PaperSource for HexagonClient {
    fn name(&self) -> &str {
        "hexagon"
    }

    // The works API has no date parameters; federated search applies date filters.
    async fn search(
        &self,
        query: &str,
        max_results: u32,
        _options: &SearchOptions,
    ) -> Result<Vec<PaperResult>, SourceError> {
        let resp: WorksResponse = works_request(&self.client, query)
            .send()
            .await?
            .error_for_status()?
            .json()
            .await?;
        // q matches the whole phrase, so multi-word queries are ANDed locally.
        Ok(resp
            .works
            .into_iter()
            .map(work_to_paper)
            .filter(|p| super::aixiv::matches_query(p, query))
            .take(max_results as usize)
            .collect())
    }

    async fn get_paper(&self, id: &str) -> Result<Option<PaperResult>, SourceError> {
        let id = id.strip_prefix("hexagon:").unwrap_or(id);
        let resp = self
            .client
            .get(format!("{}/api/v1/works/{}", BASE_URL, id))
            .send()
            .await?;
        if resp.status() == reqwest::StatusCode::NOT_FOUND {
            return Ok(None);
        }
        parse_single_work(&resp.error_for_status()?.text().await?).map(Some)
    }

    async fn get_citations(&self, _id: &str) -> Result<Vec<PaperResult>, SourceError> {
        Ok(vec![])
    }
    async fn get_references(&self, _id: &str) -> Result<Vec<PaperResult>, SourceError> {
        Ok(vec![])
    }
}

/// Query by the longest term (likely the most selective), since q is a phrase match.
/// q is limited to a 50-byte LIKE pattern, two bytes of which are the % wrappers.
fn works_request(client: &reqwest::Client, query: &str) -> reqwest::RequestBuilder {
    let term = query
        .split_whitespace()
        .max_by_key(|t| t.len())
        .unwrap_or("");
    let mut end = term.len().min(48);
    while !term.is_char_boundary(end) {
        end -= 1;
    }
    client
        .get(format!("{}/api/v1/works", BASE_URL))
        .query(&[("q", &term[..end]), ("limit", "50")])
}

/// Accept either a bare work object or one wrapped as `{"work": {...}}`.
fn parse_single_work(json: &str) -> Result<PaperResult, SourceError> {
    let value: serde_json::Value =
        serde_json::from_str(json).map_err(|e| SourceError::Parse(e.to_string()))?;
    let work = value.get("work").cloned().unwrap_or(value);
    serde_json::from_value(work)
        .map(work_to_paper)
        .map_err(|e| SourceError::Parse(e.to_string()))
}

#[cfg(test)]
mod tests {
    use super::*;

    const SAMPLE: &str = r#"{"works":[{"identifier":"2610.00588","title":"A Lemma","abstract":"We prove it.","authorshipMode":"no-human-author-claimed","humanUnderstanding":"some","publishedAt":"2026-10-27T20:31:55.750Z","doi":null,"arxivId":"2610.01234","license":"CC-BY-4.0","authors":[{"name":"Ada","orcid":null}],"tools":[{"provider":"Acme","name":"Prover"}]}],"page":{"next_cursor":null,"total":1}}"#;

    #[test]
    fn parses_works_with_provenance() {
        let resp: WorksResponse = serde_json::from_str(SAMPLE).unwrap();
        let p = work_to_paper(resp.works.into_iter().next().unwrap());
        assert_eq!(p.id, "hexagon:2610.00588");
        assert_eq!(p.arxiv_id.as_deref(), Some("2610.01234"));
        assert_eq!(p.authors, vec!["Ada"]);
        assert_eq!(p.published_at.as_deref(), Some("2026-10-27"));
        assert_eq!(p.year, Some(2026));
        assert_eq!(
            p.pdf_url.as_deref(),
            Some("https://hexagonmath.org/pdf/2610.00588")
        );
        let abs = p.abstract_text.unwrap();
        assert!(abs.starts_with("We prove it."));
        assert!(abs.contains("authorship=no-human-author-claimed"));
        assert!(abs.contains("human understanding=some"));
        assert!(abs.contains("tools=Acme Prover"));
    }

    #[test]
    fn multi_word_query_requests_longest_term_bounded() {
        let client = reqwest::Client::new();
        let url = |q| works_request(&client, q).build().unwrap().url().to_string();
        assert_eq!(
            url("Lean formalization of Erdos problem"),
            "https://hexagonmath.org/api/v1/works?q=formalization&limit=50"
        );
        let long = "é".repeat(30);
        assert!(url(&long).contains(&format!("q={}&", "%C3%A9".repeat(24))));
    }

    #[test]
    fn parses_single_work_bare_or_wrapped() {
        let bare = r#"{"identifier":"2610.00001","title":"T"}"#;
        let wrapped = r#"{"work":{"identifier":"2610.00001","title":"T"}}"#;
        assert_eq!(parse_single_work(bare).unwrap().id, "hexagon:2610.00001");
        assert_eq!(parse_single_work(wrapped).unwrap().id, "hexagon:2610.00001");
    }
}
