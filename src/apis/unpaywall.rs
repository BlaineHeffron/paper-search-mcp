use super::SourceError;
use serde::Deserialize;

const BASE_URL: &str = "https://api.unpaywall.org/v2";

pub struct UnpaywallClient {
    client: reqwest::Client,
    email: String,
}

impl UnpaywallClient {
    pub fn new(email: String) -> Self {
        Self {
            client: reqwest::Client::builder()
                .user_agent("paper-search-mcp/0.1")
                .build()
                .unwrap(),
            email,
        }
    }

    pub async fn get_pdf_url(&self, doi: &str) -> Result<Option<String>, SourceError> {
        let url = format!("{}/{}?email={}", BASE_URL, doi, self.email);
        let resp = self.client.get(&url).send().await?;
        if resp.status() == 404 {
            return Ok(None);
        }
        let data: UnpaywallResponse = resp.json().await?;
        Ok(data.best_oa_location.and_then(|loc| loc.url_for_pdf))
    }
}

#[derive(Deserialize)]
struct UnpaywallResponse {
    best_oa_location: Option<UnpaywallLocation>,
}

#[derive(Deserialize)]
struct UnpaywallLocation {
    url_for_pdf: Option<String>,
}
