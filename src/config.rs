use std::path::PathBuf;
use std::sync::Arc;

use crate::apis::{self, PaperSource};

/// Server configuration loaded from environment variables.
#[derive(Debug, Clone)]
pub struct Config {
    pub data_dir: PathBuf,
    pub semantic_scholar_api_key: Option<String>,
    pub ads_api_key: Option<String>,
    pub openalex_email: Option<String>,
    pub openalex_api_key: Option<String>,
    pub unpaywall_email: Option<String>,
    pub enabled_source_names: Vec<String>,
}

impl Config {
    /// Load configuration from environment variables.
    pub fn from_env() -> Self {
        let data_dir = std::env::var("PAPER_SEARCH_DATA_DIR")
            .map(PathBuf::from)
            .unwrap_or_else(|_| dirs_or_default().join(".paper-search"));

        // Treat empty env values ("") as unset, not Some("").
        let env_opt = |k: &str| std::env::var(k).ok().filter(|v| !v.trim().is_empty());

        let semantic_scholar_api_key = env_opt("SEMANTIC_SCHOLAR_API_KEY");
        let ads_api_key = env_opt("ADS_API_KEY");
        let openalex_email = env_opt("OPENALEX_EMAIL");
        let openalex_api_key = env_opt("OPENALEX_API_KEY");
        let unpaywall_email = env_opt("UNPAYWALL_EMAIL");

        let enabled_source_names = std::env::var("PAPER_SEARCH_SOURCES")
            .map(|s| s.split(',').map(|s| s.trim().to_lowercase()).collect())
            .unwrap_or_default();

        Self {
            data_dir,
            semantic_scholar_api_key,
            ads_api_key,
            openalex_email,
            openalex_api_key,
            unpaywall_email,
            enabled_source_names,
        }
    }

    /// Build the list of enabled paper sources based on configuration.
    pub fn build_sources(&self) -> Vec<Arc<dyn PaperSource>> {
        let mut sources: Vec<Arc<dyn PaperSource>> = Vec::new();
        let filter = &self.enabled_source_names;
        let filter_active = !filter.is_empty();

        let should_enable =
            |name: &str| -> bool { !filter_active || filter.contains(&name.to_lowercase()) };

        // Sources that don't need API keys
        if should_enable("arxiv") {
            sources.push(Arc::new(apis::arxiv::ArxivClient::new()));
        }
        if should_enable("inspire") {
            sources.push(Arc::new(apis::inspire::InspireClient::new()));
        }
        if should_enable("crossref") {
            sources.push(Arc::new(apis::crossref::CrossRefClient::new()));
        }
        if should_enable("doaj") {
            sources.push(Arc::new(apis::doaj::DoajClient::new()));
        }
        if should_enable("europepmc") {
            sources.push(Arc::new(apis::europepmc::EuropePmcClient::new()));
        }
        if should_enable("vixra") {
            sources.push(Arc::new(apis::vixra::VixraClient::new()));
        }

        // Sources with optional API keys
        if should_enable("semantic_scholar") {
            sources.push(Arc::new(
                apis::semantic_scholar::SemanticScholarClient::new(
                    self.semantic_scholar_api_key.clone(),
                ),
            ));
        }
        if should_enable("openalex") {
            sources.push(Arc::new(apis::openalex::OpenAlexClient::new(
                self.openalex_email.clone(),
                self.openalex_api_key.clone(),
            )));
        }

        // Sources requiring API keys
        if should_enable("ads") {
            if let Some(ref key) = self.ads_api_key {
                sources.push(Arc::new(apis::ads::AdsClient::new(key.clone())));
            } else {
                tracing::warn!("NASA ADS disabled: ADS_API_KEY not set");
            }
        }

        sources
    }

    /// Build an Unpaywall client if configured.
    pub fn build_unpaywall(&self) -> Option<apis::unpaywall::UnpaywallClient> {
        self.unpaywall_email
            .as_ref()
            .map(|email| apis::unpaywall::UnpaywallClient::new(email.clone()))
    }

    /// Return a list of source status descriptions.
    pub fn source_status(&self) -> Vec<SourceStatus> {
        let mut statuses = vec![
            SourceStatus {
                name: "arxiv".into(),
                enabled: true,
                note: "No API key required".into(),
            },
            SourceStatus {
                name: "inspire".into(),
                enabled: true,
                note: "No API key required".into(),
            },
            SourceStatus {
                name: "semantic_scholar".into(),
                enabled: true,
                note: if self.semantic_scholar_api_key.is_some() {
                    "API key set".into()
                } else {
                    "No API key (rate limited)".into()
                },
            },
            SourceStatus {
                name: "openalex".into(),
                enabled: true,
                note: if self.openalex_api_key.is_some() {
                    "Premium API key set".into()
                } else if self.openalex_email.is_some() {
                    "Polite pool email set".into()
                } else {
                    "No email (limited rate)".into()
                },
            },
            SourceStatus {
                name: "crossref".into(),
                enabled: true,
                note: "No API key required".into(),
            },
            SourceStatus {
                name: "ads".into(),
                enabled: self.ads_api_key.is_some(),
                note: if self.ads_api_key.is_some() {
                    "API key set".into()
                } else {
                    "Disabled: ADS_API_KEY not set".into()
                },
            },
            SourceStatus {
                name: "europepmc".into(),
                enabled: true,
                note: "No API key required".into(),
            },
            SourceStatus {
                name: "doaj".into(),
                enabled: true,
                note: "No API key required".into(),
            },
            SourceStatus {
                name: "vixra".into(),
                enabled: true,
                note: "HTML scraping".into(),
            },
        ];

        // Apply filter
        if !self.enabled_source_names.is_empty() {
            for s in &mut statuses {
                if !self.enabled_source_names.contains(&s.name) {
                    s.enabled = false;
                    s.note = "Disabled by PAPER_SEARCH_SOURCES filter".into();
                }
            }
        }

        statuses
    }
}

#[derive(Debug, Clone, serde::Serialize)]
pub struct SourceStatus {
    pub name: String,
    pub enabled: bool,
    pub note: String,
}

fn dirs_or_default() -> PathBuf {
    std::env::var("HOME")
        .map(PathBuf::from)
        .unwrap_or_else(|_| PathBuf::from("."))
}
