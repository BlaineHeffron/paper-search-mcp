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
        let should_enable = |name: &str| self.should_enable_source(name);

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
                enabled: self.should_enable_source("vixra"),
                note: if self.should_enable_source("vixra") {
                    "HTML scraping".into()
                } else {
                    "Disabled by default; opt in with PAPER_SEARCH_SOURCES".into()
                },
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

    fn should_enable_source(&self, name: &str) -> bool {
        if self.enabled_source_names.is_empty() {
            return name != "vixra";
        }

        self.enabled_source_names.contains(&name.to_lowercase())
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

#[cfg(test)]
mod tests {
    use super::Config;
    use std::path::PathBuf;

    fn config_with_sources(enabled_source_names: &[&str]) -> Config {
        Config {
            data_dir: PathBuf::from(".paper-search-test"),
            semantic_scholar_api_key: None,
            ads_api_key: None,
            openalex_email: None,
            openalex_api_key: None,
            unpaywall_email: None,
            enabled_source_names: enabled_source_names
                .iter()
                .map(|name| name.to_string())
                .collect(),
        }
    }

    fn built_source_names(config: &Config) -> Vec<String> {
        config
            .build_sources()
            .into_iter()
            .map(|source| source.name().to_string())
            .collect()
    }

    #[test]
    fn default_enabled_sources_exclude_vixra() {
        let config = config_with_sources(&[]);

        let names = built_source_names(&config);

        assert!(names.contains(&"arxiv".to_string()));
        assert!(names.contains(&"inspire".to_string()));
        assert!(names.contains(&"crossref".to_string()));
        assert!(names.contains(&"doaj".to_string()));
        assert!(names.contains(&"europepmc".to_string()));
        assert!(names.contains(&"semantic_scholar".to_string()));
        assert!(names.contains(&"openalex".to_string()));
        assert!(!names.contains(&"vixra".to_string()));
    }

    #[test]
    fn explicit_source_allowlist_can_enable_vixra() {
        let config = config_with_sources(&["arxiv", "vixra"]);

        let names = built_source_names(&config);

        assert_eq!(names, vec!["arxiv".to_string(), "vixra".to_string()]);
    }

    #[test]
    fn source_status_marks_vixra_disabled_by_default_and_enabled_when_listed() {
        let default_status = config_with_sources(&[])
            .source_status()
            .into_iter()
            .find(|status| status.name == "vixra")
            .expect("vixra status");
        assert!(!default_status.enabled);
        assert!(default_status.note.contains("Disabled by default"));

        let enabled_status = config_with_sources(&["vixra"])
            .source_status()
            .into_iter()
            .find(|status| status.name == "vixra")
            .expect("vixra status");
        assert!(enabled_status.enabled);
        assert_eq!(enabled_status.note, "HTML scraping");
    }
}
