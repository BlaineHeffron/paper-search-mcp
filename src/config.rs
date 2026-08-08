use std::path::PathBuf;
use std::sync::Arc;
use std::time::Duration;

use crate::{
    access::InstitutionalAccess,
    apis::{self, PaperSource},
    institutional::{
        retrieval::{InstitutionalRetriever, RetrievalConfig},
        InstitutionalSessionConfig, InstitutionalSessionManager, SessionError,
    },
};

/// Server configuration loaded from environment variables.
#[derive(Debug, Clone)]
pub struct Config {
    pub data_dir: PathBuf,
    pub semantic_scholar_api_key: Option<String>,
    pub ads_api_key: Option<String>,
    pub openalex_email: Option<String>,
    pub openalex_api_key: Option<String>,
    pub unpaywall_email: Option<String>,
    pub institution_name: Option<String>,
    pub library_proxy_url: Option<String>,
    pub library_proxy_target_parameter: String,
    pub institutional_allowed_hosts: Vec<String>,
    pub institutional_download_dir: PathBuf,
    pub institutional_max_session_ttl_seconds: i64,
    pub institutional_max_pdf_bytes: usize,
    pub institutional_minimum_interval_seconds: u64,
    pub institutional_hourly_limit: usize,
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
        let institution_name = env_opt("PAPER_SEARCH_INSTITUTION_NAME");
        let library_proxy_url = env_opt("PAPER_SEARCH_LIBRARY_PROXY_URL");
        let library_proxy_target_parameter = env_opt("PAPER_SEARCH_LIBRARY_PROXY_TARGET_PARAMETER")
            .unwrap_or_else(|| "url".to_string());
        let institutional_allowed_hosts = env_opt("PAPER_SEARCH_INSTITUTION_ALLOWED_HOSTS")
            .map(|value| {
                value
                    .split(',')
                    .map(|host| host.trim().trim_start_matches('.').to_ascii_lowercase())
                    .filter(|host| !host.is_empty())
                    .collect()
            })
            .unwrap_or_default();
        let institutional_download_dir = env_opt("PAPER_SEARCH_INSTITUTION_DOWNLOAD_DIR")
            .map(PathBuf::from)
            .unwrap_or_else(|| data_dir.join("downloads").join("institutional"));
        let institutional_max_session_ttl_seconds = parse_env_bounded(
            "PAPER_SEARCH_INSTITUTION_SESSION_TTL_SECONDS",
            43_200,
            60,
            86_400,
        );
        let institutional_max_pdf_bytes = parse_env_bounded(
            "PAPER_SEARCH_INSTITUTION_MAX_PDF_BYTES",
            50 * 1024 * 1024,
            1024,
            100 * 1024 * 1024,
        );
        let institutional_minimum_interval_seconds =
            parse_env_bounded("PAPER_SEARCH_INSTITUTION_MIN_INTERVAL_SECONDS", 30, 1, 3600);
        let institutional_hourly_limit =
            parse_env_bounded("PAPER_SEARCH_INSTITUTION_HOURLY_LIMIT", 10, 1, 60);

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
            institution_name,
            library_proxy_url,
            library_proxy_target_parameter,
            institutional_allowed_hosts,
            institutional_download_dir,
            institutional_max_session_ttl_seconds,
            institutional_max_pdf_bytes,
            institutional_minimum_interval_seconds,
            institutional_hourly_limit,
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

    /// Build institutional access when a proxy login endpoint is configured.
    /// Credentials are intentionally not part of server configuration.
    pub fn build_institutional_access(&self) -> Option<InstitutionalAccess> {
        let proxy_url = self.library_proxy_url.as_ref()?;
        let institution = self
            .institution_name
            .clone()
            .unwrap_or_else(|| "Configured institution".to_string());

        match InstitutionalAccess::new(
            institution,
            proxy_url.clone(),
            self.library_proxy_target_parameter.clone(),
        ) {
            Ok(access) => Some(access),
            Err(err) => {
                tracing::warn!("Institutional access disabled: {}", err);
                None
            }
        }
    }

    pub fn try_build_institutional_session_manager(
        &self,
    ) -> Result<Option<InstitutionalSessionManager>, SessionError> {
        let Some(access) = self.build_institutional_access() else {
            return Ok(None);
        };
        let institution_name = self
            .institution_name
            .clone()
            .unwrap_or_else(|| "Configured institution".to_string());
        let institution_id = access.proxy_host().to_ascii_lowercase();
        let allowed_hosts = self.resolved_institutional_hosts(&access);
        InstitutionalSessionManager::new(InstitutionalSessionConfig {
            data_dir: self.data_dir.clone(),
            institution_id,
            institution_name,
            allowed_hosts,
            max_session_ttl_seconds: self.institutional_max_session_ttl_seconds,
        })
        .map(Some)
    }

    pub fn build_institutional_retriever(&self) -> Option<InstitutionalRetriever> {
        let access = self.build_institutional_access()?;
        match InstitutionalRetriever::new(RetrievalConfig {
            download_root: self.institutional_download_dir.clone(),
            allowed_hosts: self.resolved_institutional_hosts(&access),
            max_response_bytes: self.institutional_max_pdf_bytes,
            max_redirects: 5,
            connect_timeout: Duration::from_secs(10),
            request_timeout: Duration::from_secs(60),
            minimum_interval: Duration::from_secs(self.institutional_minimum_interval_seconds),
            hourly_limit: self.institutional_hourly_limit,
        }) {
            Ok(retriever) => Some(retriever),
            Err(error) => {
                tracing::warn!("Institutional retrieval disabled: {}", error);
                None
            }
        }
    }

    fn resolved_institutional_hosts(&self, access: &InstitutionalAccess) -> Vec<String> {
        let proxy_host = access.proxy_host().to_ascii_lowercase();
        let mut hosts = self.institutional_allowed_hosts.clone();
        if !hosts.contains(&proxy_host) {
            hosts.push(proxy_host);
        }
        hosts.sort();
        hosts.dedup();
        hosts
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
            SourceStatus {
                name: "institutional_access".into(),
                enabled: self.build_institutional_access().is_some(),
                note: match (&self.institution_name, &self.library_proxy_url) {
                    (Some(name), Some(_)) => format!(
                        "Browser-mediated access configured for {}; credentials remain in the institutional login flow",
                        name
                    ),
                    (None, Some(_)) => "Browser-mediated access configured; institution name not set".into(),
                    (_, None) => "Disabled: PAPER_SEARCH_LIBRARY_PROXY_URL not set".into(),
                },
            },
        ];

        // Apply filter
        if !self.enabled_source_names.is_empty() {
            for s in &mut statuses {
                if s.name != "institutional_access" && !self.enabled_source_names.contains(&s.name)
                {
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

fn parse_env_bounded<T>(name: &str, default: T, minimum: T, maximum: T) -> T
where
    T: std::str::FromStr + Ord + Copy,
{
    std::env::var(name)
        .ok()
        .and_then(|value| value.parse::<T>().ok())
        .filter(|value| *value >= minimum && *value <= maximum)
        .unwrap_or(default)
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
            institution_name: None,
            library_proxy_url: None,
            library_proxy_target_parameter: "url".to_string(),
            institutional_allowed_hosts: Vec::new(),
            institutional_download_dir: PathBuf::from(".paper-search-test/downloads"),
            institutional_max_session_ttl_seconds: 43_200,
            institutional_max_pdf_bytes: 50 * 1024 * 1024,
            institutional_minimum_interval_seconds: 30,
            institutional_hourly_limit: 10,
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
    fn institutional_access_is_independent_of_search_source_allowlist() {
        let mut config = config_with_sources(&["arxiv"]);
        config.institution_name = Some("Example University".to_string());
        config.library_proxy_url = Some("https://proxy.example.edu/login".to_string());

        assert!(config.build_institutional_access().is_some());
        let status = config
            .source_status()
            .into_iter()
            .find(|status| status.name == "institutional_access")
            .unwrap();
        assert!(status.enabled);
        assert!(status.note.contains("Example University"));
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
