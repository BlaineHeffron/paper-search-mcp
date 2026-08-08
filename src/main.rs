use rmcp::{
    handler::server::tool::ToolRouter, handler::server::wrapper::Parameters, model::*, tool,
    tool_handler, tool_router, transport::stdio, ErrorData as McpError, ServerHandler, ServiceExt,
};
use schemars::JsonSchema;
use serde::Deserialize;
use std::sync::Arc;
use tokio::sync::Mutex;
use tracing_subscriber::EnvFilter;

mod access;
mod apis;
mod config;
mod embed;
mod index;
mod institutional;
mod search;

use apis::PaperSource;
use apis::{SearchOptions, SearchSort};
use config::Config;
use embed::specter;
use index::LocalIndex;

// ── Parameter structs ───────────────────────────────────────────────────────

#[derive(Debug, Deserialize, JsonSchema)]
struct SearchPapersParams {
    #[schemars(description = "Search query string")]
    query: String,
    #[schemars(description = "Filter to specific sources (e.g. [\"arxiv\", \"inspire\"])")]
    sources: Option<Vec<String>>,
    #[schemars(description = "Maximum results to return (default 10, max 100)")]
    max_results: Option<u32>,
    #[schemars(description = "Sort order: relevance (default), date_desc, date_asc, or hybrid")]
    sort: Option<String>,
    #[schemars(
        description = "Inclusive lower publication/submission date bound in YYYY-MM-DD format"
    )]
    date_from: Option<String>,
    #[schemars(
        description = "Inclusive upper publication/submission date bound in YYYY-MM-DD format"
    )]
    date_to: Option<String>,
}

#[derive(Debug, Deserialize, JsonSchema)]
struct GetPaperParams {
    #[schemars(description = "Paper ID with prefix (arxiv:ID, doi:ID, inspire:ID, s2:ID, etc.)")]
    id: String,
    #[schemars(description = "Force a specific source to query")]
    source: Option<String>,
}

#[derive(Debug, Deserialize, JsonSchema)]
struct RelationParams {
    #[schemars(description = "Paper ID to look up citations/references for")]
    id: String,
    #[schemars(description = "Specific source to query")]
    source: Option<String>,
}

#[derive(Debug, Deserialize, JsonSchema)]
struct SearchLocalParams {
    #[schemars(description = "Search query")]
    query: String,
    #[schemars(description = "Search mode: 'hybrid' (default), 'keyword', 'vector'")]
    mode: Option<String>,
    #[schemars(description = "Maximum results (default 10, max 100)")]
    limit: Option<u32>,
}

#[derive(Debug, Deserialize, JsonSchema)]
struct SearchSimilarParams {
    #[schemars(description = "Query text to find similar papers")]
    query: String,
    #[schemars(description = "Maximum results (default 10, max 100)")]
    limit: Option<u32>,
}

#[derive(Debug, Deserialize, JsonSchema)]
struct IndexPaperParams {
    #[schemars(description = "Paper ID to fetch and index")]
    id: String,
    #[schemars(description = "Source to fetch from")]
    source: Option<String>,
}

#[derive(Debug, Deserialize, JsonSchema)]
struct IndexFromQueryParams {
    #[schemars(description = "Search query to find papers to index")]
    query: String,
    #[schemars(description = "Source to search")]
    source: Option<String>,
    #[schemars(description = "Maximum papers to index (default 10, max 50)")]
    max_results: Option<u32>,
}

#[derive(Debug, Deserialize, JsonSchema)]
struct GetPdfUrlParams {
    #[schemars(description = "DOI of the paper")]
    doi: String,
}

#[derive(Debug, Deserialize, JsonSchema)]
struct GetInstitutionalAccessUrlParams {
    #[schemars(
        description = "DOI to route through the configured institution. Supply either doi or url, not both."
    )]
    doi: Option<String>,
    #[schemars(
        description = "Publisher or resolver URL to route through the configured institution. Supply either doi or url, not both."
    )]
    url: Option<String>,
}

#[derive(Debug, Deserialize, JsonSchema)]
struct StartInstitutionalSessionParams {
    #[schemars(
        description = "DOI whose institutional browser login flow should be prepared. Supply either doi or url, not both."
    )]
    doi: Option<String>,
    #[schemars(
        description = "HTTPS publisher URL whose institutional browser login flow should be prepared. Supply either doi or url, not both."
    )]
    url: Option<String>,
}

#[derive(Debug, Deserialize, JsonSchema)]
struct CompleteInstitutionalSessionParams {
    #[schemars(
        description = "Non-secret request ID returned by start_institutional_session. Cookie contents must never be supplied as an argument."
    )]
    request_id: String,
}

#[derive(Debug, Deserialize, JsonSchema)]
struct RetrieveInstitutionalPdfParams {
    #[schemars(description = "HTTPS URL for the one explicitly requested paper")]
    url: String,
    #[schemars(description = "Optional DOI recorded in provenance and checked for open access")]
    doi: Option<String>,
    #[schemars(
        description = "Optional safe destination filename beneath the configured download root"
    )]
    filename: Option<String>,
    #[schemars(
        description = "Caller intent declaration. Must be true: the open-access path was checked and was unavailable. If a DOI and Unpaywall are configured, the server also checks and returns an OA URL instead."
    )]
    confirmed_open_access_unavailable: bool,
    #[schemars(
        description = "Caller intent declaration. Must be true: this individual retrieval is authorized by the user's institutional subscription and applicable terms. The server cannot verify license coverage."
    )]
    confirmed_authorized_access: bool,
}

// ── Server ──────────────────────────────────────────────────────────────────

#[derive(Clone)]
pub struct PaperSearchServer {
    tool_router: ToolRouter<Self>,
    config: Arc<Config>,
    sources: Arc<Vec<Arc<dyn PaperSource>>>,
    local_index: Arc<Mutex<LocalIndex>>,
    unpaywall: Option<Arc<apis::unpaywall::UnpaywallClient>>,
    institutional_access: Option<Arc<access::InstitutionalAccess>>,
    institutional_sessions: Option<Arc<institutional::InstitutionalSessionManager>>,
    institutional_retriever: Option<Arc<institutional::retrieval::InstitutionalRetriever>>,
    institutional_session_fallback_status: Arc<serde_json::Value>,
}

#[tool_router]
impl PaperSearchServer {
    pub async fn create() -> anyhow::Result<Self> {
        let config = Config::from_env();
        let sources = config.build_sources();
        let unpaywall = config.build_unpaywall().map(Arc::new);
        let institutional_access = config.build_institutional_access().map(Arc::new);
        let (institutional_sessions, institutional_session_fallback_status) =
            match config.try_build_institutional_session_manager() {
                Ok(Some(manager)) => (Some(Arc::new(manager)), serde_json::Value::Null),
                Ok(None) => (
                    None,
                    unavailable_session_status(
                        &config,
                        "not_configured",
                        "Institutional access is not configured.",
                    ),
                ),
                Err(error) => {
                    let state = match error {
                        institutional::SessionError::Store(
                            institutional::StoreError::InsecurePermissions,
                        ) => "insecure_permissions",
                        institutional::SessionError::Store(
                            institutional::StoreError::UnsafePath,
                        ) => "unsafe_storage_path",
                        _ => "unavailable",
                    };
                    let note = format!("Institutional session lifecycle unavailable: {error}");
                    tracing::warn!("{}", note);
                    (None, unavailable_session_status(&config, state, &note))
                }
            };
        let institutional_retriever = config.build_institutional_retriever().map(Arc::new);

        tracing::info!(
            "Initialized {} paper sources, data_dir={}",
            sources.len(),
            config.data_dir.display()
        );

        let local_index = LocalIndex::create_or_open(&config.data_dir).await?;

        Ok(Self {
            tool_router: Self::tool_router(),
            config: Arc::new(config),
            sources: Arc::new(sources),
            local_index: Arc::new(Mutex::new(local_index)),
            unpaywall,
            institutional_access,
            institutional_sessions,
            institutional_retriever,
            institutional_session_fallback_status: Arc::new(institutional_session_fallback_status),
        })
    }

    #[tool(description = "List available paper sources and their status")]
    async fn list_sources(&self) -> Result<CallToolResult, McpError> {
        let statuses = self.config.source_status();
        let json = serde_json::to_string_pretty(&statuses)
            .map_err(|e| McpError::internal_error(format!("Serialization error: {}", e), None))?;
        Ok(CallToolResult::success(vec![Content::text(json)]))
    }

    #[tool(
        description = "Search papers across enabled sources with deduplication, date-aware filtering, and sorting. Supports sort=relevance|date_desc|date_asc|hybrid plus date_from/date_to in YYYY-MM-DD format."
    )]
    async fn search_papers(
        &self,
        Parameters(params): Parameters<SearchPapersParams>,
    ) -> Result<CallToolResult, McpError> {
        let max = params.max_results.unwrap_or(10).min(100);
        let sort = match params.sort.as_deref().unwrap_or("relevance") {
            "relevance" => SearchSort::Relevance,
            "date_desc" => SearchSort::DateDesc,
            "date_asc" => SearchSort::DateAsc,
            "hybrid" => SearchSort::Hybrid,
            other => {
                return Err(McpError::invalid_params(
                    format!(
                    "Invalid sort '{}'. Expected one of: relevance, date_desc, date_asc, hybrid",
                    other
                ),
                    None,
                ))
            }
        };
        let date_from = params
            .date_from
            .as_deref()
            .map(|value| chrono::NaiveDate::parse_from_str(value, "%Y-%m-%d"))
            .transpose()
            .map_err(|e| {
                McpError::invalid_params(
                    format!(
                        "Invalid date_from '{}': {}",
                        params.date_from.unwrap_or_default(),
                        e
                    ),
                    None,
                )
            })?;
        let date_to = params
            .date_to
            .as_deref()
            .map(|value| chrono::NaiveDate::parse_from_str(value, "%Y-%m-%d"))
            .transpose()
            .map_err(|e| {
                McpError::invalid_params(
                    format!(
                        "Invalid date_to '{}': {}",
                        params.date_to.unwrap_or_default(),
                        e
                    ),
                    None,
                )
            })?;

        if let (Some(from), Some(to)) = (date_from, date_to) {
            if from > to {
                return Err(McpError::invalid_params(
                    "date_from must be on or before date_to".to_string(),
                    None,
                ));
            }
        }

        let options = SearchOptions {
            sort,
            date_from,
            date_to,
        };
        let results = search::federated_search(
            &self.sources,
            &params.query,
            max,
            params.sources.as_deref(),
            &options,
        )
        .await;

        let json = serde_json::to_string_pretty(&results)
            .map_err(|e| McpError::internal_error(format!("{}", e), None))?;
        Ok(CallToolResult::success(vec![Content::text(json)]))
    }

    #[tool(
        description = "Get full metadata for a paper by ID (arxiv:ID, doi:ID, inspire:ID, s2:ID, etc.)"
    )]
    async fn get_paper(
        &self,
        Parameters(params): Parameters<GetPaperParams>,
    ) -> Result<CallToolResult, McpError> {
        let id = &params.id;
        let target_source = params
            .source
            .as_deref()
            .or_else(|| source_from_prefixed_id(id));

        // Check local index first
        {
            let idx = self.local_index.lock().await;
            if let Ok(Some(paper)) = idx.get_paper(id).await {
                let json = serde_json::to_string_pretty(&paper)
                    .map_err(|e| McpError::internal_error(format!("{}", e), None))?;
                return Ok(CallToolResult::success(vec![Content::text(json)]));
            }
        }

        for src in self.sources.iter() {
            if let Some(target) = target_source {
                if !src.name().eq_ignore_ascii_case(target) {
                    continue;
                }
            }
            match src.get_paper(id).await {
                Ok(Some(paper)) => {
                    let json = serde_json::to_string_pretty(&paper)
                        .map_err(|e| McpError::internal_error(format!("{}", e), None))?;
                    return Ok(CallToolResult::success(vec![Content::text(json)]));
                }
                Ok(None) => continue,
                Err(e) => {
                    tracing::warn!("Source {} failed for get_paper: {}", src.name(), e);
                    continue;
                }
            }
        }

        Ok(CallToolResult::success(vec![Content::text(format!(
            "Paper not found: {}",
            id
        ))]))
    }

    #[tool(description = "Get papers that cite a given paper")]
    async fn get_citations(
        &self,
        Parameters(params): Parameters<RelationParams>,
    ) -> Result<CallToolResult, McpError> {
        let results = self
            .query_relation(&params.id, params.source.as_deref(), |src, id| {
                Box::pin(src.get_citations(id))
            })
            .await;
        let json = serde_json::to_string_pretty(&results)
            .map_err(|e| McpError::internal_error(format!("{}", e), None))?;
        Ok(CallToolResult::success(vec![Content::text(json)]))
    }

    #[tool(description = "Get papers referenced by a given paper")]
    async fn get_references(
        &self,
        Parameters(params): Parameters<RelationParams>,
    ) -> Result<CallToolResult, McpError> {
        let results = self
            .query_relation(&params.id, params.source.as_deref(), |src, id| {
                Box::pin(src.get_references(id))
            })
            .await;
        let json = serde_json::to_string_pretty(&results)
            .map_err(|e| McpError::internal_error(format!("{}", e), None))?;
        Ok(CallToolResult::success(vec![Content::text(json)]))
    }

    #[tool(
        description = "Search locally indexed papers using keyword, vector, or hybrid search. Mode: 'hybrid' (default), 'keyword', 'vector'"
    )]
    async fn search_local(
        &self,
        Parameters(params): Parameters<SearchLocalParams>,
    ) -> Result<CallToolResult, McpError> {
        let limit = params.limit.unwrap_or(10).min(100) as usize;
        let idx = self.local_index.lock().await;

        let mode_str = params.mode.as_deref().unwrap_or("hybrid");
        let embedding = specter::mock_embedding(&params.query);

        let search_mode = match mode_str {
            "keyword" => index::hybrid::SearchMode::KeywordOnly {
                query: &params.query,
            },
            "vector" => index::hybrid::SearchMode::VectorOnly {
                embedding: &embedding,
            },
            _ => index::hybrid::SearchMode::Hybrid {
                query: &params.query,
                embedding: &embedding,
            },
        };

        let scored = idx
            .search(search_mode, limit)
            .await
            .map_err(|e| McpError::internal_error(format!("Search failed: {}", e), None))?;

        let papers = index::hybrid::resolve_results(&idx.vector, &scored)
            .await
            .map_err(|e| {
                McpError::internal_error(format!("Failed to resolve results: {}", e), None)
            })?;

        let json = serde_json::to_string_pretty(&papers)
            .map_err(|e| McpError::internal_error(format!("{}", e), None))?;
        Ok(CallToolResult::success(vec![Content::text(json)]))
    }

    #[tool(
        description = "Search for semantically similar papers in the local index using SPECTER2 embeddings"
    )]
    async fn search_similar(
        &self,
        Parameters(params): Parameters<SearchSimilarParams>,
    ) -> Result<CallToolResult, McpError> {
        let limit = params.limit.unwrap_or(10).min(100) as usize;
        let idx = self.local_index.lock().await;
        let embedding = specter::mock_embedding(&params.query);

        let results = idx
            .vector
            .search_similar(&embedding, limit)
            .await
            .map_err(|e| McpError::internal_error(format!("Vector search failed: {}", e), None))?;

        let mut papers = Vec::new();
        for (id, _distance) in &results {
            if let Ok(Some(paper)) = idx.vector.get_paper(id).await {
                papers.push(paper);
            }
        }

        let json = serde_json::to_string_pretty(&papers)
            .map_err(|e| McpError::internal_error(format!("{}", e), None))?;
        Ok(CallToolResult::success(vec![Content::text(json)]))
    }

    #[tool(
        description = "Fetch a paper from an API source and add it to the local index with embedding"
    )]
    async fn index_paper(
        &self,
        Parameters(params): Parameters<IndexPaperParams>,
    ) -> Result<CallToolResult, McpError> {
        let mut paper = None;
        for src in self.sources.iter() {
            if let Some(ref target) = params.source {
                if !src.name().eq_ignore_ascii_case(target) {
                    continue;
                }
            }
            match src.get_paper(&params.id).await {
                Ok(Some(p)) => {
                    paper = Some(p);
                    break;
                }
                Ok(None) => continue,
                Err(e) => {
                    tracing::warn!("Source {} failed: {}", src.name(), e);
                    continue;
                }
            }
        }

        let paper = paper.ok_or_else(|| {
            McpError::invalid_params(format!("Paper not found: {}", params.id), None)
        })?;

        let mut idx = self.local_index.lock().await;
        idx.index_paper_mock(&paper)
            .await
            .map_err(|e| McpError::internal_error(format!("Indexing failed: {}", e), None))?;

        Ok(CallToolResult::success(vec![Content::text(format!(
            "Indexed: {} - {}",
            paper.id, paper.title
        ))]))
    }

    #[tool(description = "Search for papers and bulk-index all results into the local index")]
    async fn index_from_query(
        &self,
        Parameters(params): Parameters<IndexFromQueryParams>,
    ) -> Result<CallToolResult, McpError> {
        let max = params.max_results.unwrap_or(10).min(50);
        let source_filter = params.source.map(|s| vec![s]);

        let papers = search::federated_search(
            &self.sources,
            &params.query,
            max,
            source_filter.as_deref(),
            &SearchOptions::default(),
        )
        .await;

        let mut idx = self.local_index.lock().await;
        let mut indexed = 0;
        for paper in &papers {
            if idx.index_paper_mock(paper).await.is_ok() {
                indexed += 1;
            }
        }

        Ok(CallToolResult::success(vec![Content::text(format!(
            "Indexed {} of {} papers from query: {}",
            indexed,
            papers.len(),
            params.query
        ))]))
    }

    #[tool(description = "Find open-access PDF URL for a paper via Unpaywall (requires DOI)")]
    async fn get_pdf_url(
        &self,
        Parameters(params): Parameters<GetPdfUrlParams>,
    ) -> Result<CallToolResult, McpError> {
        let client = self.unpaywall.as_ref().ok_or_else(|| {
            McpError::invalid_params(
                "Unpaywall not configured. Set UNPAYWALL_EMAIL environment variable.".to_string(),
                None,
            )
        })?;

        match client.get_pdf_url(&params.doi).await {
            Ok(Some(url)) => Ok(CallToolResult::success(vec![Content::text(format!(
                "PDF URL: {}",
                url
            ))])),
            Ok(None) => Ok(CallToolResult::success(vec![Content::text(format!(
                "No open-access PDF found for DOI: {}",
                params.doi
            ))])),
            Err(e) => Err(McpError::internal_error(
                format!("Unpaywall error: {}", e),
                None,
            )),
        }
    }

    #[tool(
        description = "Create an institution-routed browser URL for a DOI or publisher URL. Authentication and MFA remain in the user's browser; this server never accepts credentials."
    )]
    async fn get_institutional_access_url(
        &self,
        Parameters(params): Parameters<GetInstitutionalAccessUrlParams>,
    ) -> Result<CallToolResult, McpError> {
        let access = self.institutional_access.as_ref().ok_or_else(|| {
            McpError::invalid_params(
                "Institutional access not configured. Set PAPER_SEARCH_LIBRARY_PROXY_URL and optionally PAPER_SEARCH_INSTITUTION_NAME.".to_string(),
                None,
            )
        })?;

        let target_url = match (params.doi, params.url) {
            (Some(doi), None) => {
                let doi = doi
                    .trim()
                    .strip_prefix("doi:")
                    .unwrap_or(doi.trim())
                    .trim_start_matches("https://doi.org/");
                if doi.is_empty() || !doi.contains('/') {
                    return Err(McpError::invalid_params(
                        "doi must be a non-empty DOI such as 10.1103/PhysRevA.1.1".to_string(),
                        None,
                    ));
                }
                format!("https://doi.org/{}", doi)
            }
            (None, Some(url)) => url,
            (Some(_), Some(_)) => {
                return Err(McpError::invalid_params(
                    "Supply either doi or url, not both".to_string(),
                    None,
                ))
            }
            (None, None) => {
                return Err(McpError::invalid_params(
                    "Supply either doi or url".to_string(),
                    None,
                ))
            }
        };

        let link = access.access_link(&target_url).map_err(|err| {
            McpError::invalid_params(
                format!("Cannot create institutional access URL: {}", err),
                None,
            )
        })?;
        let json = serde_json::to_string_pretty(&link).map_err(|err| {
            McpError::internal_error(format!("Serialization error: {}", err), None)
        })?;
        Ok(CallToolResult::success(vec![Content::text(json)]))
    }

    #[tool(
        description = "Prepare a user-mediated institutional login. Returns a browser URL and a private staging path for an out-of-band Netscape cookie export; never supply cookie values to MCP."
    )]
    async fn start_institutional_session(
        &self,
        Parameters(params): Parameters<StartInstitutionalSessionParams>,
    ) -> Result<CallToolResult, McpError> {
        let access = self.institutional_access.as_ref().ok_or_else(|| {
            McpError::invalid_params("Institutional access is not configured".to_string(), None)
        })?;
        let sessions = self.institutional_sessions.as_ref().ok_or_else(|| {
            McpError::invalid_params(
                "Institutional session storage is unavailable. PAPER_SEARCH_DATA_DIR must be outside the repository with a usable OS keyring.".to_string(),
                None,
            )
        })?;
        let target = institutional_target_url(params.doi, params.url)?;
        let link = access.access_link(&target).map_err(|error| {
            McpError::invalid_params(format!("Cannot prepare institutional URL: {error}"), None)
        })?;
        let authentication_url = reqwest::Url::parse(&link.access_url).map_err(|_| {
            McpError::internal_error("Prepared institutional URL is invalid".to_string(), None)
        })?;
        let sessions = Arc::clone(sessions);
        let start = tokio::task::spawn_blocking(move || sessions.start(&authentication_url))
            .await
            .map_err(|_| {
                McpError::internal_error(
                    "Institutional session preparation failed".to_string(),
                    None,
                )
            })?
            .map_err(|error| {
                McpError::invalid_params(
                    format!("Institutional session unavailable: {error}"),
                    None,
                )
            })?;
        json_result(&start)
    }

    #[tool(
        description = "Complete a prepared institutional session after the user has logged in through a real browser and exported scoped cookies to the prepared private file. Accepts only the non-secret request ID."
    )]
    async fn complete_institutional_session(
        &self,
        Parameters(params): Parameters<CompleteInstitutionalSessionParams>,
    ) -> Result<CallToolResult, McpError> {
        let sessions = self.institutional_sessions.as_ref().ok_or_else(|| {
            McpError::invalid_params(
                "Institutional session storage is unavailable".to_string(),
                None,
            )
        })?;
        let sessions = Arc::clone(sessions);
        let status = tokio::task::spawn_blocking(move || sessions.complete(&params.request_id))
            .await
            .map_err(|_| {
                McpError::internal_error(
                    "Institutional session completion failed".to_string(),
                    None,
                )
            })?
            .map_err(|error| {
                McpError::invalid_params(
                    format!("Institutional session not completed: {error}"),
                    None,
                )
            })?;
        json_result(&status)
    }

    #[tool(
        description = "Report institutional-session health, scope, expiry, and protection status without returning cookie names or values."
    )]
    async fn institutional_session_status(&self) -> Result<CallToolResult, McpError> {
        let Some(sessions) = self.institutional_sessions.as_ref() else {
            return json_result(self.institutional_session_fallback_status.as_ref());
        };
        let sessions = Arc::clone(sessions);
        let status = tokio::task::spawn_blocking(move || sessions.status())
            .await
            .map_err(|_| {
                McpError::internal_error("Institutional session status failed".to_string(), None)
            })?
            .map_err(|error| {
                McpError::internal_error(
                    format!("Institutional session status failed: {error}"),
                    None,
                )
            })?;
        json_result(&status)
    }

    #[tool(
        description = "Retrieve one explicitly requested, licensed PDF through a ready institutional session. Open access must be checked first. HTTPS:443 only; strict SSRF, redirect, size, PDF, path, and rate controls apply."
    )]
    async fn retrieve_institutional_pdf(
        &self,
        Parameters(params): Parameters<RetrieveInstitutionalPdfParams>,
    ) -> Result<CallToolResult, McpError> {
        if !params.confirmed_open_access_unavailable || !params.confirmed_authorized_access {
            return Err(McpError::invalid_params(
                "Both open-access-unavailable and authorized-access confirmations must be true"
                    .to_string(),
                None,
            ));
        }
        if let (Some(doi), Some(unpaywall)) = (params.doi.as_deref(), self.unpaywall.as_ref()) {
            if let Ok(Some(open_url)) = unpaywall.get_pdf_url(doi).await {
                return Ok(CallToolResult::success(vec![Content::text(format!(
                    "Open-access PDF available; institutional fallback not used. PDF URL: {}",
                    open_url
                ))]));
            }
        }
        let access = self.institutional_access.as_ref().ok_or_else(|| {
            McpError::invalid_params("Institutional access is not configured".to_string(), None)
        })?;
        let sessions = self.institutional_sessions.as_ref().ok_or_else(|| {
            McpError::invalid_params(
                "Institutional session storage is unavailable".to_string(),
                None,
            )
        })?;
        let retriever = self.institutional_retriever.as_ref().ok_or_else(|| {
            McpError::invalid_params("Institutional retrieval is unavailable".to_string(), None)
        })?;
        let source_url = reqwest::Url::parse(&params.url).map_err(|_| {
            McpError::invalid_params("url must be a valid HTTPS URL".to_string(), None)
        })?;
        let link = access.access_link(source_url.as_str()).map_err(|error| {
            McpError::invalid_params(format!("Institutional target rejected: {error}"), None)
        })?;
        let institutional_url = reqwest::Url::parse(&link.access_url).map_err(|_| {
            McpError::internal_error("Prepared institutional URL is invalid".to_string(), None)
        })?;
        let sessions = Arc::clone(sessions);
        let jar = tokio::task::spawn_blocking(move || sessions.load_jar())
            .await
            .map_err(|_| {
                McpError::internal_error("Institutional session load failed".to_string(), None)
            })?
            .map_err(|error| {
                McpError::invalid_params(
                    format!("Institutional session is not ready: {error}"),
                    None,
                )
            })?;
        let result = retriever
            .retrieve(
                &jar,
                institutional_url,
                &source_url,
                params.doi.as_deref(),
                params.filename.as_deref(),
            )
            .await
            .map_err(|error| {
                McpError::invalid_params(format!("Institutional retrieval refused: {error}"), None)
            })?;
        json_result(&result)
    }

    #[tool(
        description = "Delete the locally stored institutional session, pending plaintext exports, and its OS-keyring key. This does not revoke the institution's server-side session."
    )]
    async fn clear_institutional_session(&self) -> Result<CallToolResult, McpError> {
        let sessions = self.institutional_sessions.as_ref().ok_or_else(|| {
            McpError::invalid_params(
                "Institutional session storage is unavailable".to_string(),
                None,
            )
        })?;
        let sessions = Arc::clone(sessions);
        let status = tokio::task::spawn_blocking(move || sessions.clear())
            .await
            .map_err(|_| {
                McpError::internal_error("Institutional session deletion failed".to_string(), None)
            })?
            .map_err(|error| {
                McpError::internal_error(
                    format!("Institutional session deletion failed: {error}"),
                    None,
                )
            })?;
        json_result(&status)
    }
}

impl PaperSearchServer {
    /// Helper: query citations or references from the best matching source.
    async fn query_relation<F>(
        &self,
        id: &str,
        source: Option<&str>,
        f: F,
    ) -> Vec<apis::PaperResult>
    where
        F: for<'a> Fn(
            &'a Arc<dyn PaperSource>,
            &'a str,
        ) -> std::pin::Pin<
            Box<
                dyn std::future::Future<Output = Result<Vec<apis::PaperResult>, apis::SourceError>>
                    + Send
                    + 'a,
            >,
        >,
    {
        for src in self.sources.iter() {
            if let Some(target) = source {
                if !src.name().eq_ignore_ascii_case(target) {
                    continue;
                }
            }
            match f(src, id).await {
                Ok(results) if !results.is_empty() => return results,
                Ok(_) => continue,
                Err(e) => {
                    tracing::warn!("Source {} failed: {}", src.name(), e);
                    continue;
                }
            }
        }
        Vec::new()
    }
}

#[tool_handler]
impl ServerHandler for PaperSearchServer {
    fn get_info(&self) -> ServerInfo {
        ServerInfo {
            protocol_version: ProtocolVersion::V_2024_11_05,
            capabilities: ServerCapabilities::builder().enable_tools().build(),
            server_info: Implementation::from_build_env(),
            instructions: Some(
                "Search, index, and retrieve scientific papers across open journals. \
                 Supports arXiv, INSPIRE-HEP, Semantic Scholar, OpenAlex, CrossRef, \
                 NASA ADS, Europe PMC, DOAJ, and opt-in viXra. Local hybrid search with \
                 BM25 + SPECTER2 embeddings. Can create browser-mediated institutional \
                 access URLs when a library proxy is configured; credentials never pass \
                 through the MCP server."
                    .into(),
            ),
        }
    }
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    tracing_subscriber::fmt()
        .with_env_filter(EnvFilter::from_default_env())
        .with_writer(std::io::stderr)
        .with_ansi(false)
        .init();

    tracing::info!("Starting paper-search MCP server");

    let server = PaperSearchServer::create().await?;
    let service = server.serve(stdio()).await?;
    service.waiting().await?;

    Ok(())
}

fn source_from_prefixed_id(id: &str) -> Option<&'static str> {
    if id.starts_with("arxiv:") {
        Some("arxiv")
    } else if id.starts_with("inspire:") {
        Some("inspire")
    } else if id.starts_with("s2:") {
        Some("semantic_scholar")
    } else if id.starts_with("ads:") {
        Some("ads")
    } else if id.starts_with("doi:") {
        Some("crossref")
    } else if id.starts_with("pmid:") {
        Some("europepmc")
    } else if id.starts_with("doaj:") {
        Some("doaj")
    } else if id.starts_with("vixra:") {
        Some("vixra")
    } else if id.starts_with("openalex:") {
        Some("openalex")
    } else {
        None
    }
}

fn institutional_target_url(doi: Option<String>, url: Option<String>) -> Result<String, McpError> {
    match (doi, url) {
        (Some(doi), None) => {
            let doi = doi
                .trim()
                .strip_prefix("doi:")
                .unwrap_or(doi.trim())
                .trim_start_matches("https://doi.org/");
            if doi.is_empty() || !doi.contains('/') {
                return Err(McpError::invalid_params(
                    "doi must be a non-empty DOI such as 10.1103/PhysRevA.1.1".to_string(),
                    None,
                ));
            }
            Ok(format!("https://doi.org/{doi}"))
        }
        (None, Some(url)) => Ok(url),
        (Some(_), Some(_)) => Err(McpError::invalid_params(
            "Supply either doi or url, not both".to_string(),
            None,
        )),
        (None, None) => Err(McpError::invalid_params(
            "Supply either doi or url".to_string(),
            None,
        )),
    }
}

fn json_result<T: serde::Serialize>(value: &T) -> Result<CallToolResult, McpError> {
    let json = serde_json::to_string_pretty(value)
        .map_err(|_| McpError::internal_error("Serialization failed".to_string(), None))?;
    Ok(CallToolResult::success(vec![Content::text(json)]))
}

fn unavailable_session_status(
    config: &Config,
    state: &str,
    operational_note: &str,
) -> serde_json::Value {
    serde_json::json!({
        "state": state,
        "institution": config.institution_name.as_deref().unwrap_or("Configured institution"),
        "protection": "not_checked",
        "expires_at": null,
        "domains": [],
        "cookie_count": 0,
        "pending_request_count": 0,
        "plaintext_export_present": false,
        "plaintext_export_oldest_age_seconds": null,
        "operational_note": operational_note,
    })
}

#[cfg(test)]
mod tests {
    use super::source_from_prefixed_id;

    #[test]
    fn prefixed_ids_route_to_existing_sources() {
        assert_eq!(source_from_prefixed_id("arxiv:2401.00001"), Some("arxiv"));
        assert_eq!(
            source_from_prefixed_id("doi:10.1234/example"),
            Some("crossref")
        );
        assert_eq!(source_from_prefixed_id("pmid:12345"), Some("europepmc"));
        assert_eq!(source_from_prefixed_id("openalex:W123"), Some("openalex"));
    }

    #[test]
    fn prefixed_vixra_id_still_routes_to_vixra() {
        assert_eq!(source_from_prefixed_id("vixra:2603.0090"), Some("vixra"));
    }
}
