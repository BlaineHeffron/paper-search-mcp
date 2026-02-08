use std::sync::Arc;
use rmcp::{
    handler::server::tool::ToolRouter, handler::server::wrapper::Parameters,
    model::*, tool, tool_handler, tool_router,
    transport::stdio, ErrorData as McpError, ServerHandler, ServiceExt,
};
use schemars::JsonSchema;
use serde::Deserialize;
use tokio::sync::Mutex;
use tracing_subscriber::EnvFilter;

mod apis;
mod config;
mod embed;
mod index;
mod search;

use apis::PaperSource;
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

// ── Server ──────────────────────────────────────────────────────────────────

#[derive(Clone)]
pub struct PaperSearchServer {
    tool_router: ToolRouter<Self>,
    config: Arc<Config>,
    sources: Arc<Vec<Arc<dyn PaperSource>>>,
    local_index: Arc<Mutex<LocalIndex>>,
    unpaywall: Option<Arc<apis::unpaywall::UnpaywallClient>>,
}

#[tool_router]
impl PaperSearchServer {
    pub async fn create() -> anyhow::Result<Self> {
        let config = Config::from_env();
        let sources = config.build_sources();
        let unpaywall = config.build_unpaywall().map(Arc::new);

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
        })
    }

    #[tool(description = "List available paper sources and their status")]
    async fn list_sources(&self) -> Result<CallToolResult, McpError> {
        let statuses = self.config.source_status();
        let json = serde_json::to_string_pretty(&statuses)
            .map_err(|e| McpError::internal_error(format!("Serialization error: {}", e), None))?;
        Ok(CallToolResult::success(vec![Content::text(json)]))
    }

    #[tool(description = "Search papers across all enabled sources. Returns deduplicated, ranked results.")]
    async fn search_papers(
        &self,
        Parameters(params): Parameters<SearchPapersParams>,
    ) -> Result<CallToolResult, McpError> {
        let max = params.max_results.unwrap_or(10).min(100);
        let results = search::federated_search(
            &self.sources,
            &params.query,
            max,
            params.sources.as_deref(),
        )
        .await;

        let json = serde_json::to_string_pretty(&results)
            .map_err(|e| McpError::internal_error(format!("{}", e), None))?;
        Ok(CallToolResult::success(vec![Content::text(json)]))
    }

    #[tool(description = "Get full metadata for a paper by ID (arxiv:ID, doi:ID, inspire:ID, s2:ID, etc.)")]
    async fn get_paper(
        &self,
        Parameters(params): Parameters<GetPaperParams>,
    ) -> Result<CallToolResult, McpError> {
        let id = &params.id;
        let target_source = params.source.as_deref().or_else(|| {
            if id.starts_with("arxiv:") { Some("arxiv") }
            else if id.starts_with("inspire:") { Some("inspire") }
            else if id.starts_with("s2:") { Some("semantic_scholar") }
            else if id.starts_with("ads:") { Some("ads") }
            else if id.starts_with("doi:") { Some("crossref") }
            else if id.starts_with("pmid:") { Some("europepmc") }
            else if id.starts_with("doaj:") { Some("doaj") }
            else if id.starts_with("vixra:") { Some("vixra") }
            else if id.starts_with("openalex:") { Some("openalex") }
            else { None }
        });

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

        Ok(CallToolResult::success(vec![Content::text(
            format!("Paper not found: {}", id),
        )]))
    }

    #[tool(description = "Get papers that cite a given paper")]
    async fn get_citations(
        &self,
        Parameters(params): Parameters<RelationParams>,
    ) -> Result<CallToolResult, McpError> {
        let results = self.query_relation(&params.id, params.source.as_deref(), |src, id| {
            Box::pin(src.get_citations(id))
        }).await;
        let json = serde_json::to_string_pretty(&results)
            .map_err(|e| McpError::internal_error(format!("{}", e), None))?;
        Ok(CallToolResult::success(vec![Content::text(json)]))
    }

    #[tool(description = "Get papers referenced by a given paper")]
    async fn get_references(
        &self,
        Parameters(params): Parameters<RelationParams>,
    ) -> Result<CallToolResult, McpError> {
        let results = self.query_relation(&params.id, params.source.as_deref(), |src, id| {
            Box::pin(src.get_references(id))
        }).await;
        let json = serde_json::to_string_pretty(&results)
            .map_err(|e| McpError::internal_error(format!("{}", e), None))?;
        Ok(CallToolResult::success(vec![Content::text(json)]))
    }

    #[tool(description = "Search locally indexed papers using keyword, vector, or hybrid search. Mode: 'hybrid' (default), 'keyword', 'vector'")]
    async fn search_local(
        &self,
        Parameters(params): Parameters<SearchLocalParams>,
    ) -> Result<CallToolResult, McpError> {
        let limit = params.limit.unwrap_or(10).min(100) as usize;
        let idx = self.local_index.lock().await;

        let mode_str = params.mode.as_deref().unwrap_or("hybrid");
        let embedding = specter::mock_embedding(&params.query);

        let search_mode = match mode_str {
            "keyword" => index::hybrid::SearchMode::KeywordOnly { query: &params.query },
            "vector" => index::hybrid::SearchMode::VectorOnly { embedding: &embedding },
            _ => index::hybrid::SearchMode::Hybrid { query: &params.query, embedding: &embedding },
        };

        let scored = idx.search(search_mode, limit).await
            .map_err(|e| McpError::internal_error(format!("Search failed: {}", e), None))?;

        let papers = index::hybrid::resolve_results(&idx.vector, &scored).await
            .map_err(|e| McpError::internal_error(format!("Failed to resolve results: {}", e), None))?;

        let json = serde_json::to_string_pretty(&papers)
            .map_err(|e| McpError::internal_error(format!("{}", e), None))?;
        Ok(CallToolResult::success(vec![Content::text(json)]))
    }

    #[tool(description = "Search for semantically similar papers in the local index using SPECTER2 embeddings")]
    async fn search_similar(
        &self,
        Parameters(params): Parameters<SearchSimilarParams>,
    ) -> Result<CallToolResult, McpError> {
        let limit = params.limit.unwrap_or(10).min(100) as usize;
        let idx = self.local_index.lock().await;
        let embedding = specter::mock_embedding(&params.query);

        let results = idx.vector.search_similar(&embedding, limit).await
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

    #[tool(description = "Fetch a paper from an API source and add it to the local index with embedding")]
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
                Ok(Some(p)) => { paper = Some(p); break; }
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
        idx.index_paper_mock(&paper).await
            .map_err(|e| McpError::internal_error(format!("Indexing failed: {}", e), None))?;

        Ok(CallToolResult::success(vec![Content::text(
            format!("Indexed: {} - {}", paper.id, paper.title),
        )]))
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
        ).await;

        let mut idx = self.local_index.lock().await;
        let mut indexed = 0;
        for paper in &papers {
            if idx.index_paper_mock(paper).await.is_ok() {
                indexed += 1;
            }
        }

        Ok(CallToolResult::success(vec![Content::text(
            format!("Indexed {} of {} papers from query: {}", indexed, papers.len(), params.query),
        )]))
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
            Ok(Some(url)) => Ok(CallToolResult::success(vec![Content::text(
                format!("PDF URL: {}", url),
            )])),
            Ok(None) => Ok(CallToolResult::success(vec![Content::text(
                format!("No open-access PDF found for DOI: {}", params.doi),
            )])),
            Err(e) => Err(McpError::internal_error(format!("Unpaywall error: {}", e), None)),
        }
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
            Box<dyn std::future::Future<Output = Result<Vec<apis::PaperResult>, apis::SourceError>> + Send + 'a>,
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
                 NASA ADS, Europe PMC, DOAJ, and viXra. Local hybrid search with \
                 BM25 + SPECTER2 embeddings."
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
