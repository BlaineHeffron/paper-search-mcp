pub mod fulltext;
pub mod hybrid;
pub mod vectordb;

use std::path::{Path, PathBuf};
use anyhow::{Context, Result};

use crate::apis::PaperResult;
use crate::embed::specter::mock_embedding;

/// Unified local index owning both Tantivy (fulltext) and LanceDB (vector) components.
pub struct LocalIndex {
    pub fulltext: fulltext::FulltextIndex,
    pub vector: vectordb::VectorStore,
    data_dir: PathBuf,
}

impl LocalIndex {
    /// Create or open the local index at the given data directory.
    /// Creates subdirectories `tantivy/` and `lance/` under data_dir.
    pub async fn create_or_open(data_dir: &Path) -> Result<Self> {
        std::fs::create_dir_all(data_dir)
            .context("Failed to create data directory")?;

        let tantivy_path = data_dir.join("tantivy");
        let lance_path = data_dir.join("lance");

        let fulltext = fulltext::FulltextIndex::create_or_open(&tantivy_path)
            .context("Failed to open fulltext index")?;
        let vector = vectordb::VectorStore::create_or_open(&lance_path)
            .await
            .context("Failed to open vector store")?;

        Ok(Self {
            fulltext,
            vector,
            data_dir: data_dir.to_path_buf(),
        })
    }

    /// Index a paper with a precomputed embedding.
    pub async fn index_paper(&mut self, paper: &PaperResult, embedding: &[f32]) -> Result<()> {
        self.fulltext.add_paper(
            &paper.id,
            &paper.title,
            paper.abstract_text.as_deref(),
            &paper.authors,
            paper.year,
        )?;
        self.vector.add_paper(paper, embedding).await?;
        self.fulltext.commit()?;
        Ok(())
    }

    /// Index a paper using a mock embedding (for when no SPECTER2 model is available).
    pub async fn index_paper_mock(&mut self, paper: &PaperResult) -> Result<()> {
        let text = format!(
            "{} {}",
            paper.title,
            paper.abstract_text.as_deref().unwrap_or("")
        );
        let embedding = mock_embedding(&text);
        self.index_paper(paper, &embedding).await
    }

    /// Hybrid search over the local index.
    pub async fn search(
        &self,
        mode: hybrid::SearchMode<'_>,
        limit: usize,
    ) -> Result<Vec<hybrid::ScoredResult>> {
        hybrid::hybrid_search(&self.fulltext, &self.vector, mode, limit).await
    }

    /// Get total number of indexed papers.
    pub async fn count(&self) -> Result<usize> {
        self.vector.count().await
    }

    /// Delete a paper from both indices.
    pub async fn delete(&mut self, id: &str) -> Result<()> {
        self.fulltext.delete(id)?;
        self.fulltext.commit()?;
        self.vector.delete(id).await?;
        Ok(())
    }

    /// Get a paper by ID from the vector store.
    pub async fn get_paper(&self, id: &str) -> Result<Option<PaperResult>> {
        self.vector.get_paper(id).await
    }

    pub fn data_dir(&self) -> &Path {
        &self.data_dir
    }
}
