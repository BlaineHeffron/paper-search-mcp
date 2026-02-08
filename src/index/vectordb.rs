use std::path::Path;
use std::sync::Arc;
use anyhow::{Context, Result};
use arrow_array::{
    types::Float32Type, FixedSizeListArray, Int32Array, RecordBatch, RecordBatchIterator,
    StringArray,
};
use arrow_array::Array;
use arrow_schema::{DataType, Field, Schema};
use futures::stream::StreamExt;
use lancedb::query::{ExecutableQuery, QueryBase};

use crate::apis::PaperResult;
use crate::embed::specter::EMBEDDING_DIMENSION;

const TABLE_NAME: &str = "papers";

/// LanceDB-based vector store for papers with SPECTER2 embeddings.
pub struct VectorStore {
    db: lancedb::Connection,
    schema: Arc<Schema>,
}

fn make_schema() -> Arc<Schema> {
    Arc::new(Schema::new(vec![
        Field::new("id", DataType::Utf8, false),
        Field::new("title", DataType::Utf8, false),
        Field::new("abstract_text", DataType::Utf8, true),
        Field::new("authors_json", DataType::Utf8, true),
        Field::new("year", DataType::Int32, true),
        Field::new("source", DataType::Utf8, true),
        Field::new("doi", DataType::Utf8, true),
        Field::new("arxiv_id", DataType::Utf8, true),
        Field::new("url", DataType::Utf8, true),
        Field::new("pdf_url", DataType::Utf8, true),
        Field::new("citation_count", DataType::Int32, true),
        Field::new(
            "embedding",
            DataType::FixedSizeList(
                Arc::new(Field::new("item", DataType::Float32, true)),
                EMBEDDING_DIMENSION as i32,
            ),
            true,
        ),
    ]))
}

impl VectorStore {
    /// Create or open a LanceDB database at the given path.
    pub async fn create_or_open(path: &Path) -> Result<Self> {
        std::fs::create_dir_all(path)
            .context("Failed to create LanceDB directory")?;

        let db = lancedb::connect(path.to_str().unwrap())
            .execute()
            .await
            .context("Failed to connect to LanceDB")?;

        let schema = make_schema();

        // Create table if it doesn't exist
        let tables = db.table_names().execute().await
            .context("Failed to list tables")?;
        if !tables.contains(&TABLE_NAME.to_string()) {
            db.create_empty_table(TABLE_NAME, schema.clone())
                .execute()
                .await
                .context("Failed to create papers table")?;
        }

        Ok(Self { db, schema })
    }

    /// Get a handle to the papers table.
    async fn table(&self) -> Result<lancedb::Table> {
        self.db
            .open_table(TABLE_NAME)
            .execute()
            .await
            .context("Failed to open papers table")
    }

    /// Add a paper with its embedding to the vector store.
    pub async fn add_paper(&self, paper: &PaperResult, embedding: &[f32]) -> Result<()> {
        let table = self.table().await?;

        let authors_json = serde_json::to_string(&paper.authors).unwrap_or_default();

        let batch = RecordBatch::try_new(
            self.schema.clone(),
            vec![
                Arc::new(StringArray::from(vec![paper.id.as_str()])),
                Arc::new(StringArray::from(vec![paper.title.as_str()])),
                Arc::new(StringArray::from(vec![paper.abstract_text.as_deref()])),
                Arc::new(StringArray::from(vec![Some(authors_json.as_str())])),
                Arc::new(Int32Array::from(vec![paper.year.map(|y| y as i32)])),
                Arc::new(StringArray::from(vec![Some(paper.source.as_str())])),
                Arc::new(StringArray::from(vec![paper.doi.as_deref()])),
                Arc::new(StringArray::from(vec![paper.arxiv_id.as_deref()])),
                Arc::new(StringArray::from(vec![Some(paper.url.as_str())])),
                Arc::new(StringArray::from(vec![paper.pdf_url.as_deref()])),
                Arc::new(Int32Array::from(vec![paper.citation_count.map(|c| c as i32)])),
                Arc::new(
                    FixedSizeListArray::from_iter_primitive::<Float32Type, _, _>(
                        std::iter::once(Some(embedding.iter().map(|&v| Some(v)))),
                        EMBEDDING_DIMENSION as i32,
                    ),
                ),
            ],
        )
        .context("Failed to create RecordBatch")?;

        let batches = RecordBatchIterator::new(vec![Ok(batch)], self.schema.clone());
        table
            .add(Box::new(batches))
            .execute()
            .await
            .context("Failed to add paper to vector store")?;

        Ok(())
    }

    /// Search for similar papers by embedding vector. Returns (id, distance) pairs.
    pub async fn search_similar(
        &self,
        embedding: &[f32],
        limit: usize,
    ) -> Result<Vec<(String, f32)>> {
        let table = self.table().await?;

        let mut results_stream = table
            .query()
            .nearest_to(embedding)
            .context("Failed to set up vector search")?
            .limit(limit)
            .execute()
            .await
            .context("Failed to execute vector search")?;

        let mut results = Vec::new();
        while let Some(batch) = results_stream.next().await {
            let batch = batch.context("Failed to read search result batch")?;
            let id_col = batch
                .column_by_name("id")
                .and_then(|c| c.as_any().downcast_ref::<StringArray>())
                .context("Missing id column")?;
            let dist_col = batch
                .column_by_name("_distance")
                .and_then(|c| c.as_any().downcast_ref::<arrow_array::Float32Array>());

            for i in 0..batch.num_rows() {
                let id = id_col.value(i).to_string();
                let distance = dist_col.map(|d| d.value(i)).unwrap_or(0.0);
                results.push((id, distance));
            }
        }
        Ok(results)
    }

    /// Get a paper by its ID.
    pub async fn get_paper(&self, id: &str) -> Result<Option<PaperResult>> {
        let table = self.table().await?;

        let filter = format!("id = '{}'", id.replace('\'', "''"));
        let mut results_stream = table
            .query()
            .only_if(filter)
            .limit(1)
            .execute()
            .await
            .context("Failed to query by ID")?;

        if let Some(batch) = results_stream.next().await {
            let batch = batch.context("Failed to read query result")?;
            if batch.num_rows() == 0 {
                return Ok(None);
            }
            Ok(Some(batch_row_to_paper(&batch, 0)?))
        } else {
            Ok(None)
        }
    }

    /// Delete a paper by ID.
    pub async fn delete(&self, id: &str) -> Result<()> {
        let table = self.table().await?;
        let filter = format!("id = '{}'", id.replace('\'', "''"));
        table.delete(&filter).await.context("Failed to delete")?;
        Ok(())
    }

    /// Get the total number of papers in the store.
    pub async fn count(&self) -> Result<usize> {
        let table = self.table().await?;
        table
            .count_rows(None)
            .await
            .context("Failed to count rows")
    }
}

/// Extract a PaperResult from a RecordBatch at the given row index.
fn batch_row_to_paper(batch: &RecordBatch, row: usize) -> Result<PaperResult> {
    let get_str = |name: &str| -> Option<String> {
        batch
            .column_by_name(name)?
            .as_any()
            .downcast_ref::<StringArray>()
            .and_then(|a| {
                if a.is_null(row) {
                    None
                } else {
                    Some(a.value(row).to_string())
                }
            })
    };
    let get_i32 = |name: &str| -> Option<i32> {
        batch
            .column_by_name(name)?
            .as_any()
            .downcast_ref::<Int32Array>()
            .and_then(|a| if a.is_null(row) { None } else { Some(a.value(row)) })
    };

    let authors: Vec<String> = get_str("authors_json")
        .and_then(|s| serde_json::from_str(&s).ok())
        .unwrap_or_default();

    Ok(PaperResult {
        id: get_str("id").unwrap_or_default(),
        title: get_str("title").unwrap_or_default(),
        authors,
        abstract_text: get_str("abstract_text"),
        year: get_i32("year").map(|y| y as u32),
        source: get_str("source").unwrap_or_default(),
        doi: get_str("doi"),
        arxiv_id: get_str("arxiv_id"),
        url: get_str("url").unwrap_or_default(),
        pdf_url: get_str("pdf_url"),
        citation_count: get_i32("citation_count").map(|c| c as u32),
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::embed::specter::mock_embedding;
    use tempfile::TempDir;

    fn sample_paper(id: &str, title: &str) -> PaperResult {
        PaperResult {
            id: id.to_string(),
            title: title.to_string(),
            authors: vec!["Test Author".to_string()],
            abstract_text: Some("Test abstract".to_string()),
            year: Some(2024),
            source: "test".to_string(),
            doi: None,
            arxiv_id: None,
            url: "https://example.com".to_string(),
            pdf_url: None,
            citation_count: Some(10),
        }
    }

    #[tokio::test]
    async fn test_vectordb_roundtrip() {
        let tmp = TempDir::new().unwrap();
        let store = VectorStore::create_or_open(tmp.path()).await.unwrap();

        let paper1 = sample_paper("test:001", "Holographic Entanglement in AdS/CFT");
        let emb1 = mock_embedding(&paper1.title);
        store.add_paper(&paper1, &emb1).await.unwrap();

        let paper2 = sample_paper("test:002", "Quantum Error Correction Codes");
        let emb2 = mock_embedding(&paper2.title);
        store.add_paper(&paper2, &emb2).await.unwrap();

        assert_eq!(store.count().await.unwrap(), 2);

        // Search similar to paper1
        let results = store.search_similar(&emb1, 5).await.unwrap();
        assert!(!results.is_empty());
        assert_eq!(results[0].0, "test:001"); // Most similar to itself

        // Get by ID
        let got = store.get_paper("test:001").await.unwrap();
        assert!(got.is_some());
        let got = got.unwrap();
        assert_eq!(got.title, "Holographic Entanglement in AdS/CFT");
        assert_eq!(got.year, Some(2024));

        // Delete
        store.delete("test:001").await.unwrap();
        assert_eq!(store.count().await.unwrap(), 1);
        assert!(store.get_paper("test:001").await.unwrap().is_none());
    }
}
