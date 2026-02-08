use std::path::Path;
use anyhow::{Context, Result};
use tantivy::{
    collector::TopDocs,
    doc,
    query::QueryParser,
    schema::*,
    Index, IndexReader, IndexWriter, ReloadPolicy, Term,
};

/// Tantivy-based BM25 full-text search index for papers.
pub struct FulltextIndex {
    index: Index,
    reader: IndexReader,
    writer: IndexWriter,
    // Field handles
    f_id: Field,
    f_title: Field,
    f_abstract: Field,
    f_authors: Field,
    f_year: Field,
}

impl FulltextIndex {
    /// Create or open a Tantivy index at the given directory.
    pub fn create_or_open(path: &Path) -> Result<Self> {
        std::fs::create_dir_all(path)
            .context("Failed to create tantivy index directory")?;

        let mut schema_builder = Schema::builder();
        let f_id = schema_builder.add_text_field("id", STRING | STORED);
        let f_title = schema_builder.add_text_field("title", TEXT | STORED);
        let f_abstract = schema_builder.add_text_field("abstract_text", TEXT);
        let f_authors = schema_builder.add_text_field("authors", TEXT);
        let f_year = schema_builder.add_i64_field(
            "year",
            NumericOptions::default().set_stored().set_indexed(),
        );
        let schema = schema_builder.build();

        let dir = tantivy::directory::MmapDirectory::open(path)
            .context("Failed to open MmapDirectory")?;
        let index = Index::open_or_create(dir, schema)
            .context("Failed to open or create tantivy index")?;

        let reader = index
            .reader_builder()
            .reload_policy(ReloadPolicy::OnCommitWithDelay)
            .try_into()
            .context("Failed to create index reader")?;

        let writer = index
            .writer(50_000_000)
            .context("Failed to create index writer")?;

        Ok(Self {
            index,
            reader,
            writer,
            f_id,
            f_title,
            f_abstract,
            f_authors,
            f_year,
        })
    }

    /// Add a paper to the index.
    pub fn add_paper(
        &mut self,
        id: &str,
        title: &str,
        abstract_text: Option<&str>,
        authors: &[String],
        year: Option<u32>,
    ) -> Result<()> {
        // Delete existing document with same ID first
        self.writer.delete_term(Term::from_field_text(self.f_id, id));

        let mut doc = doc!(
            self.f_id => id,
            self.f_title => title,
        );

        if let Some(abs) = abstract_text {
            doc.add_text(self.f_abstract, abs);
        }

        if !authors.is_empty() {
            doc.add_text(self.f_authors, &authors.join(", "));
        }

        if let Some(y) = year {
            doc.add_i64(self.f_year, y as i64);
        }

        self.writer.add_document(doc)
            .context("Failed to add document")?;
        Ok(())
    }

    /// Commit pending changes to make them searchable.
    pub fn commit(&mut self) -> Result<()> {
        self.writer.commit().context("Failed to commit")?;
        self.reader.reload().context("Failed to reload reader")?;
        Ok(())
    }

    /// Search the index. Returns (id, score) pairs ranked by BM25.
    pub fn search(&self, query: &str, limit: usize) -> Result<Vec<(String, f32)>> {
        let searcher = self.reader.searcher();
        let query_parser = QueryParser::for_index(
            &self.index,
            vec![self.f_title, self.f_abstract, self.f_authors],
        );
        let parsed = query_parser
            .parse_query(query)
            .context("Failed to parse query")?;

        let top_docs = searcher
            .search(&parsed, &TopDocs::with_limit(limit))
            .context("Search failed")?;

        let mut results = Vec::with_capacity(top_docs.len());
        for (score, doc_address) in top_docs {
            let doc: TantivyDocument = searcher
                .doc(doc_address)
                .context("Failed to retrieve document")?;
            if let Some(id) = doc.get_first(self.f_id).and_then(|v| v.as_str()) {
                results.push((id.to_string(), score));
            }
        }
        Ok(results)
    }

    /// Delete a paper by ID.
    pub fn delete(&mut self, id: &str) -> Result<()> {
        self.writer.delete_term(Term::from_field_text(self.f_id, id));
        Ok(())
    }

    /// Get the total number of indexed documents.
    pub fn count(&self) -> u64 {
        self.reader.searcher().num_docs()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::TempDir;

    #[test]
    fn test_fulltext_roundtrip() {
        let tmp = TempDir::new().unwrap();
        let mut idx = FulltextIndex::create_or_open(tmp.path()).unwrap();

        idx.add_paper(
            "arxiv:2301.00001",
            "AdS/CFT Correspondence and Holographic Entanglement",
            Some("We study the entanglement entropy in anti-de Sitter spacetime using holographic methods."),
            &["Alice Physicist".to_string(), "Bob Theorist".to_string()],
            Some(2023),
        ).unwrap();

        idx.add_paper(
            "arxiv:2302.00002",
            "Quantum Error Correction Codes",
            Some("A review of stabilizer codes and topological quantum error correction."),
            &["Charlie Quantum".to_string()],
            Some(2023),
        ).unwrap();

        idx.commit().unwrap();

        // Search for holographic
        let results = idx.search("holographic entanglement", 10).unwrap();
        assert!(!results.is_empty());
        assert_eq!(results[0].0, "arxiv:2301.00001");

        // Search for quantum
        let results = idx.search("quantum error correction", 10).unwrap();
        assert!(!results.is_empty());
        assert_eq!(results[0].0, "arxiv:2302.00002");

        assert_eq!(idx.count(), 2);

        // Delete
        idx.delete("arxiv:2301.00001").unwrap();
        idx.commit().unwrap();
        assert_eq!(idx.count(), 1);
    }
}
