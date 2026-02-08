use std::path::{Path, PathBuf};
use anyhow::{Context, Result};

pub const EMBEDDING_DIMENSION: usize = 768;

/// Generate a mock embedding for testing (deterministic based on text hash).
pub fn mock_embedding(text: &str) -> Vec<f32> {
    use std::collections::hash_map::DefaultHasher;
    use std::hash::{Hash, Hasher};
    let mut hasher = DefaultHasher::new();
    text.hash(&mut hasher);
    let seed = hasher.finish();
    let mut rng_state = seed;
    (0..EMBEDDING_DIMENSION)
        .map(|_| {
            rng_state ^= rng_state << 13;
            rng_state ^= rng_state >> 7;
            rng_state ^= rng_state << 17;
            ((rng_state as f32) / (u64::MAX as f32)) * 2.0 - 1.0
        })
        .collect()
}

/// Download the SPECTER2 ONNX model from HuggingFace to the given directory.
pub async fn download_model(model_dir: &Path) -> Result<PathBuf> {
    let model_path = model_dir.join("specter2.onnx");
    if model_path.exists() {
        tracing::info!("SPECTER2 model already exists at {:?}", model_path);
        return Ok(model_path);
    }

    std::fs::create_dir_all(model_dir)
        .context("Failed to create model directory")?;

    let url = "https://huggingface.co/allenai/specter2/resolve/main/onnx/model.onnx";
    tracing::info!("Downloading SPECTER2 model from {}", url);

    let client = reqwest::Client::new();
    let resp = client.get(url).send().await
        .context("Failed to download SPECTER2 model")?;
    anyhow::ensure!(resp.status().is_success(), "Download failed with status: {}", resp.status());

    let bytes = resp.bytes().await.context("Failed to read model bytes")?;
    std::fs::write(&model_path, &bytes)
        .context("Failed to write model file")?;

    tracing::info!("SPECTER2 model saved to {:?} ({} bytes)", model_path, bytes.len());
    Ok(model_path)
}

// ── ONNX-based embedder (requires `onnx` feature) ──────────────────────────

#[cfg(feature = "onnx")]
mod onnx_impl {
    use super::*;
    use anyhow::Context;

    const MAX_SEQ_LEN: usize = 512;

    /// SPECTER2 embedder using ONNX Runtime.
    ///
    /// Generates 768-dim embeddings from paper title + abstract.
    pub struct SpecterEmbedder {
        session: ort::session::Session,
        tokenizer: tokenizers::Tokenizer,
    }

    impl SpecterEmbedder {
        /// Create a new embedder loading the ONNX model and tokenizer.
        pub fn new(model_dir: &Path) -> Result<Self> {
            let model_path = model_dir.join("specter2.onnx");
            anyhow::ensure!(model_path.exists(), "ONNX model not found at {:?}. Run download_model() first.", model_path);

            let session = ort::session::Session::builder()
                .context("Failed to create ONNX session builder")?
                .commit_from_file(&model_path)
                .context("Failed to load ONNX model")?;

            let tokenizer_path = model_dir.join("tokenizer.json");
            let tokenizer = if tokenizer_path.exists() {
                tokenizers::Tokenizer::from_file(&tokenizer_path)
                    .map_err(|e| anyhow::anyhow!("Failed to load tokenizer: {}", e))?
            } else {
                let tok = tokenizers::Tokenizer::from_pretrained("allenai/specter2", None)
                    .map_err(|e| anyhow::anyhow!("Failed to download tokenizer: {}", e))?;
                let _ = tok.save(&tokenizer_path, false);
                tok
            };

            Ok(Self { session, tokenizer })
        }

        /// Embed a paper from its title and optional abstract.
        pub fn embed(&mut self, title: &str, abstract_text: Option<&str>) -> Result<Vec<f32>> {
            let text = match abstract_text {
                Some(abs) if !abs.is_empty() => format!("{} [SEP] {}", title, abs),
                _ => title.to_string(),
            };
            self.embed_text(&text)
        }

        /// Embed raw text. Returns a 768-dimensional f32 vector.
        pub fn embed_text(&mut self, text: &str) -> Result<Vec<f32>> {
            let encoding = self.tokenizer.encode(text, true)
                .map_err(|e| anyhow::anyhow!("Tokenization failed: {}", e))?;

            let ids = encoding.get_ids();
            let mask = encoding.get_attention_mask();

            let len = ids.len().min(MAX_SEQ_LEN);
            let token_ids: Vec<i64> = ids[..len].iter().map(|&x| x as i64).collect();
            let attention_mask: Vec<i64> = mask[..len].iter().map(|&x| x as i64).collect();

            let input_ids = ort::value::Tensor::from_array(([1, len], token_ids.into_boxed_slice()))
                .context("Failed to create input_ids tensor")?;
            let attn_mask = ort::value::Tensor::from_array(([1, len], attention_mask.into_boxed_slice()))
                .context("Failed to create attention_mask tensor")?;

            let outputs = self.session.run(ort::inputs![
                "input_ids" => input_ids,
                "attention_mask" => attn_mask
            ])
            .context("ONNX inference failed")?;

            let (shape, data) = outputs[0].try_extract_tensor::<f32>()
                .context("Failed to extract output tensor")?;

            let embedding = if shape.len() == 3 {
                data[..EMBEDDING_DIMENSION].to_vec()
            } else if shape.len() == 2 {
                data[..EMBEDDING_DIMENSION].to_vec()
            } else {
                anyhow::bail!("Unexpected output shape: {:?}", shape);
            };

            Ok(embedding)
        }
    }
}

#[cfg(feature = "onnx")]
pub use onnx_impl::SpecterEmbedder;
