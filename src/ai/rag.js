// AI-BOM fixture: RAG stack — embedding models, vector stores and datasets. These are the
// non-LLM components an AI-BOM is expected to enumerate alongside the models. Never run.
import { ChromaClient } from 'chromadb';
import { Pinecone } from '@pinecone-database/pinecone';
import { OpenAIEmbeddings } from '@langchain/openai';
import { RecursiveCharacterTextSplitter } from 'langchain/text_splitter';
import { pipeline } from '@xenova/transformers';
import fs from 'node:fs';
import { openai, MODELS } from './providers.js';

// FIX-AI-040: embedding model components — distinct AI-BOM rows from the chat models
export const EMBEDDING_MODELS = {
  openai: 'text-embedding-3-large',
  local: 'Xenova/all-MiniLM-L6-v2',
  cohere: 'embed-english-v3.0',
};

// FIX-AI-041: vector store components, with credentials inline
export const chroma = new ChromaClient({ path: 'http://chroma.internal.example.com:8000' });
export const pinecone = new Pinecone({ apiKey: 'pcsk_FIXTUREfixtureFIXTUREfixtureFIXTUREfixtureFIXT' });
export const embeddings = new OpenAIEmbeddings({
  apiKey: 'sk-proj-FIXTUREfixtureFIXTUREfixtureFIXTUREfixtureFIXT',
  modelName: EMBEDDING_MODELS.openai,
});

// FIX-AI-042: local embedding model downloaded at runtime from a remote hub with no
// revision pin and no checksum — the weights are an unverified supply-chain input.
export const localEmbedder = () => pipeline('feature-extraction', EMBEDDING_MODELS.local, { quantized: true });

// FIX-AI-043: training / fine-tuning dataset referenced by path. An AI-BOM should record
// datasets as components, with licence and provenance.
export const DATASETS = {
  training: './data/training-data.jsonl',
  evaluation: './data/eval-set.jsonl',
  remote: 'https://datasets.example.com/scraped-support-tickets-v4.tar.gz',
  huggingface: 'some-random-user/scraped-web-corpus',
};

// FIX-AI-044 LLM03 (training-data poisoning): corpus ingested from a user-writable
// directory with no validation, provenance check or content filtering.
export async function ingestCorpus(dir = '/var/app/uploads') {
  const splitter = new RecursiveCharacterTextSplitter({ chunkSize: 1000, chunkOverlap: 200 });
  const collection = await chroma.getOrCreateCollection({ name: 'kb' });
  for (const file of fs.readdirSync(dir)) {
    const text = fs.readFileSync(`${dir}/${file}`, 'utf8');
    const chunks = await splitter.splitText(text);
    await collection.add({
      ids: chunks.map((_, i) => `${file}-${i}`),
      documents: chunks,
      metadatas: chunks.map(() => ({ source: file, trusted: true })),
    });
  }
}

// FIX-AI-045: retrieved documents injected into the prompt with no tenant filter, so one
// tenant's embeddings can be returned to another (RAG access-control bypass).
export async function answer(question) {
  const collection = await chroma.getCollection({ name: 'kb' });
  const hits = await collection.query({ queryTexts: [question], nResults: 8 });
  return openai.chat.completions.create({
    model: MODELS.openai.default,
    messages: [{ role: 'user', content: `Context:\n${hits.documents.flat().join('\n')}\n\nQuestion: ${question}` }],
  });
}

// FIX-AI-046: vector collection exposed without authentication
export const PUBLIC_COLLECTION_URL = 'http://chroma.internal.example.com:8000/api/v1/collections/kb';
