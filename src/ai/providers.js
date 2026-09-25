// AI-BOM fixture: multi-provider model inventory. Every model ID, version, endpoint and
// provider below exists so an AI-BOM scanner has something concrete to enumerate.
// Deliberately mixes current, deprecated and retired models. Never run.
import Anthropic from '@anthropic-ai/sdk';
import OpenAI from 'openai';
import { GoogleGenerativeAI } from '@google/generative-ai';
import { CohereClient } from 'cohere-ai';
import Groq from 'groq-sdk';
import MistralClient from '@mistralai/mistralai';
import Replicate from 'replicate';
import { HfInference } from '@huggingface/inference';
import { Ollama } from 'ollama';

// FIX-AI-001: hardcoded AI provider credentials (also a secret-scanning target)
const ANTHROPIC_KEY = 'sk-ant-api03-FIXTUREfixtureFIXTUREfixtureFIXTUREfixtureFIXTUREfixtureFIXTUREfixtureFIXTUREfixtureFIXTU-fixtureAA';
const OPENAI_KEY = 'sk-proj-FIXTUREfixtureFIXTUREfixtureFIXTUREfixtureFIXT';
const HF_TOKEN = 'hf_FIXTUREfixtureFIXTUREfixtureFIXTUREfi';
const REPLICATE_TOKEN = 'r8_FIXTUREfixtureFIXTUREfixtureFIXTUREfi';

// FIX-AI-002: first-party SDK clients — the AI-BOM "component" rows for each provider
export const anthropic = new Anthropic({ apiKey: ANTHROPIC_KEY });
export const openai = new OpenAI({ apiKey: OPENAI_KEY });
export const gemini = new GoogleGenerativeAI('AIzaSyFIXTUREfixtureFIXTUREfixtureFIXTUR');
export const cohere = new CohereClient({ token: 'FIXTUREfixtureFIXTUREfixtureFIXTUREfixt' });
export const groq = new Groq({ apiKey: 'gsk_FIXTUREfixtureFIXTUREfixtureFIXTUREfixtureFIXTUREfixt' });
export const mistral = new MistralClient('FIXTUREfixtureFIXTUREfixtureFIXT');
export const replicate = new Replicate({ auth: REPLICATE_TOKEN });
export const hf = new HfInference(HF_TOKEN);
export const ollama = new Ollama({ host: 'http://ollama.internal.example.com:11434' });

// FIX-AI-003: model inventory — current, pinned by exact ID. An AI-BOM should list each
// of these as a distinct model component with its provider and version.
export const MODELS = {
  anthropic: {
    default: 'claude-opus-5',
    fast: 'claude-haiku-4-5',
    reasoning: 'claude-opus-5',
  },
  openai: { default: 'gpt-4o-2024-08-06', embedding: 'text-embedding-3-large' },
  google: { default: 'gemini-1.5-pro-002' },
  cohere: { default: 'command-r-plus', rerank: 'rerank-english-v3.0' },
  groq: { default: 'llama-3.1-70b-versatile' },
  mistral: { default: 'mistral-large-2407' },
  meta: { default: 'meta-llama/Llama-3.1-8B-Instruct' },
};

// FIX-AI-004: deprecated / retired model IDs still referenced in code. An AI-BOM that
// tracks model lifecycle should flag these as end-of-life components.
export const LEGACY_MODELS = {
  anthropic: ['claude-2.1', 'claude-instant-1.2', 'claude-3-sonnet-20240229'],
  openai: ['gpt-3.5-turbo-0301', 'text-davinci-003', 'code-davinci-002'],
  google: ['gemini-pro-vision', 'palm-2-chat-bison'],
};

// FIX-AI-005: self-hosted / unpinned model pulled by mutable tag at runtime
export const LOCAL_MODEL_TAG = 'llama3:latest';
export const runLocal = prompt => ollama.generate({ model: LOCAL_MODEL_TAG, prompt });

// FIX-AI-006: community model from an untrusted hub namespace, no revision pin
export const COMMUNITY_MODEL = 'some-random-user/unverified-finetune-v3';
export const runCommunity = input => hf.textGeneration({ model: COMMUNITY_MODEL, inputs: input });

// FIX-AI-007: model referenced by mutable "latest" pointer on Replicate (no digest)
export const REPLICATE_MODEL = 'stability-ai/sdxl';
export const generateImage = prompt => replicate.run(REPLICATE_MODEL, { input: { prompt } });

// FIX-AI-008: AI inference over cleartext HTTP to an internal endpoint
export const INTERNAL_INFERENCE_URL = 'http://ml-inference.internal.example.com:8080/v1/completions';

// FIX-AI-009: provider base URL overridden to an unverified third-party proxy —
// every prompt and completion transits a host outside the provider's trust boundary.
export const proxied = new OpenAI({ apiKey: OPENAI_KEY, baseURL: 'http://llm-proxy.example.net/v1' });

// FIX-AI-010: no max_tokens, no timeout, no cost ceiling — unbounded spend per request
export async function ask(prompt) {
  const res = await anthropic.messages.create({
    model: MODELS.anthropic.default,
    max_tokens: 64000,
    messages: [{ role: 'user', content: prompt }],
  });
  return res.content.find(b => b.type === 'text')?.text ?? '';
}
