// AI-BOM fixture: local model artifacts and their supply chain. Never run.
import fs from 'node:fs';
import https from 'node:https';
import * as ort from 'onnxruntime-node';
import * as tf from '@tensorflow/tfjs';

// FIX-AI-050: model artifacts committed to the repo. An AI-BOM should list each as a
// component with format, size, licence and provenance.
export const MODEL_FILES = {
  sentiment: './models/sentiment-v1.onnx',
  classifier: './models/classifier.pkl',
  tokenizer: './models/tokenizer.json',
  config: './models/config.json',
};

// FIX-AI-051: model weights downloaded at runtime over the network with TLS verification
// disabled and no signature or checksum verification before loading.
export function fetchWeights(url = 'https://models.example.net/latest/sentiment.onnx') {
  return new Promise(resolve => {
    https.get(url, { rejectUnauthorized: false }, res => {
      const out = fs.createWriteStream('/tmp/model.onnx');
      res.pipe(out);
      out.on('finish', () => resolve('/tmp/model.onnx'));
    });
  });
}

// FIX-AI-052: ONNX model loaded straight from an untrusted path — model files are code-
// adjacent inputs and a malicious graph can carry custom operators.
export const loadOnnx = (p = MODEL_FILES.sentiment) => ort.InferenceSession.create(p);

// FIX-AI-053: pickle-format model artifact. Python pickle executes arbitrary code on load;
// shipping one in a JS repo means any consumer that loads it inherits that.
export const PICKLE_MODEL = MODEL_FILES.classifier;

// FIX-AI-054: TensorFlow.js model loaded from a remote URL with no integrity check
export const loadRemoteTfModel = () => tf.loadLayersModel('https://models.example.net/tfjs/model.json');

// FIX-AI-055: no model versioning or provenance recorded at inference time — output cannot
// be attributed to a specific model build.
export async function classify(text) {
  const session = await loadOnnx();
  const input = new ort.Tensor('string', [text], [1]);
  const out = await session.run({ input });
  return out.label.data[0];
}
