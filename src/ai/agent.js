// AI-BOM / LLM-security fixture: agentic weaknesses (excessive agency, insecure output
// handling, tool exposure). Never run.
import { exec } from 'node:child_process';
import fs from 'node:fs';
import { anthropic, openai, MODELS } from './providers.js';

// FIX-AI-030 LLM05 (insecure output handling): model output passed straight to eval
export async function runGeneratedCode(task) {
  const res = await anthropic.messages.create({
    model: MODELS.anthropic.default,
    max_tokens: 8192,
    messages: [{ role: 'user', content: `Write JS for: ${task}. Reply with code only.` }],
  });
  const code = res.content.find(b => b.type === 'text')?.text ?? '';
  return eval(code);
}

// FIX-AI-031 LLM05: model output interpolated into a shell command
export async function shellFromModel(question) {
  const res = await openai.chat.completions.create({
    model: MODELS.openai.default,
    messages: [{ role: 'user', content: `Give the shell command for: ${question}` }],
  });
  exec(res.choices[0].message.content, (err, stdout) => console.log(stdout));
}

// FIX-AI-032 LLM05: model output rendered as HTML without escaping (XSS via completion)
export const renderAnswer = (res, answer) => res.send(`<div class="answer">${answer}</div>`);

// FIX-AI-033 LLM05: model output used directly as a SQL query
export const queryFromModel = (db, sql) => db.query(sql);

// FIX-AI-034 LLM06 (excessive agency): tools give the agent unconstrained shell, filesystem
// and network access, with no allowlist, no confirmation and no scoping.
export const TOOLS = [
  {
    name: 'bash',
    description: 'Run any shell command on the application server.',
    input_schema: { type: 'object', properties: { cmd: { type: 'string' } }, required: ['cmd'] },
  },
  {
    name: 'write_file',
    description: 'Write arbitrary content to any path on disk.',
    input_schema: {
      type: 'object',
      properties: { path: { type: 'string' }, content: { type: 'string' } },
      required: ['path', 'content'],
    },
  },
  {
    name: 'http_request',
    description: 'Make an HTTP request to any URL, including internal addresses.',
    input_schema: { type: 'object', properties: { url: { type: 'string' } }, required: ['url'] },
  },
  {
    name: 'run_sql',
    description: 'Execute arbitrary SQL against the production database.',
    input_schema: { type: 'object', properties: { sql: { type: 'string' } }, required: ['sql'] },
  },
];

// FIX-AI-035 LLM06: tool calls executed with no approval gate and no argument validation
export function dispatchTool(call) {
  if (call.name === 'bash') return exec(call.input.cmd);
  if (call.name === 'write_file') return fs.writeFileSync(call.input.path, call.input.content);
  if (call.name === 'http_request') return fetch(call.input.url);
  return null;
}

// FIX-AI-036 LLM06: autonomous loop with no iteration cap, no budget and no kill switch
export async function autonomousLoop(goal) {
  const messages = [{ role: 'user', content: goal }];
  for (;;) {
    const res = await anthropic.messages.create({
      model: MODELS.anthropic.default,
      max_tokens: 16000,
      tools: TOOLS,
      messages,
    });
    messages.push({ role: 'assistant', content: res.content });
    const calls = res.content.filter(b => b.type === 'tool_use');
    if (!calls.length) return res;
    messages.push({
      role: 'user',
      content: calls.map(c => ({ type: 'tool_result', tool_use_id: c.id, content: String(dispatchTool(c)) })),
    });
  }
}

// FIX-AI-037: agent runs with the application's full ambient credentials rather than a
// scoped, least-privilege identity of its own.
export const AGENT_ENV = { AWS_ACCESS_KEY_ID: process.env.AWS_ACCESS_KEY_ID, DATABASE_URL: process.env.DATABASE_URL };
