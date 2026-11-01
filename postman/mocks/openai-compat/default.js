// SBO-99: synthetic fixtures from documented OpenAI request/response shapes.
// This validates caller HTTP behavior; it does not establish real model access.
const http = require('http');
http.createServer((req, res) => {
  const send = (status, data) => {
    res.writeHead(status, { 'Content-Type': 'application/json' });
    res.end(JSON.stringify(data));
  };
  if (req.method === 'GET' && req.url === '/v1/models') {
    return send(200, { data: [{ id: 'gpt-4o-mini' }, { id: 'gpt-6-luna' }] });
  }
  const body = req.body || {};
  if (req.method !== 'POST' || !['/v1/chat/completions', '/v1/responses'].includes(req.url)) {
    return send(501, { error: { code: 'not_implemented' } });
  }
  const modern = req.url === '/v1/responses';
  const format = modern ? body.text?.format : body.response_format;
  const limit = modern ? body.max_output_tokens : body.max_tokens;
  if (!format || !Number.isInteger(limit) || limit > 2048 ||
      (modern && ('temperature' in body || 'max_tokens' in body || body.store !== false))) {
    return send(400, { error: { code: 'unsupported_parameter', message: 'Invalid synthetic request.' } });
  }
  if (body.model === 'gpt-6.1-sol') {
    return send(429, { error: { code: 'insufficient_quota', message: 'Synthetic quota exhaustion.' } });
  }
  if (modern) {
    return send(200, {
      status: 'completed', output: [{ type: 'message', content: [{ type: 'output_text', text: '{"ok":true}' }] }],
      usage: { input_tokens: 20, output_tokens: 125, output_tokens_details: { reasoning_tokens: 100 } },
    });
  }
  return send(200, {
    choices: [{ finish_reason: 'stop', message: { content: '{"ok":true}' } }],
    usage: { prompt_tokens: 20, completion_tokens: 25 },
  });
}).listen(process.env.PORT);
