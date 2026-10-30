// Synthetic HTTP fixture only. No model inference or vulnerability research.
const http = require('http');
let mode = 'success', delay = 200, calls = [];
const bundle = {
  remediation_prose: {
    summary_in_context: 'Synthetic evidence identifies vulnerable log4j-core 2.14.1.',
    exploitation_likelihood: 'high',
    recommended_path: 'Upgrade log4j-core to the supplied fixed version 2.17.1 and test the application.',
    confidence: 'high',
  },
  upgrade_command: {
    ecosystem: 'Maven', command: 'Update org.apache.logging.log4j:log4j-core to 2.17.1 in pom.xml',
    target_version: '2.17.1', rationale: 'Version 2.17.1 is supplied by the synthetic fix evidence.',
    breaking_change_risk: 'minor', tested_against_data: true,
  },
  decision_recommendation: {
    priority: 'soon', reasoning: ['High severity and a supplied fixed version warrant review.'],
    citations: ['nvd', 'fix_version_data'], confidence: 'high',
    caveats: ['Synthetic test fixture; validate remediation in your environment.'],
  }, overall_confidence: 'high',
};
function strict(schema) {
  if (!schema || typeof schema !== 'object') return true;
  if (schema.type === 'object' && (schema.additionalProperties !== false ||
      Object.keys(schema.properties || {}).some(key => !schema.required?.includes(key)))) return false;
  return Object.values(schema).every(value => Array.isArray(value) ? value.every(strict) : strict(value));
}
http.createServer(async (req, res) => {
  const send = (status, body) => { res.writeHead(status, { 'Content-Type': 'application/json' }); res.end(JSON.stringify(body)); };
  if (req.url === '/__control' && req.method === 'POST') {
    mode = req.body?.mode || 'success'; delay = req.body?.delay ?? 200;
    if (req.body?.reset) calls = [];
    return send(200, { mode, delay });
  }
  if (req.url === '/__metrics') return send(200, { calls });
  if (req.url === '/v1/models') return send(200, { data: [{ id: 'gpt-4o' }, { id: 'gpt-6-luna' }] });
  if (req.method !== 'POST' || !['/v1/chat/completions', '/v1/responses'].includes(req.url)) {
    return send(501, { error: { code: 'not_implemented' } });
  }
  const body = req.body || {}, modern = req.url === '/v1/responses';
  const schema = modern ? body.text?.format?.schema : body.response_format?.json_schema?.schema;
  const valid = strict(schema) && !!schema && (modern ? body.max_output_tokens > 0 && body.store === false : body.max_tokens > 0);
  calls.push({ endpoint: req.url, model: body.model, strict_schema: valid, mode });
  if (!valid) return send(400, { error: { code: 'invalid_json_schema', message: 'Synthetic strict schema rejected.' } });
  const selected = mode;
  await new Promise(resolve => setTimeout(resolve, delay));
  if (selected === 'quota') return send(429, { error: { code: 'insufficient_quota', message: 'Synthetic quota exhausted.' } });
  if (selected === 'permission') return send(403, { error: { code: 'permission_denied', message: 'Synthetic model permission denied.' } });
  const text = selected === 'invalid_json' ? 'not-json' : JSON.stringify(bundle);
  if (modern) return send(200, { status: selected === 'incomplete' ? 'incomplete' : 'completed',
    incomplete_details: selected === 'incomplete' ? { reason: 'max_output_tokens' } : null,
    output: [{ type: 'message', content: [{ type: 'output_text', text }] }],
    usage: { input_tokens: 100, output_tokens: 240, output_tokens_details: { reasoning_tokens: 40 } },
  });
  return send(200, { choices: [{ finish_reason: selected === 'incomplete' ? 'length' : 'stop', message: { content: text } }],
    usage: { prompt_tokens: 100, completion_tokens: 200 } });
}).listen(process.env.PORT);
