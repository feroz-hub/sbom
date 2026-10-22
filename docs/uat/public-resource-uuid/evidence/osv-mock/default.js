/* Local-only OSV contract fixture; source: tests/fixtures/canned_responses.py.
 * https://google.github.io/osv.dev/post-v1-querybatch/
 * https://google.github.io/osv.dev/get-v1-vulns/
 * No credentials, remote requests, or production intelligence claims. */
const http = require('node:http');
const records = require('./fixtures.json');
const headers = { 'Content-Type': 'application/json' };
function matches(query) {
  const purl = query?.package?.purl ?? '';
  return Object.values(records).filter(v => v.affected.some(a =>
    (a.package.name === 'requests' && (purl.startsWith('pkg:pypi/requests@') || query?.package?.name === 'requests')) ||
    (a.package.name === 'org.apache.logging.log4j:log4j-core' && purl.includes('log4j-core'))));
}
http.createServer(async (req,res) => {
  try {
    const path = new URL(req.url, 'http://localhost').pathname;
    const body = req.body ?? {};
    if (req.method === 'POST' && path === '/v1/querybatch') {
      if (!Array.isArray(body.queries) || body.queries.some(q => q.version && /@[^/]+$/.test(q.package?.purl ?? ''))) {
        res.writeHead(400,headers); res.end(JSON.stringify({message:'Invalid querybatch payload'})); return;
      }
      res.writeHead(200,headers); res.end(JSON.stringify({results:body.queries.map(q=>({vulns:matches(q).map(v=>({id:v.id,modified:v.modified}))}))})); return;
    }
    if (req.method === 'POST' && path === '/v1/query') {
      res.writeHead(200,headers);res.end(JSON.stringify({vulns:matches(body)}));return;
    }
    if (req.method === 'GET' && path.startsWith('/v1/vulns/')) {
      const record=records[decodeURIComponent(path.slice('/v1/vulns/'.length))];
      res.writeHead(record?200:404,headers);res.end(JSON.stringify(record??{message:'Vulnerability not found'}));return;
    }
    res.writeHead(501,headers);res.end(JSON.stringify({message:'Unmodeled contract operation'}));
  } catch {
    res.writeHead(400,headers);res.end(JSON.stringify({message:'Invalid request'}));
  }
}).listen(process.env.PORT, '127.0.0.1');
