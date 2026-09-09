import { severities, validateTarget, csvCell } from './utils.mjs';
import { repository } from './config.mjs';
const $ = id => document.getElementById(id);
let report = null;
const pause = ms => new Promise(resolve => setTimeout(resolve, ms));
function status(message) { $('status').textContent = message; }
function context() {
  const owner = repository.owner.trim(), repo = repository.name.trim(), token = $('token').value.trim();
  if (!/^[a-z\d-]+$/i.test(owner) || !/^[a-z\d_.-]+$/i.test(repo) || repo === '.' || repo === '..') throw new Error('The dashboard owner must configure the scanner repository before scanning.');
  return { owner, repo, token, base: `https://api.github.com/repos/${owner}/${repo}` };
}
async function api(ctx, path, options = {}) {
  const response = await fetch(ctx.base + path, { ...options, cache: 'no-store', signal: AbortSignal.timeout(30000), headers: { Accept: 'application/vnd.github+json', 'X-GitHub-Api-Version': '2022-11-28', ...(ctx.token ? { Authorization: `Bearer ${ctx.token}` } : {}), ...(options.body ? { 'Content-Type': 'application/json' } : {}) } });
  if (!response.ok) throw new Error(`GitHub API ${response.status}. ${response.status === 403 || response.status === 429 ? 'Check token permissions and API rate limits.' : response.status === 404 ? 'Repository, workflow or report not found. Check setup and token access.' : 'Open GitHub Actions for details.'}`);
  return response.status === 204 ? null : response.json();
}
async function getReport(ctx, path) {
  const file = await api(ctx, '/contents/' + path);
  if (!file.content) throw new Error('Report exceeds the Contents API inline size limit. Download it from the repository.');
  return JSON.parse(new TextDecoder().decode(Uint8Array.from(atob(file.content.replace(/\s/g, '')), c => c.charCodeAt(0))));
}
function setReport(data) {
  if (!Array.isArray(data.findings)) throw new Error('Invalid report format.');
  report = data;
  $('meta').textContent = `${data.target || 'Unknown target'} · ${data.finished_at || ''} · ${data.findings.length} findings${data.truncated ? ' · Report capped; see raw artifact' : ''}`;
  $('csv').disabled = $('json').disabled = false;
  render();
}
function node(tag, text, className) { const e = document.createElement(tag); if (text !== undefined) e.textContent = text; if (className) e.className = className; return e; }
function filtered() { const query = $('search').value.toLowerCase(); return (report?.findings || []).filter(f => ($('severity').value === 'all' || f.severity === $('severity').value) && JSON.stringify(f).toLowerCase().includes(query)); }
function render() {
  $('counts').replaceChildren(...severities.map(s => { const e = node('div', undefined, `count ${s}`); e.append(node('span', s.toUpperCase()), node('strong', (report?.findings || []).filter(f => f.severity === s).length)); return e; }));
  $('findings').replaceChildren();
  if (!report) return;
  const matches = filtered();
  if (!matches.length) { $('findings').append(node('p', report.status !== 'completed' ? 'Scan failed or was incomplete. This is not a clean result.' : report.findings.length ? 'No findings match your filters.' : 'No vulnerabilities matched the selected templates. This is not a guarantee of security.', 'empty')); return; }
  for (const severity of severities) {
    const group = matches.filter(f => f.severity === severity); if (!group.length) continue;
    $('findings').append(node('h2', `${severity.toUpperCase()} · ${group.length}`));
    for (const f of group) {
      const card = node('article', undefined, 'finding'); card.append(node('span', severity, `badge ${severity}`), node('h3', f.name));
      for (const cve of f.cves || []) if (/^CVE-\d{4}-\d{4,}$/i.test(cve)) { const a = node('a', cve + ' ↗ '); a.href = `https://nvd.nist.gov/vuln/detail/${encodeURIComponent(cve)}`; a.target = '_blank'; a.rel = 'noopener noreferrer'; card.append(a); }
      for (const [label, value] of [['Endpoint', f.matched], ['Description', f.description], ['Extraction', (f.extracted || []).join('\n')], ['Remediation', f.remediation || 'Not provided by template.']]) { card.append(node('h4', label), node('p', value || 'Not provided')); }
      const details = node('details'); details.append(node('summary', 'HTTP request / response snippets'), node('pre', `REQUEST\n${f.request || 'Not available'}\n\nRESPONSE\n${f.response || 'Not available'}`)); card.append(details); $('findings').append(card);
    }
  }
}
function busy(value) { for (const id of ['start', 'latest', 'target', 'token']) $(id).disabled = value; }
$('scan-form').addEventListener('submit', async event => {
  event.preventDefault(); let ctx;
  try {
    ctx = context(); if (!ctx.token) throw new Error('A GitHub token is required.');
    const target = validateTarget($('target').value.trim()), scanId = crypto.randomUUID();
    busy(true); report = null; $('csv').disabled = $('json').disabled = true; render(); $('run-link').hidden = true; status('Dispatching scan…');
    await api(ctx, '/dispatches', { method: 'POST', body: JSON.stringify({ event_type: 'run-nuclei-scan', client_payload: { target_url: target, scan_id: scanId } }) });
    $('token').value = ''; status('Queued · waiting for GitHub Actions');
    const deadline = Date.now() + 45 * 60 * 1000; let run;
    while (Date.now() < deadline) {
      if (run) run = await api(ctx, `/actions/runs/${run.id}`);
      else { const data = await api(ctx, '/actions/workflows/nuclei-scan.yml/runs?event=repository_dispatch&per_page=100'); run = data.workflow_runs.find(r => r.display_title === `Nuclei scan ${scanId}`); }
      if (run) {
        $('run-link').href = `https://github.com/${ctx.owner}/${ctx.repo}/actions/runs/${run.id}`; $('run-link').hidden = false;
        status(`${run.status}${run.conclusion ? ' · ' + run.conclusion : ''}`);
        if (run.status === 'completed') {
          if (run.conclusion !== 'success') throw new Error(`Workflow ${run.conclusion}. Open the run log; no clean scan result is claimed.`);
          const data = await getReport(ctx, `public/scans/${scanId}.json`);
          if (data.scan_id !== scanId || String(data.run_id) !== String(run.id)) throw new Error('Report does not match this scan.');
          setReport(data); status(data.status === 'completed' ? 'Completed' : 'Scan incomplete · ' + data.error); return;
        }
      }
      await pause(10000);
    }
    throw new Error('Monitoring timed out. The workflow may still be running; check GitHub Actions.');
  } catch (error) { status(error.message); } finally { if (ctx) ctx.token = ''; $('token').value = ''; busy(false); }
});
$('latest').addEventListener('click', async () => { let ctx; try { ctx = context(); busy(true); setReport(await getReport(ctx, 'public/latest_scan.json')); status(report.status === 'completed' ? 'Latest report loaded' : `Latest scan incomplete: ${report.error || report.status}`); } catch (error) { status(error.message); } finally { if (ctx) ctx.token = ''; $('token').value = ''; busy(false); } });
for (const id of ['search', 'severity']) $(id).addEventListener('input', render);
function download(text, type, extension) { const url = URL.createObjectURL(new Blob([text], { type })); const a = node('a'); a.href = url; a.download = `nuclei-${report.scan_id || 'report'}.${extension}`; a.click(); setTimeout(() => URL.revokeObjectURL(url), 1000); }
$('json').addEventListener('click', () => download(JSON.stringify({ ...report, findings: filtered() }, null, 2), 'application/json', 'json'));
$('csv').addEventListener('click', () => { const keys = ['name', 'cves', 'severity', 'matched', 'description', 'extracted', 'remediation', 'request', 'response']; download([keys, ...filtered().map(f => keys.map(k => Array.isArray(f[k]) ? f[k].join('; ') : f[k]))].map(row => row.map(csvCell).join(',')).join('\r\n'), 'text/csv;charset=utf-8', 'csv'); });
render();
