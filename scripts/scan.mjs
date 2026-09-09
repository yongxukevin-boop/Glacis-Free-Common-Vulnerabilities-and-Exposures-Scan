import { readFileSync, writeFileSync, mkdirSync, existsSync } from 'node:fs';
import { spawnSync } from 'node:child_process';
import { lookup } from 'node:dns/promises';
import { pathToFileURL } from 'node:url';
import { validateTarget, severities } from '../docs/utils.mjs';

export function normalize(rows) {
  if (!Array.isArray(rows)) throw new Error('Nuclei output must be a JSON array.');
  const clip = (v, length = 1600) => String(v ?? '').slice(0, length);
  const list = v => Array.isArray(v) ? v : v ? [v] : [];
  const findings = rows.slice(0, 60).map(row => {
    if (!row || typeof row !== 'object' || !row.info) throw new Error('Malformed Nuclei finding.');
    const info = row.info;
    return { name: clip(info.name || row['template-id']), template_id: clip(row['template-id']), cves: list(info.classification?.['cve-id']).map(v => clip(v, 40)), severity: severities.includes(info.severity) ? info.severity : 'info', matched: clip(row['matched-at'] || row.url || row.host), description: clip(info.description), remediation: clip(info.remediation), extracted: list(row['extracted-results']).slice(0, 10).map(v => clip(v, 200)), request: clip(row.request, 2000), response: clip(row.response, 2000) };
  });
  // Leave room for metadata below GitHub's 1 MB inline Contents API limit.
  while (Buffer.byteLength(JSON.stringify(findings), 'utf8') > 700000) findings.pop();
  return findings;
}
export function privateAddress(address) {
  // Restrict IPv6 targets conservatively; IPv4-mapped IPv6 is also rejected.
  if (address.includes(':')) return true;
  const [a, b] = address.split('.').map(Number);
  return a === 0 || a === 10 || a === 127 || a >= 224 || (a === 169 && b === 254) || (a === 172 && b >= 16 && b <= 31) || (a === 192 && b === 168) || (a === 100 && b >= 64 && b <= 127) || (a === 198 && [18, 19].includes(b));
}
export async function validateScan(payload, resolveHost = lookup) {
  if (!/^[a-f0-9]{8}-[a-f0-9]{4}-4[a-f0-9]{3}-[89ab][a-f0-9]{3}-[a-f0-9]{12}$/i.test(payload.scan_id || '')) throw new Error('Invalid scan ID.');
  const target = validateTarget(payload.target_url);
  const host = new URL(target).hostname.toLowerCase();
  const addresses = await resolveHost(host, { all: true });
  if (!addresses.length || addresses.some(a => privateAddress(a.address))) throw new Error('Only public IPv4 targets are supported.');
  return target;
}
async function main() {
  const payload = JSON.parse(readFileSync(process.env.GITHUB_EVENT_PATH, 'utf8')).client_payload || {};
  const target = await validateScan(payload);
  if (process.argv.includes('--validate')) return;
  const report = { schema_version: 1, profile: 'recommended', scan_id: payload.scan_id, run_id: process.env.GITHUB_RUN_ID, target, finished_at: null, status: 'failed', error: null, findings: [], truncated: false };
  try {
    const result = spawnSync('nuclei', ['-profile', 'recommended', '-stats', '-stats-interval', '15', '-u', target, '-json-export', 'results.json', '-severity', 'low,medium,high,critical', '-rl', '10', '-c', '5', '-timeout', '10', '-retries', '1', '-dr', '-ni', '-duc'], { stdio: 'inherit', shell: false, timeout: 20 * 60 * 1000 });
    if (result.error || result.status !== 0) throw new Error(`Nuclei failed or exceeded 20 minutes (exit ${result.status ?? 'unknown'}).`);
    if (!existsSync('results.json')) throw new Error('Nuclei produced no JSON output; scan completion cannot be verified.');
    const rows = JSON.parse(readFileSync('results.json', 'utf8'));
    report.findings = normalize(rows); report.truncated = rows.length > report.findings.length;
    report.status = 'completed';
  } catch (error) { report.error = error.message; }
  report.finished_at = new Date().toISOString();
  mkdirSync('public/scans', { recursive: true });
  const output = JSON.stringify(report);
  writeFileSync('public/latest_scan.json', output);
  writeFileSync(`public/scans/${payload.scan_id}.json`, output);
  if (report.status !== 'completed') process.exitCode = 1;
}
if (process.argv[1] && import.meta.url === pathToFileURL(process.argv[1]).href) main().catch(error => { console.error(error.message); process.exitCode = 1; });

