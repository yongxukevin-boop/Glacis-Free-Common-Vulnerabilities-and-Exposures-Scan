import test from 'node:test';
import assert from 'node:assert/strict';
import { validateTarget, csvCell } from '../docs/utils.mjs';
import { normalize, privateAddress, validateScan } from '../scripts/scan.mjs';
test('reject unsafe URL forms', () => {
  for (const url of ['file:///etc/passwd', 'https://user:pass@example.com', 'https://example.com/#fragment', 'https://example.com\nwhoami', '-version']) assert.throws(() => validateTarget(url));
  assert.equal(validateTarget('https://example.com/a?q=x'), 'https://example.com/a?q=x');
});
test('reject dispatch identifiers and unapproved targets before DNS', async () => {
  await assert.rejects(validateScan({scan_id: '../../bad', target_url:'https://example.com'}, 'example.com'));
  await assert.rejects(validateScan({scan_id: '12345678-1234-4123-8123-123456789012', target_url:'https://example.com'}, 'other.example'));
});
test('block local and private addresses', () => {
  for (const ip of ['127.0.0.1','10.2.3.4','172.16.0.1','192.168.1.1','169.254.169.254','::1','::ffff:127.0.0.1']) assert.equal(privateAddress(ip), true);
  assert.equal(privateAddress('8.8.8.8'), false);
});
test('parse empty output, preserve template details, and bound snippets', () => {
  assert.deepEqual(normalize([]), []);
  assert.throws(() => normalize({}));
  assert.throws(() => normalize([null]));
  const [finding] = normalize([{info: {name:'Test', severity:'high', classification:{'cve-id':['CVE-2025-12345']}, remediation:'Upgrade'}, 'matched-at':'https://example.com', 'extracted-results':['value'], request:'a'.repeat(3000)}]);
  assert.equal(finding.request.length, 2000); assert.equal(finding.remediation, 'Upgrade'); assert.deepEqual(finding.cves, ['CVE-2025-12345']);
});
test('CSV quotes text and neutralises spreadsheet formulas', () => {
  assert.equal(csvCell('=HYPERLINK("evil")'), '"\'=HYPERLINK(""evil"")"');
  assert.equal(csvCell('a,b'), '"a,b"');
});
test('keep Unicode-heavy reports under the API inline limit', () => {
  const text = '漢'.repeat(4000);
  const rows = Array.from({length: 100}, () => ({info: {name:text, description:text, remediation:text}, request:text, response:text, 'extracted-results':Array(10).fill(text)}));
  const result = normalize(rows);
  assert.ok(result.length > 0 && result.length < rows.length);
  assert.ok(Buffer.byteLength(JSON.stringify(result)) <= 700000);
});
