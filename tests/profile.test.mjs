import test from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import vm from 'node:vm';

test('scanner includes KEV and informational templates and preserves URL argument isolation', () => {
  const source = readFileSync(new URL('../scripts/scan.mjs', import.meta.url), 'utf8');
  const expression = source.match(/spawnSync\('nuclei', (\[[^\n]+?\]), \{/)[1];
  const target = 'https://example.com/?x=$(echo-injection)';
  const args = vm.runInNewContext(expression, { target });
  assert.equal(args[args.indexOf('-template-condition') + 1], "contains(tags, 'kev') || severity == 'info'");
  assert.ok(!args.includes('-profile'));
  assert.ok(args[args.indexOf('-severity') + 1].split(',').includes('info'));
  assert.equal(args[args.indexOf('-u') + 1], target);
  assert.equal(args.filter(arg => arg === target).length, 1);
  assert.ok(args.includes('-stats'));
  assert.equal(args[args.indexOf('-json-export') + 1], 'results.json');
});
