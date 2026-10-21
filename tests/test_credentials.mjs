// SPDX-License-Identifier: Apache-2.0
import test from 'node:test';
import assert from 'node:assert/strict';
import {credentialView} from '../web/credentials.mjs';

const now = Date.parse('2026-10-18T09:00:00Z');
const record = (state, expires_at) => ({state, items:[{id:'login', state, expires_at, secret:'private-token'}]});
test('current lifetime shows the real countdown and no destructive action', () => {
  const view = credentialView(record('current','2026-10-20T11:00:00+02:00'), now);
  assert.equal(view.items[1].text, 'Expires in 48h 0m');
  assert.equal(view.guidance, null);
  assert.match(view.message, /24 hours/);
  assert.doesNotMatch(JSON.stringify(view), /private-token/);
});
test('approaching and elapsed lifetimes explain the supported explicit recovery', () => {
  const soon = credentialView(record('expiring','2026-10-18T09:15:00Z'), now);
  const expired = credentialView(record('expired','2026-10-18T08:30:00Z'), now);
  assert.equal(soon.items[1].text,'Expires in 15m');
  assert.equal(expired.items[1].text,'Expired 30m ago');
  assert.match(soon.title,/expire soon/);
  assert.match(expired.title,/have expired/);
  assert.match(expired.message,/does not renew/);
  assert.match(expired.guidance,/identities, keys and notes/);
  assert.match(expired.guidance,/No automatic reset/);
});
test('unknown metadata does not display a fabricated remaining lifetime', () => {
  for (const value of [undefined, record('unknown','2090-10-18T09:00:00Z'), record('unknown','private-token')]) {
    const view = credentialView(value, now);
    assert.equal(view.state,'unknown');
    assert.equal(view.items[1].text,'Expiry unavailable');
    assert.equal(view.items[1].expires_at,null);
    assert.equal(view.guidance,null);
    assert.doesNotMatch(JSON.stringify(view),/private-token/);
  }
});
test('stopped identity checks request startup instead of claiming credentials are current', () => {
  const view = credentialView({state:'stopped'}, now);
  assert.match(view.message,/Start the security stack/);
  assert.equal(view.items[1].text,'Expiry unavailable');
});

test('elapsed lifetime rounds down and immediate expiry does not invent an elapsed minute', () => {
  assert.equal(credentialView(record('expired','2026-10-18T08:00:00Z'), now + 500).items[1].text,'Expired 1h 0m ago');
  assert.equal(credentialView(record('expired','2026-10-18T09:00:00Z'), now + 500).items[1].text,'Expired just now');
});
