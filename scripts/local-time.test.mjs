// Real Intl timezone formatting; deterministic DOM seams, no browser/network/database required.
import assert from 'node:assert/strict';
import { readFile } from 'node:fs/promises';
import test from 'node:test';
import vm from 'node:vm';
const script = await readFile(new URL('../src/Nergal.Web/wwwroot/js/local-time.js', import.meta.url), 'utf8');

function fixture(instants, initialZone = 'America/New_York', noIntl = false) {
  let zone = initialZone;
  let observe;
  const events = {};
  const element = instant => ({ nodeType: 1, textContent: 'UTC fallback', getAttribute: () => instant,
    matches: selector => selector === 'time[data-local-time]', querySelectorAll: () => [] });
  const times = instants.map(element);
  const label = { textContent: 'UTC fallback' };
  const document = { documentElement: {}, hidden: false,
    querySelectorAll: selector => selector === 'time[data-local-time]' ? times : [label],
    addEventListener: (name, callback) => { events[name] = callback; } };
  const context = vm.createContext({ document, window: { addEventListener: (name, callback) => { events[name] = callback; } },
    Intl: noIntl ? undefined : { DateTimeFormat: function (_, options) { return new Intl.DateTimeFormat('en-US', { ...options, timeZone: zone }); } },
    MutationObserver: class { constructor(callback) { observe = callback; } observe() {} } });
  vm.runInContext(script, context);
  return { times, label, events, element, setZone: value => { zone = value; }, mutate: records => observe(records) };
}

test('local presentation crosses the date boundary without modifying the UTC instant', () => {
  const instant = '2026-11-23T01:00:00.1234567Z';
  const f = fixture([instant]);
  assert.match(f.times[0].textContent, /Nov\s+22,\s+2026/);
  assert.match(f.times[0].textContent, /08:00:00\s+PM\s+EST/);
  assert.equal(f.times[0].getAttribute('datetime'), instant);
  assert.equal(f.label.textContent, 'America/New_York');
});
test('spring DST skips the nonexistent local hour', () => {
  const f = fixture(['2026-03-08T06:59:59Z', '2026-03-08T07:00:00Z']);
  assert.match(f.times[0].textContent, /01:59:59\s+AM\s+EST/);
  assert.match(f.times[1].textContent, /03:00:00\s+AM\s+EDT/);
});
test('autumn repeated local hours retain their distinct timezone indication', () => {
  const f = fixture(['2026-11-01T05:30:00Z', '2026-11-01T06:30:00Z']);
  assert.match(f.times[0].textContent, /01:30:00\s+AM\s+EDT/);
  assert.match(f.times[1].textContent, /01:30:00\s+AM\s+EST/);
});
test('half-hour zones and southern summer offsets use the viewer timezone', () => {
  assert.match(fixture(['2026-01-01T00:00:00Z'], 'Asia/Kolkata').times[0].textContent, /05:30:00\s+AM/);
  assert.match(fixture(['2026-01-01T00:00:00Z'], 'Pacific/Auckland').times[0].textContent, /01:00:00\s+PM/);
});
test('ambiguous, normalized and invalid dates retain explicit fallback text', () => {
  const f = fixture(['2026-11-22T01:00:00', '2026-02-30T00:00:00Z', 'invalid', '2026-01-01T24:00:00Z']);
  assert.ok(f.times.every(e => e.textContent === 'UTC fallback'));
});
test('unavailable Intl preserves UTC fallback without breaking the page', () => {
  const f = fixture(['2026-11-22T01:00:00Z'], 'America/New_York', true);
  assert.equal(f.times[0].textContent, 'UTC fallback');
  assert.equal(f.label.textContent, 'UTC fallback');
});
test('later component timestamps and changed datetime attributes are formatted', () => {
  const f = fixture([]);
  const added = f.element('2026-11-23T01:00:00Z');
  f.mutate([{ type: 'childList', addedNodes: [added] }]);
  assert.match(added.textContent, /08:00:00\s+PM\s+EST/);
  const changed = f.element('2026-11-23T02:00:00Z');
  f.mutate([{ type: 'attributes', target: changed }]);
  assert.match(changed.textContent, /09:00:00\s+PM\s+EST/);
});
test('returning to the page refreshes a changed system timezone', () => {
  const f = fixture(['2026-11-23T01:00:00Z']);
  f.setZone('Europe/London'); f.events.focus();
  assert.equal(f.label.textContent, 'Europe/London');
  assert.match(f.times[0].textContent, /Nov\s+23,\s+2026/);
  assert.match(f.times[0].textContent, /01:00:00\s+AM\s+GMT/);
});

test('a component rerender of fallback text is localized again without changing its instant', () => {
  const f = fixture(['2026-11-23T01:00:00Z']);
  const time = f.times[0];
  time.textContent = 'UTC fallback';
  f.mutate([{ type: 'childList', target: time, addedNodes: [{ nodeType: 3 }] }]);
  assert.match(time.textContent, /08:00:00\s+PM\s+EST/);
  assert.equal(time.getAttribute('datetime'), '2026-11-23T01:00:00Z');
});
