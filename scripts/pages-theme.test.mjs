// Observable theme behavior, including storage denial; no browser or network required.
import assert from 'node:assert/strict';
import { readFile } from 'node:fs/promises';
import test from 'node:test';
import vm from 'node:vm';

const initial = await readFile(new URL('../pages/assets/theme.js', import.meta.url), 'utf8');
const portal = await readFile(new URL('../pages/assets/portal.js', import.meta.url), 'utf8');
function fixture({ preference = null, systemDark = false, denyStorage = false } = {}) {
  const attributes = new Map([['data-default-theme', 'system']]);
  const events = new Map();
  const button = { textContent: '', setAttribute(key, value) { this[key] = value; }, addEventListener(key, callback) { events.set(key, callback); } };
  const root = { getAttribute: key => attributes.get(key) ?? null, setAttribute: (key, value) => attributes.set(key, value), style: { setProperty() {} } };
  const system = { matches: systemDark, addEventListener() {} };
  const storage = new Map(preference ? [['nergal-theme', preference]] : []);
  const context = vm.createContext({
    document: { documentElement: root, querySelector: selector => selector === '[data-theme-toggle]' ? button : { addEventListener() {} }, querySelectorAll: () => [] },
    window: { matchMedia: () => system },
    localStorage: {
      getItem(key) { if (denyStorage) throw new Error('Denied'); return storage.get(key); },
      setItem(key, value) { if (denyStorage) throw new Error('Denied'); storage.set(key, value); },
    },
    ResizeObserver: class { observe() {} },
    location: { hash: '#/' },
  });
  vm.runInContext(initial, context);
  vm.runInContext(portal, context);
  return { attributes, button, storage, click: () => events.get('click')() };
}

test('saved light preference overrides a dark system and toggles persistently', () => {
  const f = fixture({ preference: 'light', systemDark: true });
  assert.equal(f.button.textContent, 'Dark mode');
  f.click();
  assert.equal(f.attributes.get('data-theme'), 'dark');
  assert.equal(f.storage.get('nergal-theme'), 'dark');
  assert.equal(f.button['aria-label'], 'Switch to light theme');
});
test('system dark preference is used before an explicit choice', () => {
  const f = fixture({ systemDark: true });
  assert.equal(f.attributes.has('data-theme'), false);
  assert.equal(f.button.textContent, 'Light mode');
  f.click();
  assert.equal(f.attributes.get('data-theme'), 'light');
});
test('storage denial preserves theme switching and accessible labels', () => {
  const f = fixture({ denyStorage: true });
  assert.equal(f.button['aria-label'], 'Switch to dark theme');
  assert.doesNotThrow(f.click);
  assert.equal(f.attributes.get('data-theme'), 'dark');
  assert.equal(f.button.textContent, 'Light mode');
});
