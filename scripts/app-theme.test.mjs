// Accessible action labels must reflect effective preferences after every navigation.
import assert from 'node:assert/strict';
import { readFile } from 'node:fs/promises';
import test from 'node:test';
import vm from 'node:vm';

const initial = await readFile(new URL('../src/Nergal.Web/wwwroot/js/theme.js', import.meta.url), 'utf8');
const ui = await readFile(new URL('../src/Nergal.Web/wwwroot/js/nergal.js', import.meta.url), 'utf8');

function fixture({ preference = null, defaultTheme = 'system', systemDark = false, denyStorage = false } = {}) {
  const attributes = new Map([['data-default-theme', defaultTheme]]);
  const handlers = new Map();
  const button = { textContent: 'Theme', setAttribute(key, value) { this[key] = value; } };
  const system = { matches: systemDark, addEventListener(key, callback) { handlers.set('system:' + key, callback); } };
  const storage = new Map(preference ? [['nergal-theme', preference]] : []);
  const context = vm.createContext({
    document: {
      documentElement: { getAttribute: key => attributes.get(key) ?? null, setAttribute: (key, value) => attributes.set(key, value) },
      querySelector: () => null,
      querySelectorAll: selector => selector === '[data-theme-toggle]' ? [button] : [],
      addEventListener(key, callback) { handlers.set(key, callback); },
    },
    window: { matchMedia: () => system },
    localStorage: {
      getItem(key) { if (denyStorage) throw new Error('Denied'); return storage.get(key); },
      setItem(key, value) { if (denyStorage) throw new Error('Denied'); storage.set(key, value); },
    },
  });
  vm.runInContext(initial, context);
  vm.runInContext(ui, context);
  return {
    attributes, button, storage,
    click(toggle = true) { handlers.get('click')({ target: { closest: () => toggle ? button : null } }); },
    systemChange(dark) { system.matches = dark; handlers.get('system:change')(); },
  };
}

test('saved light preference labels the action immediately and ignores unrelated clicks', () => {
  const f = fixture({ preference: 'light', systemDark: true });
  assert.equal(f.button.textContent, 'Dark mode');
  assert.equal(f.button['aria-label'], 'Switch to dark theme');
  f.click(false);
  assert.equal(f.attributes.get('data-theme'), 'light');
  f.click();
  assert.equal(f.attributes.get('data-theme'), 'dark');
  assert.equal(f.storage.get('nergal-theme'), 'dark');
  assert.equal(f.button['aria-label'], 'Switch to light theme');
});

test('system changes update labels until an explicit preference overrides them', () => {
  const f = fixture();
  assert.equal(f.button.textContent, 'Dark mode');
  f.systemChange(true);
  assert.equal(f.button.textContent, 'Light mode');
  assert.equal(f.attributes.has('data-theme'), false);
  f.click();
  assert.equal(f.attributes.get('data-theme'), 'light');
  f.systemChange(true);
  assert.equal(f.button['aria-label'], 'Switch to dark theme');
});

test('configured default and storage denial retain accessible switching', () => {
  const f = fixture({ defaultTheme: 'dark', denyStorage: true });
  assert.equal(f.button.textContent, 'Light mode');
  assert.doesNotThrow(() => f.click());
  assert.equal(f.button.textContent, 'Dark mode');
  assert.equal(f.attributes.get('data-theme'), 'light');
});
