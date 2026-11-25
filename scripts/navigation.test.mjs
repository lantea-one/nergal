// Opening the mobile menu must not trap keyboard users on its toggle.
import assert from 'node:assert/strict';
import { readFile } from 'node:fs/promises';
import test from 'node:test';
import vm from 'node:vm';

const source = await readFile(new URL('../src/Nergal.Web/wwwroot/js/navigation.js', import.meta.url), 'utf8');

function fixture() {
  function element() {
    const attributes = new Map();
    const events = new Map();
    return {
      focused: false,
      getAttribute: key => attributes.get(key) ?? null,
      setAttribute: (key, value) => attributes.set(key, value),
      removeAttribute: key => attributes.delete(key),
      addEventListener: (key, action) => events.set(key, action),
      focus() { this.focused = true; },
      dispatch(key, event = {}) { events.get(key)?.(event); },
    };
  }
  const toggle = element();
  const sidebar = element();
  vm.runInNewContext(source, { document: {
    querySelector: () => toggle,
    getElementById: () => sidebar,
    documentElement: element(),
    addEventListener() {},
  } });
  return { toggle, sidebar };
}

for (const origin of ['toggle', 'sidebar']) {
  test(`Escape closes mobile navigation from the ${origin} and restores focus`, () => {
    const f = fixture();
    f.toggle.dispatch('click');
    assert.equal(f.toggle.getAttribute('aria-expanded'), 'true');
    assert.equal(f.sidebar.getAttribute('data-open'), 'true');
    f[origin].dispatch('keydown', { key: 'Escape' });
    assert.equal(f.toggle.getAttribute('aria-expanded'), 'false');
    assert.equal(f.sidebar.getAttribute('data-open'), null);
    assert.equal(f.toggle.focused, true);
  });
}

test('other keys do not dismiss navigation or steal focus', () => {
  const f = fixture();
  f.toggle.dispatch('click');
  f.sidebar.dispatch('keydown', { key: 'Tab' });
  assert.equal(f.toggle.getAttribute('aria-expanded'), 'true');
  assert.equal(f.toggle.focused, false);
});
