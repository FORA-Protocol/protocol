import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import { test } from 'node:test';
import { runInNewContext } from 'node:vm';

test('walkthrough selection updates examples, preserves controls, and never starts autoplay', () => {
  const element = () => ({
    innerHTML: '',
    attributes: {},
    classList: { toggle() {} },
    setAttribute(name, value) { this.attributes[name] = value; },
    addEventListener() {},
  });
  const buttons = Array.from({ length: 8 }, element);
  const steps = Array.from({ length: 6 }, () => ({
    ...element(),
    button: element(),
    querySelector() { return this.button; },
  }));
  const nodes = Object.fromEntries(['flowJson', 'archDetailInner', 'archStepsList', 'archStory', 'archTab0', 'archTab1'].map(id => [id, element()]));
  nodes.archStepsList.querySelectorAll = () => buttons;
  const context = {
    document: {
      getElementById: id => nodes[id],
      querySelectorAll: selector => selector === '.flow-step' ? steps : [],
    },
    window: { addEventListener() {} },
    IntersectionObserver: class { observe() {} },
    setInterval() { assert.fail('Walkthroughs must wait for user selection'); },
  };
  // Run the real inline script against only the DOM surface its controls use.
  const page = readFileSync(new URL('../src/pages/index.astro', import.meta.url), 'utf8');
  runInNewContext(page.match(/<script is:inline>([\s\S]*?)<\/script>/)[1], context);

  context.setActiveStep(5);
  assert.match(nodes.flowJson.innerHTML, /DisputeRequest/);
  assert.equal(steps[5].button.attributes['aria-pressed'], 'true');
  assert.equal(steps[0].button.attributes['aria-pressed'], 'false');
  context.setActiveStep(0);
  assert.match(nodes.flowJson.innerHTML, /WellKnownManifest/);

  context.switchScenario(1);
  const controls = nodes.archStepsList.innerHTML;
  context.setArchStep(5);
  assert.match(nodes.archDetailInner.innerHTML, /Exchange B/);
  assert.match(nodes.archDetailInner.innerHTML, /txn-comp-b2/);
  assert.equal(buttons[5].attributes['aria-pressed'], 'true');
  assert.equal(nodes.archStepsList.innerHTML, controls, 'Selecting a step must preserve its focused button');
  context.switchScenario(0);
  assert.equal(nodes.archTab0.attributes['aria-pressed'], 'true');
  assert.equal(nodes.archTab1.attributes['aria-pressed'], 'false');
  assert.equal(buttons[0].attributes['aria-pressed'], 'true');
  assert.match(nodes.archDetailInner.innerHTML, /403/);
});
