// Renders the placeholders that plugins/remark-mermaid.mjs leaves in a docs page, and
// renders them again when the reader switches theme.

let ids = 0;
let generation = 0;

export async function renderMermaid(boxes: HTMLElement[]) {
  if (boxes.length === 0) return;
  const { default: mermaid } = await import('mermaid');

  async function render() {
    const run = ++generation;
    const dark = document.documentElement.dataset.theme === 'dark';
    mermaid.initialize({ startOnLoad: false, theme: dark ? 'dark' : 'default' });
    for (const box of boxes) {
      const source = box.dataset.content;
      if (!source) continue;
      try {
        const { svg } = await mermaid.render(`mermaid-${++ids}`, source);
        if (run !== generation) return; // the theme changed again; the newer pass wins
        box.innerHTML = svg;
        box.dataset.status = 'rendered';
      } catch (error) {
        if (run !== generation) return;
        box.textContent = String(error);
        box.dataset.status = 'error';
      }
    }
  }

  await render();
  new MutationObserver(render).observe(document.documentElement, {
    attributes: true,
    attributeFilter: ['data-theme'],
  });
}
