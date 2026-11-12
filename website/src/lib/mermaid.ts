// Renders the placeholders that plugins/remark-mermaid.mjs leaves in a docs page, in
// the site's own colors, and renders them again when the reader switches theme.
//
// Mermaid's `base` theme is the only one that takes `themeVariables`, so every color a
// diagram uses is set here, once for light and once for dark. The neutrals are the
// Starlight docs shell's own grays (`--sl-color-gray-*`, as hex, because Mermaid derives
// shades from these values and cannot read a CSS variable), so a diagram sits on the
// page like a code block does. Lines, arrows and notes take the brand accent from
// src/styles/brand.css, which is what marks a diagram as FORA's.
//
// Text is set in the docs body font.

import type { MermaidConfig } from 'mermaid';

const ACCENT = '#4f6df5'; // --accent in brand.css

type Palette = {
  bg: string; // page background (--sl-color-bg)
  node: string; // node and actor fill
  group: string; // subgraph and composite-state fill
  border: string; // node, actor and group borders
  lifeline: string; // sequence lifelines
  text: string; // node and message text (--sl-color-white: the strongest text)
  muted: string; // group titles, edge-label text
  line: string; // edges, arrows, messages
  noteBg: string;
  noteBorder: string;
};

// Hex of Starlight 0.38's --sl-color-* tokens (style/props.css), and the brand accent.
const LIGHT: Palette = {
  bg: '#ffffff',
  node: '#ffffff',
  group: '#f6f7f9', // gray-7
  border: '#888c96', // gray-4
  lifeline: '#c1c3c8', // gray-5
  text: '#17181c', // white (light mode)
  muted: '#555962', // gray-3
  line: ACCENT,
  noteBg: '#f1f3fe', // 8% accent on white
  noteBorder: '#c1ccfc', // 35% accent on white
};

const DARK: Palette = {
  bg: '#17181c', // black (dark mode)
  node: '#23262f', // gray-6
  group: '#1c1e24', // halfway from black to gray-6
  border: '#555962', // gray-4
  lifeline: '#353841', // gray-5
  text: '#edeef3', // gray-1
  muted: '#c1c3c8', // gray-2
  line: '#7d93f8', // accent lifted toward --accent-text (#9aaeff) to read on dark
  noteBg: '#212845', // 18% accent on black
  noteBorder: '#364794', // 55% accent on black
};

export function mermaidConfig(dark: boolean, fontFamily: string): MermaidConfig {
  const p = dark ? DARK : LIGHT;
  return {
    startOnLoad: false,
    theme: 'base',
    darkMode: dark,
    fontFamily,
    // Scoped to each diagram by Mermaid. Lines a touch heavier than its 1px, and the
    // state-diagram arrowhead, whose own rule targets an id Mermaid 11 no longer emits
    // (#statediagram-barbEnd), so it would otherwise stay black in both themes.
    themeCSS: `
      .flowchart-link, .transition, .messageLine0, .messageLine1, .relation { stroke-width: 1.5px; }
      marker[id$="barbEnd"] path { fill: ${p.line}; stroke: ${p.line}; }
    `,
    themeVariables: {
      darkMode: dark,
      fontFamily,
      background: p.bg,
      textColor: p.text,
      lineColor: p.line,

      primaryColor: p.node,
      primaryBorderColor: p.border,
      primaryTextColor: p.text,
      secondaryColor: p.noteBg,
      secondaryBorderColor: p.noteBorder,
      secondaryTextColor: p.text,
      tertiaryColor: p.group,
      tertiaryBorderColor: p.border,
      tertiaryTextColor: p.text,

      // flowchart
      mainBkg: p.node,
      nodeBorder: p.border,
      nodeTextColor: p.text,
      clusterBkg: p.group,
      clusterBorder: p.border,
      titleColor: p.muted,
      edgeLabelBackground: p.bg,

      // sequenceDiagram
      actorBkg: p.node,
      actorBorder: p.border,
      actorTextColor: p.text,
      actorLineColor: p.lifeline,
      signalColor: p.line,
      signalTextColor: p.text,
      labelBoxBkgColor: p.bg,
      labelBoxBorderColor: p.border,
      labelTextColor: p.text,
      loopTextColor: p.muted,
      noteBkgColor: p.noteBg,
      noteBorderColor: p.noteBorder,
      noteTextColor: p.text,
      activationBkgColor: p.group,
      activationBorderColor: p.border,
      sequenceNumberColor: '#ffffff',

      // stateDiagram-v2
      stateBkg: p.node,
      stateLabelColor: p.text,
      stateBorder: p.border,
      transitionColor: p.line,
      transitionLabelColor: p.muted,
      labelBackgroundColor: p.bg,
      compositeBackground: p.group,
      compositeTitleBackground: p.group,
      compositeBorder: p.border,
      altBackground: p.group,
      specialStateColor: p.text,
      innerEndBackground: p.border,
    },
  };
}

let ids = 0;
let generation = 0;

export async function renderMermaid(boxes: HTMLElement[]) {
  if (boxes.length === 0) return;
  const { default: mermaid } = await import('mermaid');

  async function render() {
    const run = ++generation;
    const dark = document.documentElement.dataset.theme === 'dark';
    mermaid.initialize(mermaidConfig(dark, getComputedStyle(document.body).fontFamily));
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
