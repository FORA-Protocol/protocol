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
// Text is set at FONT_PX in the docs body font. A diagram wider than the content column
// scales down only as far as MIN_SCALE, which keeps rendered text at 14px or more; past
// that the diagram keeps its size and scrolls inside its own box, never the page.

import type { MermaidConfig } from 'mermaid';

const FONT_PX = 16;
const MIN_SCALE = 14 / FONT_PX;

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
  const font = `${FONT_PX}px`;
  return {
    startOnLoad: false,
    // Without this, a diagram that fails to parse also leaves Mermaid's "Syntax error"
    // graphic appended to <body>, below the footer, one more on every theme switch.
    // The error is shown in the diagram's own frame instead (renderMermaid).
    suppressErrorRendering: true,
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
      fontSize: font,
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
    flowchart: {
      useMaxWidth: true,
      curve: 'basis',
      padding: 12,
      nodeSpacing: 32,
      rankSpacing: 40,
      wrappingWidth: 160, // long labels wrap rather than widen the diagram
      subGraphTitleMargin: { top: 4, bottom: 8 }, // keeps a group's title off its first node
    },
    sequence: {
      useMaxWidth: true,
      actorFontSize: FONT_PX,
      messageFontSize: FONT_PX,
      noteFontSize: FONT_PX,
      // Not `wrap: true`. It would make most diagrams narrow enough for the column, but
      // Mermaid then splits any word wider than an actor with a hyphen, which garbles
      // identifiers such as BillingAdapter.Authorize, and squeezes a note that already
      // has <br/> into one actor's width, clipping its text. Breaking a long label is
      // left to each page, with <br/>.
      width: 120,
      actorMargin: 28,
      height: 52,
      boxMargin: 8,
      noteMargin: 10,
      messageMargin: 36,
      diagramMarginX: 8,
      diagramMarginY: 8,
      mirrorActors: true,
    },
    state: {
      useMaxWidth: true,
      padding: 8,
      nodeSpacing: 32,
      rankSpacing: 40,
    },
  };
}

// Keep text at or above 14px: let the SVG shrink to fit the column only down to
// MIN_SCALE of its natural width, then let its box scroll. Mermaid already caps the
// width at the natural size (`useMaxWidth`), so a small diagram is never enlarged.
function fit(box: HTMLElement) {
  const svg = box.querySelector('svg');
  const natural = svg?.viewBox.baseVal?.width;
  if (!svg || !natural) return;
  svg.style.minWidth = `${Math.ceil(natural * MIN_SCALE)}px`;
  overflow(box);
}

// A box that scrolls must be reachable by keyboard, and a focusable box needs a role
// and a name for a screen reader to announce it. Whether it scrolls changes with the
// page width, so this runs again whenever the box is resized.
function overflow(box: HTMLElement) {
  if (box.scrollWidth > box.clientWidth + 1) {
    box.tabIndex = 0;
    box.setAttribute('role', 'region');
    box.setAttribute('aria-label', label(box));
  } else {
    for (const name of ['tabindex', 'role', 'aria-label']) box.removeAttribute(name);
  }
  edges(box);
}

// Mark the side(s) of the frame with more diagram to scroll to, so the frame can fade
// that edge: overlay scrollbars (macOS, iOS, Android) give no other sign. Runs on
// scroll as well as on resize.
function edges(box: HTMLElement) {
  const frame = box.parentElement;
  if (!frame) return;
  const hidden = box.scrollWidth - box.clientWidth;
  frame.toggleAttribute('data-more-start', hidden > 1 && box.scrollLeft > 1);
  frame.toggleAttribute('data-more-end', hidden > 1 && box.scrollLeft < hidden - 1);
}

// "Diagram: <the heading the diagram sits under>", or plain "Diagram" before any heading.
function label(box: HTMLElement) {
  const headings = box.closest('.sl-markdown-content')?.querySelectorAll('h2, h3, h4, h5, h6') ?? [];
  let under: Element | undefined;
  for (const heading of headings) {
    if (heading.compareDocumentPosition(box) & Node.DOCUMENT_POSITION_FOLLOWING) under = heading;
    else break;
  }
  const title = under?.textContent?.trim();
  return title ? `Diagram: ${title}` : 'Diagram';
}

let ids = 0;
let generation = 0;

export async function renderMermaid(boxes: HTMLElement[]) {
  if (boxes.length === 0) return;
  const { default: mermaid } = await import('mermaid');

  // Each box scrolls inside a frame that does not, which carries the border and the
  // edge fades (MarkdownContent.astro).
  for (const box of boxes) {
    const frame = document.createElement('div');
    frame.className = 'mermaid-frame';
    box.replaceWith(frame);
    frame.append(box);
    box.addEventListener('scroll', () => edges(box), { passive: true });
  }

  async function render() {
    const run = ++generation;
    const dark = document.documentElement.dataset.theme === 'dark';
    mermaid.initialize(mermaidConfig(dark, getComputedStyle(document.body).fontFamily));
    for (const box of boxes) {
      const source = box.dataset.content;
      if (!source) continue;
      const id = `mermaid-${++ids}`;
      try {
        const { svg } = await mermaid.render(id, source);
        if (run !== generation) return; // the theme changed again; the newer pass wins
        box.innerHTML = svg;
        box.dataset.status = 'rendered';
        fit(box);
      } catch (error) {
        // Mermaid removes its scratch elements itself when errors are suppressed; this
        // makes sure none survives a failure it did not anticipate.
        document.getElementById(`d${id}`)?.remove();
        document.getElementById(id)?.remove();
        if (run !== generation) return;
        box.textContent = String(error);
        box.dataset.status = 'error';
      }
    }
  }

  await render();
  const resized = new ResizeObserver((entries) => {
    for (const entry of entries) overflow(entry.target as HTMLElement);
  });
  for (const box of boxes) resized.observe(box);
  new MutationObserver(render).observe(document.documentElement, {
    attributes: true,
    attributeFilter: ['data-theme'],
  });
}
