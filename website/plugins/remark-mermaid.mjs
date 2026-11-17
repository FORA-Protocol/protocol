// remark-mermaid turns each ```mermaid code block into an empty placeholder that the
// browser renders: <div class="mermaid" data-content="…source…" data-status="loading">.
//
// The rendering half lives in src/components/MarkdownContent.astro (the Starlight
// override) and src/lib/mermaid.ts (the brand theme). Both halves used to come from
// @pasqal-io/starlight-client-mermaid, which hardcodes Mermaid's `default` and `dark`
// themes with no option to change them. Owning the twenty lines of tagging here lets the
// site own the override as well, without the plugin warning that a second
// MarkdownContent override disables its own.
//
// The source goes into an attribute, not the element body, so the page never flashes
// raw Mermaid text and a re-render (on a theme switch) always starts from the original.

import { visit } from 'unist-util-visit';

const ESCAPES = { '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' };
const escapeHtml = (s) => s.replace(/[&<>"']/g, (c) => ESCAPES[c]);

export default function remarkMermaid() {
  return (tree) => {
    visit(tree, 'code', (node, index, parent) => {
      if (node.lang !== 'mermaid' || !parent) return;
      parent.children[index] = {
        type: 'html',
        value: `<div class="mermaid" data-content="${escapeHtml(node.value)}" data-status="loading"></div>`,
      };
    });
  };
}
