// Inline markup for resource pages that also appears inside HTML strings (a
// GlanceCard cell, a table cell, a step): a status tag and a citation marker.
// Their styles are global, in styles/landing.css ("Resource-page atoms"), so
// they look the same wherever a string lands. StatusTag.astro renders the same
// markup as statusTag(), so a tag in a component and a tag in a string match.
import { STATUS, type StatusKey } from '../data/content-marketplaces';

/** A status pill: Live, Beta, Closed beta, Pilot, Design, Roadmap, Not public. */
export function statusTag(status: StatusKey): string {
  return `<span class="status-tag status-tag--${status}">${STATUS[status].label}</span>`;
}

/**
 * Citation markers: cite(1, 2) gives "[1, 2]", each number linked to its
 * entry in the page's numbered SourceList (id="src-N").
 */
export function cite(...n: number[]): string {
  return `<span class="cite">[${n.map((i) => `<a href="#src-${i}">${i}</a>`).join(', ')}]</span>`;
}
