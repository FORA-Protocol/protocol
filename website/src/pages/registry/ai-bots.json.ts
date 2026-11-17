// /registry/ai-bots.json: the AI bot list (src/data/ai-bots.ts) for tools that
// generate from it, such as the edge package and the publisher console.
import type { APIRoute } from 'astro';
import { AI_BOTS, CHECKED } from '../../data/ai-bots';

export const GET: APIRoute = () =>
  new Response(JSON.stringify({ checked: CHECKED, bots: AI_BOTS }, null, 2) + '\n', {
    headers: { 'Content-Type': 'application/json' },
  });
