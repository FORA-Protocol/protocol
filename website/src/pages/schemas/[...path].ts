// /schemas/<path>: the profile files in the repository's schemas/ directory, byte for
// byte, for implementers that fetch them. For example
// /schemas/music/v1/music-v1.search-filters.schema.json, the fora-music-v1 search
// filter keys. The files are found by the glob, so a new one is published by adding it.
import type { APIRoute, GetStaticPaths } from 'astro';

const ROOT = '../../../../schemas/';
const files = import.meta.glob('../../../../schemas/**/*.json', { query: '?raw', import: 'default', eager: true });

export const getStaticPaths: GetStaticPaths = () =>
  Object.entries(files).map(([file, body]) => ({ params: { path: file.slice(ROOT.length) }, props: { body } }));

export const GET: APIRoute = ({ props }) =>
  new Response(props.body as string, { headers: { 'Content-Type': 'application/schema+json' } });
