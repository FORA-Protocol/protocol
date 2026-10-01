# Retiring a URL

The site's build already refuses to ship a link that points nowhere. What it
cannot see is a link held by somebody else — a post, a partner's page, a search
index, a message from last year. Rename a slug and every one of those breaks,
and nothing in this repository notices.

So `website/routes.txt` records every URL the site serves, and CI compares it
against the copy on `main`. A URL that stops answering has to be redirected.

## Renaming a page

The cheapest fix is not to. A page's URL and its title are independent: change
`title` in the frontmatter and the label in the sidebar, and leave the file name
alone. A reader sees the new name, an old link keeps working, and there is no
redirect to maintain. Prefer this.

## When the URL really has to change

1. Move the page and update the sidebar entry in `website/astro.config.mjs`.
2. Add a rule to `website/redirects.json`:

   ```json
   [
     {
       "source": "/getting-started/old-page/",
       "target": "/getting-started/new-page/",
       "status": "301"
     }
   ]
   ```

   Use `301` for a move that is permanent, which is nearly always. The file is
   Amplify's own custom-rules format and is applied verbatim.

3. Rebuild and regenerate the manifest, then commit both:

   ```sh
   cd website && npm run build && npm run routes
   ```

4. Check it locally before pushing:

   ```sh
   npm run routes:check
   ```

## Deleting a page

Same thing. The page is gone, so point the old URL at whatever now covers the
subject — a replacement page, or the section index. Deleting is not a reason to
skip the redirect: the outside link exists either way, and a reader who followed
it deserves better than a 404.

If the page genuinely has no successor, redirect to the nearest parent section
and say so in the pull request, so the reviewer can disagree.

## How the rules reach production

`amplify.yml` runs `scripts/apply-redirects.sh` in its `postBuild` phase. The
Amplify build container already holds the app's AWS context and injects
`AWS_APP_ID` and `AWS_BRANCH`, so nothing is stored in this repository and the
rules cannot drift from the deploy that shipped them. The script applies only
from `main`, and skips anywhere else.

Two things to know:

- **`update-app` replaces the whole rule set.** It does not merge. Once this
  file is live it is the only source of Amplify redirects, so any rule created
  in the console must be copied into it first or it will be lost on the next
  deploy. The script refuses to apply an empty file for exactly this reason.
- **The Amplify service role needs `amplify:UpdateApp`** on the app. Until it
  does, the deploy fails loudly rather than shipping without the redirects.

## What the gate does not do

It compares against `main` only, so it protects URLs that have shipped. It says
nothing about a URL invented and retired inside one branch, which is correct —
nobody outside could have linked to it.

It also cannot know whether a redirect target is the *right* one. That is the
reviewer's job, which is why the manifest is committed: the removed URL appears
in the diff beside the change that removed it.
