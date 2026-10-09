#!/usr/bin/env bash
# Applies website/redirects.json to this Amplify app's custom rules.
#
# Runs from amplify.yml's postBuild phase, so it needs no credentials of its
# own: the Amplify build container already carries the app's AWS context and
# injects AWS_APP_ID and AWS_BRANCH. That is the whole reason this lives here
# rather than in a GitHub workflow — nothing has to be stored in the repository
# and the rules cannot drift from the deploy that shipped them.
#
# The IAM role the Amplify app builds under needs amplify:UpdateApp on itself.
# Until it does, this exits non-zero and the deploy fails loudly, which is the
# intended failure: a deploy that silently drops its redirects is the drift this
# is meant to prevent.
set -uo pipefail
cd "$(dirname "$0")/.."

RULES="website/redirects.json"

# Not an Amplify build (local, or a GitHub runner). Nothing to apply.
if [ -z "${AWS_APP_ID:-}" ]; then
  echo "apply-redirects: AWS_APP_ID unset — not an Amplify build, skipping"
  exit 0
fi

# Preview and feature-branch deploys share the app's rule set with production,
# so only the production branch is allowed to rewrite it.
if [ "${AWS_BRANCH:-}" != "main" ]; then
  echo "apply-redirects: branch '${AWS_BRANCH:-unset}' is not main — skipping"
  exit 0
fi

if [ ! -f "$RULES" ]; then
  echo "::error::apply-redirects: $RULES is missing"
  exit 1
fi

# Node, not python3: this runs inside Amplify's Node build image, where node is
# guaranteed and python3 is not.
count=$(node -e "const r=require('./$RULES'); if(!Array.isArray(r)) process.exit(1); console.log(r.length)") || {
  echo "::error::apply-redirects: $RULES is missing, malformed, or not a JSON array"
  exit 1
}

# update-app REPLACES the entire rule set rather than merging into it. An empty
# file would therefore delete every rule the app has, including any configured
# in the console before this file existed. Refuse instead: an empty file means
# nothing has been retired yet, so there is nothing to apply.
if [ "$count" -eq 0 ]; then
  echo "apply-redirects: no rules in $RULES — leaving the app's existing rules alone"
  exit 0
fi

echo "apply-redirects: applying $count rule(s) to app $AWS_APP_ID"
aws amplify update-app \
  --app-id "$AWS_APP_ID" \
  --custom-rules "file://$RULES" \
  --output text --query 'app.appId' || {
    echo "::error::apply-redirects: update-app failed. Does the Amplify service role have amplify:UpdateApp?"
    exit 1
  }
echo "apply-redirects: done"
