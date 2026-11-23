# What the language helpers (go-tools.sh, python-tools.sh and node-tools.sh) share:
# the message a gate prints when its tool is missing or is not the pinned version,
# and the step that runs a gate's tool through ratchet.py. Each helper sources this
# file; it is not run on its own.

# gate_refuse HELPER MESSAGE [INSTALL]: print MESSAGE and the install command on
# stderr, and return 1. INSTALL defaults to HELPER's own `install` command.
gate_refuse() {
  echo "$1: $2. Install it with: ${3:-scripts/gates/$1 install}" >&2
  return 1
}

# golangci_lint_cache: print golangci-lint's analysis cache directory for this
# checkout. With the shared default cache, a second checkout of the same code (a git
# worktree) is served the findings cached by the first, with paths that point into
# the first checkout, and every one of them differs from its baseline entry. Run
# from the repository root.
golangci_lint_cache() {
  local checkout_key
  checkout_key=$(pwd | cksum | cut -d ' ' -f 1)
  echo "${XDG_CACHE_HOME:-$HOME/.cache}/fora-go-gates/${checkout_key}"
}

# gate_ratchet GATE FORMAT BASELINE [record] [ARG...] -- CMD...: run CMD through
# ratchet.py for the gate script GATE (a path from the repository root), with FORMAT
# and BASELINE. A first ARG of `record` runs `ratchet.py record`, which shrinks the
# baseline; the other ARGs, such as --base-ref REF, go to ratchet.py, which compares
# against the baseline GATE named at REF.
gate_ratchet() {
  local gate=$1 format=$2 baseline=$3
  shift 3
  exec python3 scripts/gates/ratchet.py --format "$format" --baseline "$baseline" --gate "$gate" "$@"
}
