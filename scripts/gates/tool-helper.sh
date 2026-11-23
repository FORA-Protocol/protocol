# What the language helpers of the gates share:
# the message a gate prints when its tool is missing or is not the pinned version,
# and the step that runs a gate's tool through ratchet.py. Each helper sources this
# file; it is not run on its own.

# gate_refuse HELPER MESSAGE [INSTALL]: print MESSAGE and the install command on
# stderr, and return 1. INSTALL defaults to HELPER's own `install` command.
gate_refuse() {
  echo "$1: $2. Install it with: ${3:-scripts/gates/$1 install}" >&2
  return 1
}

# gate_ratchet GATE FORMAT BASELINE [record] [ARG...] -- CMD...: run CMD through
# ratchet.py for the gate script GATE (a path from the repository root), with FORMAT
# and BASELINE. A first ARG of `record` runs `ratchet.py record`, which shrinks the
# baseline and carries the entries of moved findings; the other ARGs, such as
# --base-ref REF, go to ratchet.py, which compares against, or with `record` carries
# from, the baseline GATE named where HEAD left REF.
gate_ratchet() {
  local gate=$1 format=$2 baseline=$3
  shift 3
  exec python3 scripts/gates/ratchet.py --format "$format" --baseline "$baseline" --gate "$gate" "$@"
}
