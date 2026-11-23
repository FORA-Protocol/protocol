# ADR-003: How the SDK test suites are written

Status: Accepted. The duplication gate enforces rule 5 for textual copies;
reviewers enforce the rest.

## Context

The SDK suites are the evidence that the three SDKs behave as specified. Review
found tests that prove less than they claim:

- negative tests that pass for any refusal, including one the code under test did
  not make;
- replays that call a private function, or a copy of one, instead of the public
  API;
- tests that read a captured request without asserting that one was sent;
- the same signer, transport and resolver written again in each test file, with
  the copies already drifting apart;
- test-only switches in the SDK that let a test relax a check.

## Decision

1. A test drives the public API, the one a user calls. It may observe through an
   injected collaborator (a client, resolver, clock or key), never through a
   private function.
2. No test-only switch exists in the SDK: no environment variable, package
   variable, build-tag branch, option or field that exists so a test can relax a
   check, exported or not. A parameter that production code never sets is such a
   switch. A test that needs different behavior injects its own collaborator
   through the public API.
3. Every behavior that can fail has a negative test, and the test asserts the
   refusal reason.
4. A test is shown to pass for the right reason: its author breaks the code in
   each way the test claims to catch and sees it fail each time.
5. Shared test code lives in one harness per language, split into modules by
   responsibility when the file-length limit requires it. A test file imports
   it and the SDK's own codecs; it does not define its own copy.
6. A test asserts each precondition before the step that depends on it, and
   asserts that a step happened before it reads the step's result.
7. A comment or docstring in a test states only what the test checks.

## Consequences

- A test that cannot be written without a switch shows a missing injection point
  in the public API. The fix is that injection point, or dropping the case and
  recording why.
- The harness module grows; test files shrink.
- Dropped case: the Python and TypeScript tests that a redirect to a reserved
  address in the middle of a chain is refused. Their first hop had to reach a
  loopback origin through the address guard itself, which only a patched
  address classifier allowed. Each SDK follows a redirect with the same guarded
  client or dispatcher that made the first request, so every hop dials through
  the same address guard, and the shared address corpus is replayed through the
  public guarded client of each SDK; that replay is what pins the refusal.
