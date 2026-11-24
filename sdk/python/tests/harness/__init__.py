"""The shared test code of the Python SDK suites, one module per responsibility.

``corpus`` locates and reads the conformance corpora and renders the outcome a replay
compares with; ``client`` holds the two client faces, the recording transport and the
fixed resolvers a client is configured with; ``replay`` holds the key resolver, replay
store and header bag a verify replay injects, and the reason check; ``loopback`` starts
the in-process servers and the client that reaches them; ``origin`` serves the
well-known documents the resolvers read.
"""
