# fora-protocol-sdk

FORA protocol SDK for Python. One distribution, the `fora_sdk` package, with two layers:

- the IO-free protocol mechanics: thumbprint, signed-URL verification, RFC 9421 request
  signing and verification, offer and acceptance signatures, canonicalization and
  cross-field validation;
- the IO tiers built on them: the key and endpoint resolvers (`fora_sdk.resolvers`) and
  the Connect-unary JSON client (`fora_sdk.client`, with `fora_sdk.sync` as its blocking
  facade).

The generated wire types are a separate distribution, `fora-protocol`: Pydantic v2
models at `wire.models` and the registered vocabulary at `vocab.*`. This package pins it
to its own version and installs it as a dependency.

```sh
pip install fora-protocol-sdk
```

Python: 3.11 or later. The package ships `py.typed`, so mypy reads its annotations.

`httpx` and `httpcore` are installed with every consumer, including one that uses only
the IO-free mechanics: keeping them non-optional is what makes their version ceilings,
which guard the resolvers' SSRF seam, bind every install.

```python
from fora_sdk.thumbprint import thumbprint
from fora_sdk.sync import Client
from wire.models import Offer
```

`fora-protocol` installs the top-level import packages `wire` and `vocab`, so it can
collide with another distribution that owns either name; install it into an environment
that does not. Its README explains the tradeoff. Source, tests and the release process
are in [FORA-Protocol/protocol](https://github.com/FORA-Protocol/protocol) under
`sdk/python` and `gen/python`. Licensed under Apache-2.0.
