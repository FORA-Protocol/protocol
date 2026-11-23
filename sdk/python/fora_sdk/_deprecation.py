"""The SDK's one way of deprecating an argument.

An argument deprecated within a major version keeps its place and its default in the
signature, because the API gate holds the signature to the last release's. Only the call
tells whether a caller passed it, so the warning comes from the call, not the default.
"""

from __future__ import annotations

import functools
import inspect
import warnings
from typing import TYPE_CHECKING, ParamSpec, TypeVar

if TYPE_CHECKING:
    from collections.abc import Callable

P = ParamSpec("P")
R = TypeVar("R")


def deprecated_arguments(*names: str) -> Callable[[Callable[P, R]], Callable[P, R]]:
    """Warn ``DeprecationWarning`` for each of ``names`` a call passes, whatever its value.

    A caller that passes an argument explicitly, even with its default value, is a caller
    the argument's removal will break, so the warning goes to every such call and to no
    call that omits it. The warning names the caller's line. The decorated function's
    signature and defaults are left as they are, and its body still decides what a value
    means.
    """

    def decorate(fn: Callable[P, R]) -> Callable[P, R]:
        signature = inspect.signature(fn)
        unknown = [n for n in names if n not in signature.parameters]
        if unknown:
            raise TypeError(f"{fn.__qualname__} has no parameter {unknown}")
        label = fn.__qualname__.removesuffix(".__init__")

        @functools.wraps(fn)
        def wrapper(*args: P.args, **kwargs: P.kwargs) -> R:
            passed = signature.bind_partial(*args, **kwargs).arguments
            for name in names:
                if name in passed:
                    warnings.warn(
                        f"{label}({name}=...) is deprecated, removed in 2.0",
                        DeprecationWarning,
                        stacklevel=2,
                    )
            return fn(*args, **kwargs)

        return wrapper

    return decorate
