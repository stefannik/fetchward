"""Fork generation tracking and child-side runtime reinitialization.

Process-shared runtime/cache objects and caller-owned Session locks cannot be safely reused
after ``fork()``: a child may inherit a lock held by a parent thread that does not exist in
the child. Objects created in a parent carry a generation and fail before acquiring any lock
in a child. Child process globals are replaced with fresh instances; the parent's objects and
state are never touched.
"""

from __future__ import annotations

import os
from collections.abc import Callable

from .errors import ForkedProcessError

_generation = 0
_owner_pid = os.getpid()
_in_child = False
_callbacks: list[Callable[[], None]] = []


def register_child_reset(callback: Callable[[], None]) -> None:
    """Register a parent-module child reset. It must not acquire inherited locks."""
    _callbacks.append(callback)


def _after_fork_child() -> None:
    global _generation, _owner_pid, _in_child
    _generation += 1
    _owner_pid = os.getpid()
    _in_child = True
    # New objects only. Do not touch inherited lock objects or clear parent-visible state.
    for callback in tuple(_callbacks):
        callback()


if hasattr(os, "register_at_fork"):
    os.register_at_fork(after_in_child=_after_fork_child)


def generation() -> int:
    # Fallback for runtimes without register_at_fork: the first object/fetch check in the
    # child detects the PID change and performs the same lock-free reset before any lock.
    if os.getpid() != _owner_pid:
        _after_fork_child()
    return _generation


def is_forked_child() -> bool:
    _ = generation()
    return _in_child


def assert_generation(born: int, component: str) -> None:
    if born != generation():
        raise ForkedProcessError(
            f"{component} was created before fork; create a new Fetcher/Session in the child"
        )


__all__ = [
    "ForkedProcessError",
    "assert_generation",
    "generation",
    "is_forked_child",
    "register_child_reset",
]
