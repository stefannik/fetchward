"""Exceptions for API misuse. Expected acquisition failures are results, not exceptions."""


class FetchwardError(Exception):
    """Base class for fetchward exceptions."""


class ConfigurationError(FetchwardError, ValueError):
    """Invalid or contradictory configuration, raised before any DNS or network work."""


class FetcherClosedError(FetchwardError, RuntimeError):
    """A closed :class:`~fetchward.Fetcher` was used."""


class ForkedProcessError(FetchwardError, RuntimeError):
    """An object created before ``fork()`` was used in the child process.

    Create a new Fetcher/Session in the child. Browser mode is additionally unsupported in a
    forked child because Playwright/Chromium runtime state and inherited sockets are not safe
    to reuse.
    """
