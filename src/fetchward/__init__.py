"""fetchward — acquire a web resource under an explicit policy, with evidence of how."""

__version__ = "0.4.0"

from ._async import AsyncFetcher, async_fetch
from ._cache import ResponseCache
from ._fetcher import Fetcher, fetch
from ._interactive import InteractionResult
from ._memory import AcquisitionMemory
from ._profile import BrowserProfile
from ._session import Session, SessionClosedError, SessionSnapshot
from ._types import (
    AttemptRecord,
    BudgetUsage,
    Diagnostics,
    EncodingRecord,
    Evidence,
    EvidenceCategory,
    FetchResult,
    Headers,
    Mode,
    Outcome,
    ReadinessResult,
    RedirectHop,
    RenderedRepresentation,
    RequestEvent,
    ResourceKind,
    SourceRepresentation,
)
from .errors import ConfigurationError, FetcherClosedError, ForkedProcessError, FetchwardError
from .policy import (
    AccessPolicy,
    AcquisitionPolicy,
    Budgets,
    DestinationPolicy,
    Readiness,
    SchedulingPolicy,
    StealthPolicy,
    TransportPolicy,
    TrustedOrigin,
)

__all__ = [
    "AccessPolicy",
    "AcquisitionMemory",
    "AcquisitionPolicy",
    "AsyncFetcher",
    "AttemptRecord",
    "BrowserProfile",
    "Budgets",
    "BudgetUsage",
    "ConfigurationError",
    "DestinationPolicy",
    "Diagnostics",
    "EncodingRecord",
    "Evidence",
    "EvidenceCategory",
    "FetchResult",
    "Fetcher",
    "FetcherClosedError",
    "ForkedProcessError",
    "Headers",
    "InteractionResult",
    "Mode",
    "FetchwardError",
    "Outcome",
    "Readiness",
    "ReadinessResult",
    "RedirectHop",
    "RenderedRepresentation",
    "RequestEvent",
    "ResourceKind",
    "ResponseCache",
    "SchedulingPolicy",
    "StealthPolicy",
    "Session",
    "SessionClosedError",
    "SessionSnapshot",
    "SourceRepresentation",
    "TransportPolicy",
    "TrustedOrigin",
    "async_fetch",
    "fetch",
]
