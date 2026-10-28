"""Per-attempt outcome mapping and requirement-first result selection.

Pure functions: no networking, so mixed attempt histories can be tested directly.
"""

from __future__ import annotations

from dataclasses import dataclass

from ._types import RESTRICTION_OUTCOMES, AttemptRecord, Outcome


def http_status_outcome(status: int) -> tuple[Outcome, str | None]:
    """Outcome for a final (non-followed) HTTP response status."""
    if status == 401:
        return Outcome.AUTH_REQUIRED, "http.auth_required"
    if status == 403:
        return Outcome.BLOCKED, "http.forbidden"
    if status == 429:
        return Outcome.RATE_LIMITED, "http.rate_limited"
    if status == 202:
        return Outcome.PARTIAL, "http.accepted_incomplete"
    if 200 <= status < 300:
        return Outcome.SUCCESS, None
    return Outcome.ERROR, "http.error_status"


@dataclass(frozen=True)
class Requirements:
    require_rendering: bool = False
    prefer_rendered: bool = False  # a permitted render was intended (auto fallback)


@dataclass(frozen=True)
class Selection:
    outcome: Outcome
    attempt_id: str | None
    reason: str
    rejected: tuple[tuple[str, str], ...] = ()  # (attempt id, its outcome)


def _satisfies(attempt: AttemptRecord, requirements: Requirements) -> bool:
    if attempt.outcome is not Outcome.SUCCESS:
        return False
    return not requirements.require_rendering or attempt.rendered is not None


def select(attempts: tuple[AttemptRecord, ...], requirements: Requirements) -> Selection:
    def rejected(chosen: str | None) -> tuple[tuple[str, str], ...]:
        return tuple((a.id, a.outcome.value) for a in attempts if a.id != chosen)

    if not attempts:
        return Selection(Outcome.ERROR, None, "selection.no_resource")

    satisfying = [a for a in attempts if _satisfies(a, requirements)]
    if satisfying:
        chosen = satisfying[0]
        if requirements.prefer_rendered:
            chosen = next((a for a in satisfying if a.rendered is not None), chosen)
        reason = "selection.requirements_satisfied" if chosen is attempts[-1] else "selection.retained_prior"
        return Selection(Outcome.SUCCESS, chosen.id, reason, rejected(chosen.id))

    restrictions = [a for a in attempts if a.outcome in RESTRICTION_OUTCOMES]
    if restrictions:
        chosen = restrictions[-1]
        return Selection(chosen.outcome, chosen.id, "selection.restriction", rejected(chosen.id))

    # Retained resource data that does not satisfy every requirement: a known limitation.
    partials = [a for a in attempts if a.has_resource and a.outcome in (Outcome.PARTIAL, Outcome.SUCCESS)]
    if partials:
        def rank(a: AttemptRecord) -> tuple[int, int]:
            rendered_ok = 1 if (requirements.require_rendering and a.rendered is not None) else 0
            return (rendered_ok, -attempts.index(a))

        chosen = max(partials, key=rank)
        return Selection(Outcome.PARTIAL, chosen.id, "selection.best_partial", rejected(chosen.id))

    chosen = attempts[-1]
    return Selection(Outcome.ERROR, chosen.id, "selection.no_resource", rejected(chosen.id))
