"""Pick the cheapest set of verifiers that closes an assurance gap (deterministic).

There are only a handful of verifiers, so the planner tries every subset and keeps the cheapest
one that closes every short dimension. Ties go to the subset with fewer people in it. If only a
human reviewer can close the gap, the plan is the human (the existing review queue).
"""

from __future__ import annotations

from collections.abc import Mapping, Sequence
from dataclasses import dataclass
from itertools import combinations


@dataclass(frozen=True)
class VerifierSpec:
    kind: str
    closes: Mapping[str, int]  # dimension -> level it can establish
    cost: int  # rough: milliseconds for machines, much more for people
    inline: bool  # runs now (machine) vs. waits for a person
    human: bool = False


DRY_RUN = VerifierSpec("dry_run", {"resource": 2, "effect": 1}, cost=5, inline=True)
USER_CONFIRMATION = VerifierSpec("user_confirmation", {"authorization": 2, "behaviour": 1}, cost=500, inline=False)
HUMAN_APPROVAL = VerifierSpec(
    "human_approval",
    {"identity": 1, "authorization": 2, "resource": 2, "behaviour": 1, "effect": 1},
    cost=10_000,
    inline=False,
    human=True,
)


@dataclass(frozen=True)
class Plan:
    steps: tuple[VerifierSpec, ...]

    @property
    def needs_human_review(self) -> bool:
        return any(s.human for s in self.steps)

    @property
    def inline(self) -> tuple[VerifierSpec, ...]:
        return tuple(s for s in self.steps if s.inline)

    @property
    def pending(self) -> tuple[VerifierSpec, ...]:
        return tuple(s for s in self.steps if not s.inline and not s.human)

    @property
    def kinds(self) -> list[str]:
        return [s.kind for s in self.steps]


def plan(gap: Mapping[str, int], available: Sequence[VerifierSpec]) -> Plan | None:
    """None when the gap is already closed. Falls back to human review if nothing else closes it."""
    if not gap:
        return None
    best: tuple[int, int, tuple[VerifierSpec, ...]] | None = None
    machine = [v for v in available if not v.human]
    for r in range(1, len(machine) + 1):
        for combo in combinations(machine, r):
            if all(any(v.closes.get(dim, 0) >= lvl for v in combo) for dim, lvl in gap.items()):
                key = (sum(v.cost for v in combo), sum(1 for v in combo if not v.inline), combo)
                if best is None or key[:2] < best[:2]:
                    best = key
    if best is not None:
        return Plan(best[2])
    return Plan((HUMAN_APPROVAL,))
