"""
labeler.py — central label-source priority and conflict resolution.

Every service-identification path in AI-Radar (sni_direct, dns_correlation,
quic_sni_direct, ja4_community_db, llm_inference, ...) submits its proposed
label here. This module:

  - Holds the canonical source-weight table (the "trust hierarchy")
  - Computes an effective score = source_weight * confidence
  - Resolves conflicts when multiple labelers propose different services
  - Persists each proposal as a LabelAttribution row for the audit trail
  - Returns the winning label (or None if all proposals fall below the
    confidence floor) to the caller, who writes it into detection_events
    via the existing recording path

The trust hierarchy is the most important policy in this entire pipeline.
The rule that LLM output (probabilistic) MUST stay below direct
deterministic matches (sni_direct, quic_sni_direct, dns_correlation) is
deliberate: a wrong label is more harmful than a missing one because it
poisons sessionization, AI recap, alerts, and the operator's mental model
of "what is happening on my network".

The module has zero dependencies on api.py or zeek_tailer — it's pure
labeling logic plus database writes against LabelAttribution. Both the
ingest pipeline (zeek_tailer) and the LLM classifier (api.py background
task) call into it.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Optional, TYPE_CHECKING

if TYPE_CHECKING:
    from sqlalchemy.orm import Session


# ---------------------------------------------------------------------------
# Trust hierarchy
# ---------------------------------------------------------------------------
# Higher = we trust this labeler more in the absence of other signal.
# Multiplied by the labeler's self-reported confidence to get an effective
# score in [0, 1].
#
# The exact numbers matter only relative to each other. The invariants we
# care about:
#
#   - manual_seed and curated_v2fly are the gold standard (someone wrote
#     them down deliberately) — they sit above everything probabilistic.
#
#   - sni_direct and quic_sni_direct are deterministic on-wire observations.
#     They sit just below the curated tier because Zeek's parser can
#     misclassify rarely, but ~always wins from probabilistic sources.
#
#   - adguard_services is curated by the AdGuard team but the entries are
#     coarser (~100 services, hundreds of domains) than our v2fly seed.
#
#   - ja4_community_db comes from FoxIO's open-source database. Trustworthy
#     for narrow library matches but less so for "generic Chrome on Android"
#     hits — the labeler dampens those itself before submitting.
#
#   - dns_correlation is heuristic (a guess based on which hostname the
#     client most recently resolved to this server IP). Right ~95% of the
#     time but can fail on shared CDNs and stale TTLs, so we keep it
#     below the direct on-wire signals.
#
#   - llm_inference is probabilistic by definition — we explicitly cap it
#     below every deterministic source so LLM cannot overrule on-wire data.
#
#   - ip_asn_heuristic is the bottom of the barrel: "this IP belongs to
#     ASN X, the ASN org name contains the word 'discord', so it's probably
#     Discord". Used only when nothing else fires.
SOURCE_WEIGHTS: dict[str, float] = {
    "manual_seed":         1.00,
    "curated_v2fly":       0.95,
    "sni_direct":          0.95,
    "quic_sni_direct":     0.90,
    "adguard_services":    0.85,
    "ja4_community_db":    0.80,
    "dns_correlation":     0.75,
    "llm_inference":       0.70,
    "ip_asn_heuristic":    0.50,
}

# Tier gate. The plan principle is: a probabilistic source must NEVER
# overrule a deterministic on-wire / curated observation, regardless of
# its self-reported confidence. The pure source_weight × confidence math
# does not enforce that on its own — e.g. llm_inference at 0.70 × 0.95
# = 0.665 outscores ja4_community_db at 0.80 × 0.70 = 0.56 even though
# JA4 is a deterministic TLS-fingerprint observation and the LLM is a
# guess. We fix this by segmenting proposals into two tiers in resolve():
#
#   - Deterministic tier: any one of these wins over any probabilistic
#     proposal, regardless of nominal confidence. The score-based sort
#     and agreement/dispute logic only operates within this tier when
#     it is non-empty.
#
#   - Probabilistic tier: only considered when zero deterministic
#     proposals exist for the same flow. Probabilistic proposals are
#     still kept in LabelDecision.proposals for the audit trail (so we
#     can later see what the LLM said about a flow that was actually
#     labeled by SNI), but they cannot win when a deterministic
#     proposal is present.
#
# Adding a new labeler? If it observes something on the wire or looks
# up a curated database, put it here. If it makes a probabilistic
# guess (LLM, heuristic, ML model), leave it out.
DETERMINISTIC_LABELERS: frozenset[str] = frozenset({
    "manual_seed",
    "curated_v2fly",
    "sni_direct",
    "quic_sni_direct",
    "adguard_services",
    "ja4_community_db",
    "dns_correlation",
})

# Effective scores below this threshold are not used as primary labels in
# downstream consumers (sessionization, AI recap, alerts). They still get
# logged as low-confidence attributions for review, so the operator can
# spot patterns where the pipeline is uncertain.
CONFIDENCE_FLOOR = 0.60

# When two proposals agree on the same service within this score window,
# boost the winner's confidence (capped at 1.0). Multi-source corroboration
# is one of the strongest quality signals we have — if both DNS-correlation
# and JA4 say "youtube" we should trust it more than either alone.
AGREEMENT_WINDOW = 0.05
AGREEMENT_BOOST = 1.10

# Default weight for an unknown labeler name. Conservative: well below
# every named source so a typo or new labeler can't accidentally outrank
# the established ones.
UNKNOWN_LABELER_WEIGHT = 0.50


# ---------------------------------------------------------------------------
# Public dataclasses
# ---------------------------------------------------------------------------

@dataclass
class LabelProposal:
    """One labeler's proposed service identification for a flow.

    Submitted by an ingest path (e.g. dns_tailer when it makes a DNS
    correlation match) to labeler.resolve(). The labeler is identified
    by name (string key into SOURCE_WEIGHTS) so this dataclass stays
    serializable and dependency-free.
    """

    labeler: str
    service: str
    category: str
    confidence: float       # labeler's self-reported confidence in [0, 1]
    rationale: str = ""

    @property
    def source_weight(self) -> float:
        return SOURCE_WEIGHTS.get(self.labeler, UNKNOWN_LABELER_WEIGHT)

    @property
    def effective_score(self) -> float:
        # Clamp confidence into [0, 1] defensively — labelers should not
        # send out-of-range values but we'd rather be safe than have a
        # rogue 1.5 confidence outrank everything.
        c = max(0.0, min(1.0, self.confidence))
        return self.source_weight * c


@dataclass
class LabelDecision:
    """Result of resolving a list of LabelProposals."""

    primary: Optional[LabelProposal]    # the winner, or None if no proposals
    is_low_confidence: bool             # True if best proposal < CONFIDENCE_FLOOR
    is_disputed: bool                   # True if two near-equal proposals disagree
    boosted: bool                       # True if confidence was boosted by agreement
    proposals: list[LabelProposal] = field(default_factory=list)  # all, in score order

    @property
    def use_for_primary_label(self) -> bool:
        """Should the winner be written to detection_events.ai_service?

        We exclude:
          - empty results (nothing to use)
          - low-confidence winners (use for audit only, not for sessions)

        Disputed winners ARE used (the higher score wins) but flagged so
        the UI can show a warning badge and the operator can review.
        """
        return self.primary is not None and not self.is_low_confidence


# ---------------------------------------------------------------------------
# Resolution algorithm
# ---------------------------------------------------------------------------

def resolve(proposals: list[LabelProposal]) -> LabelDecision:
    """Pick a winner from a list of proposals using the trust hierarchy.

    Conflict resolution rules (in order):

      1. Empty list → no decision.
      2. **Tier gate.** Segment proposals into deterministic vs
         probabilistic (DETERMINISTIC_LABELERS). If at least one
         deterministic proposal exists, the candidate set for the
         winner is the deterministic subset only — probabilistic
         proposals are kept in the audit trail but cannot win. This
         enforces the "deterministic on-wire observation always
         overrules a probabilistic guess" principle without depending
         on the source_weight × confidence math working out (it
         doesn't, on its own — see the note above DETERMINISTIC_LABELERS).
      3. Sort the candidate set by effective_score descending. Highest
         is the candidate winner.
      4. If the runner-up agrees on the same service AND is within
         AGREEMENT_WINDOW of the winner's score → corroboration. The winner's
         confidence is multiplied by AGREEMENT_BOOST (capped at 1.0) and the
         decision is marked boosted=True.
      5. If the runner-up disagrees AND is within AGREEMENT_WINDOW → dispute.
         The winner is still returned (so we never silently drop a label),
         but is_disputed=True so the UI / observability layer can flag it.
      6. If the winner's effective score is below CONFIDENCE_FLOOR, return
         it but mark is_low_confidence=True. Downstream consumers should
         use LabelDecision.use_for_primary_label to skip these for live
         labeling and only treat them as audit-trail data.
    """
    if not proposals:
        return LabelDecision(primary=None, is_low_confidence=False,
                             is_disputed=False, boosted=False, proposals=[])

    # Tier gate: when any deterministic proposal exists, only those are
    # candidates for the winner. Probabilistic proposals are still
    # included in the full audit trail (decision.proposals), but they
    # never enter the agreement/dispute/score-sort logic that picks
    # the primary label.
    deterministic = [p for p in proposals if p.labeler in DETERMINISTIC_LABELERS]
    candidates = deterministic if deterministic else proposals

    sorted_candidates = sorted(candidates, key=lambda p: p.effective_score, reverse=True)
    winner = sorted_candidates[0]

    boosted = False
    is_disputed = False

    if len(sorted_candidates) >= 2:
        runner_up = sorted_candidates[1]
        score_diff = winner.effective_score - runner_up.effective_score
        same_label = (winner.service == runner_up.service)

        if same_label and score_diff <= AGREEMENT_WINDOW:
            # Multi-source agreement — boost the winner's confidence.
            new_conf = min(winner.confidence * AGREEMENT_BOOST, 1.0)
            winner = LabelProposal(
                labeler=winner.labeler,
                service=winner.service,
                category=winner.category,
                confidence=new_conf,
                rationale=(winner.rationale or "").rstrip()
                          + f" [boosted by {runner_up.labeler}]",
            )
            boosted = True
        elif (not same_label) and score_diff <= AGREEMENT_WINDOW:
            # Two near-equal proposals disagree on the service. Winner
            # still wins (deterministic order) but the result is flagged.
            is_disputed = True

    is_low_confidence = winner.effective_score < CONFIDENCE_FLOOR

    # Audit trail: full proposals list, sorted by effective_score, INCLUDING
    # probabilistic ones that were tier-gated out. This is what
    # persist_attributions writes to label_attributions, so the operator
    # can later see "the LLM also weighed in on this flow but was
    # overruled by SNI / JA4 / DNS correlation".
    full_audit_trail = sorted(proposals, key=lambda p: p.effective_score, reverse=True)

    return LabelDecision(
        primary=winner,
        is_low_confidence=is_low_confidence,
        is_disputed=is_disputed,
        boosted=boosted,
        proposals=full_audit_trail,
    )


# ---------------------------------------------------------------------------
# Persistence: write the audit trail
# ---------------------------------------------------------------------------

def persist_attributions(
    db_session: "Session",
    detection_event_id: int,
    decision: LabelDecision,
    commit: bool = False,
) -> None:
    """Write all proposals as LabelAttribution rows for the audit trail.

    Called after a detection_event has been created (so we have its ID).
    Every proposal — including losing ones — is persisted so we can later
    debug why a particular label won and trace decisions back to their
    source labeler.

    The winning proposal gets is_winner=True, exactly one row per decision.
    Losing proposals get is_winner=False. Low-confidence and disputed
    decisions are still persisted in full so the operator dashboard can
    surface them.

    The caller decides whether to commit() — by default we add+flush only,
    so the caller can batch this with the detection_event insert in a
    single transaction. Set commit=True for standalone use (tests, batch
    backfill).
    """
    # Lazy import to keep this module dependency-free at import time.
    # database.py imports labeler indirectly via api.py, and we don't
    # want a circular import at startup.
    from database import LabelAttribution

    if decision.primary is None:
        return

    now = datetime.now(timezone.utc)
    winner_id = id(decision.primary)  # object identity to flag the winner

    for prop in decision.proposals:
        is_winner = (id(prop) == winner_id) or (
            prop.labeler == decision.primary.labeler
            and prop.service == decision.primary.service
        )
        db_session.add(LabelAttribution(
            detection_event_id=detection_event_id,
            labeler=prop.labeler,
            proposed_service=prop.service,
            proposed_category=prop.category,
            effective_score=prop.effective_score,
            rationale=prop.rationale or None,
            is_winner=is_winner,
            created_at=now,
        ))

    if commit:
        db_session.commit()


# ---------------------------------------------------------------------------
# Convenience: one-shot resolve + persist
# ---------------------------------------------------------------------------

def resolve_and_persist(
    db_session: "Session",
    detection_event_id: int,
    proposals: list[LabelProposal],
    commit: bool = False,
) -> LabelDecision:
    """Resolve a set of proposals and immediately persist the audit trail.

    Returns the LabelDecision so the caller can also update the
    detection_event row with the winner's service/category if
    decision.use_for_primary_label is True.
    """
    decision = resolve(proposals)
    if decision.primary is not None:
        persist_attributions(db_session, detection_event_id, decision, commit=commit)
    return decision
