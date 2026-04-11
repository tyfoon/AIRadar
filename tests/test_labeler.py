"""
test_labeler.py — self-running assertions for the labeler module.

No pytest dependency. Run with:
    python tests/test_labeler.py

Exits with status 0 on success, 1 on first failure with a clear message.
The labeler module is the heart of the multi-source service-identification
pipeline — every other component (DNS snooping, QUIC tailer, JA4 matching,
LLM classification) submits proposals through it. So it gets coverage
from a few angles before we wire anything else up:

  - empty input handling
  - single-proposal pass-through
  - tie-break by source weight (gold-standard always wins)
  - corroboration boost when two sources agree
  - dispute flagging when two sources disagree at near-equal score
  - low-confidence flagging
  - unknown labeler defaults safely (cannot outrank known labelers)
  - clamp on out-of-range confidence values

These are the invariants the rest of the system relies on. If any of
these break, the whole quality-of-information promise of the pipeline
breaks with them.
"""

import os
import sys
import traceback

# Make the parent directory importable so we can `import labeler`
# without installing the package.
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))

from labeler import (  # noqa: E402
    LabelProposal,
    LabelDecision,
    SOURCE_WEIGHTS,
    CONFIDENCE_FLOOR,
    AGREEMENT_BOOST,
    AGREEMENT_WINDOW,
    UNKNOWN_LABELER_WEIGHT,
    DETERMINISTIC_LABELERS,
    resolve,
)


# ---------------------------------------------------------------------------
# Tiny test runner — no pytest, just collect failures and report.
# ---------------------------------------------------------------------------

_failures: list[tuple[str, str]] = []
_passed = 0


def check(name: str, condition: bool, message: str = "") -> None:
    global _passed
    if condition:
        _passed += 1
        print(f"  ok   {name}")
    else:
        _failures.append((name, message))
        print(f"  FAIL {name}: {message}")


def run(test_func) -> None:
    print(f"\n{test_func.__name__}")
    try:
        test_func()
    except Exception as exc:
        _failures.append((test_func.__name__, f"raised {type(exc).__name__}: {exc}"))
        traceback.print_exc()


# ---------------------------------------------------------------------------
# Test cases
# ---------------------------------------------------------------------------

def test_empty_proposal_list_returns_no_primary():
    decision = resolve([])
    check("empty.primary_is_none", decision.primary is None)
    check("empty.not_disputed", not decision.is_disputed)
    check("empty.not_boosted", not decision.boosted)
    check("empty.use_for_primary_is_false", not decision.use_for_primary_label)


def test_single_proposal_wins_unconditionally():
    p = LabelProposal(labeler="sni_direct", service="youtube", category="streaming",
                      confidence=0.95, rationale="exact SNI match")
    decision = resolve([p])
    check("single.primary_set", decision.primary is not None)
    check("single.primary_service", decision.primary.service == "youtube")
    check("single.not_disputed", not decision.is_disputed)
    check("single.not_boosted", not decision.boosted)
    # 0.95 * 0.95 = 0.9025, well above floor (0.60)
    check("single.use_for_primary", decision.use_for_primary_label)


def test_gold_standard_overrules_lower_tier_on_disagreement():
    # sni_direct (0.95 weight) vs llm_inference (0.70 weight) disagreeing.
    # Both at 0.9 confidence: scores are 0.855 vs 0.63 → gap 0.225 (way above
    # AGREEMENT_WINDOW), so this is a clean win, NOT disputed.
    sni = LabelProposal("sni_direct", "youtube", "streaming", 0.9, "TLS SNI")
    llm = LabelProposal("llm_inference", "tiktok", "social", 0.9, "LLM guess")
    decision = resolve([sni, llm])
    check("gold_vs_llm.winner_is_sni", decision.primary.labeler == "sni_direct")
    check("gold_vs_llm.winner_service", decision.primary.service == "youtube")
    check("gold_vs_llm.not_disputed_clean_win", not decision.is_disputed)
    check("gold_vs_llm.both_proposals_kept",
          len(decision.proposals) == 2,
          f"expected 2 proposals in audit trail, got {len(decision.proposals)}")


def test_two_sources_agree_get_boosted():
    # DNS-correlation and JA4 both saying "youtube" — agreement boost.
    # Scores: 0.75 * 0.85 = 0.6375 vs 0.80 * 0.80 = 0.64 → gap 0.0025 (within window).
    dns = LabelProposal("dns_correlation", "youtube", "streaming", 0.85, "DNS hit")
    ja4 = LabelProposal("ja4_community_db", "youtube", "streaming", 0.80, "JA4 hash")
    decision = resolve([dns, ja4])
    check("agree.boosted_flag_set", decision.boosted)
    check("agree.winner_service", decision.primary.service == "youtube")
    check("agree.confidence_was_raised",
          decision.primary.confidence > 0.80,
          f"expected boosted confidence, got {decision.primary.confidence}")
    # Confidence cap at 1.0
    check("agree.confidence_cap_at_one", decision.primary.confidence <= 1.0)


def test_two_sources_disagree_close_score_disputed():
    # dns_correlation (0.75) and ja4_community_db (0.80) at high confidence
    # but disagreeing on the service. Scores 0.7125 vs 0.72 → gap 0.0075 → disputed.
    dns = LabelProposal("dns_correlation", "netflix", "streaming", 0.95, "DNS hit")
    ja4 = LabelProposal("ja4_community_db", "youtube", "streaming", 0.90, "JA4 hash")
    decision = resolve([dns, ja4])
    check("dispute.is_flagged", decision.is_disputed)
    check("dispute.winner_returned", decision.primary is not None)
    # JA4 has slightly higher effective score, so it wins despite the
    # dispute. The dispute flag is what matters — UI should show a warning.
    check("dispute.higher_score_wins", decision.primary.labeler == "ja4_community_db")


def test_low_confidence_winner_is_flagged_and_excluded():
    # ip_asn_heuristic (0.50) at 0.7 confidence → 0.35 effective, well below floor.
    weak = LabelProposal("ip_asn_heuristic", "discord", "gaming", 0.70, "ASN org match")
    decision = resolve([weak])
    check("low_conf.primary_set", decision.primary is not None)
    check("low_conf.is_low_confidence_flag", decision.is_low_confidence)
    check("low_conf.use_for_primary_false", not decision.use_for_primary_label)


def test_unknown_labeler_uses_safe_default_weight():
    # A labeler not in SOURCE_WEIGHTS (typo, future addition) MUST default
    # to UNKNOWN_LABELER_WEIGHT (0.5) and not magically outrank named ones.
    unknown = LabelProposal("future_gizmo", "youtube", "streaming", 1.0, "")
    sni = LabelProposal("sni_direct", "tiktok", "social", 0.9, "")
    decision = resolve([unknown, sni])
    # unknown effective: 0.5 * 1.0 = 0.5
    # sni      effective: 0.95 * 0.9 = 0.855
    check("unknown_labeler.sni_wins", decision.primary.labeler == "sni_direct")
    check("unknown_labeler.weight_is_default",
          unknown.source_weight == UNKNOWN_LABELER_WEIGHT)


def test_confidence_clamped_into_unit_interval():
    # Defensive: a labeler that submits confidence > 1.0 should not get
    # superpower scoring. Same for negative.
    overshoot = LabelProposal("sni_direct", "youtube", "streaming", 1.5, "")
    undershoot = LabelProposal("sni_direct", "youtube", "streaming", -0.3, "")
    check("clamp.high_capped_at_1",
          overshoot.effective_score == SOURCE_WEIGHTS["sni_direct"] * 1.0)
    check("clamp.negative_floored_at_0",
          undershoot.effective_score == 0.0)


def test_llm_cannot_overrule_direct_sni_when_both_high_confidence():
    # The whole point of the trust hierarchy: even when the LLM is "very
    # confident", it cannot beat a direct SNI observation.
    sni = LabelProposal("sni_direct", "youtube", "streaming", 0.85, "TLS SNI seen")
    llm = LabelProposal("llm_inference", "tiktok", "social", 1.0, "LLM very sure")
    decision = resolve([sni, llm])
    # sni: 0.95 * 0.85 = 0.8075
    # llm: 0.70 * 1.00 = 0.70
    # Gap: 0.1075 — well above window, clean win, not disputed.
    check("invariant.sni_wins_over_confident_llm",
          decision.primary.labeler == "sni_direct")
    check("invariant.not_disputed", not decision.is_disputed)


def test_proposals_returned_in_score_order():
    p1 = LabelProposal("ip_asn_heuristic", "discord", "gaming", 0.9, "")
    p2 = LabelProposal("sni_direct", "discord", "gaming", 0.9, "")
    p3 = LabelProposal("llm_inference", "discord", "gaming", 0.9, "")
    decision = resolve([p1, p2, p3])
    scores = [p.effective_score for p in decision.proposals]
    check("ordering.descending",
          scores == sorted(scores, reverse=True),
          f"got {scores}")
    check("ordering.first_is_sni", decision.proposals[0].labeler == "sni_direct")


def test_tier_gate_llm_cannot_outscore_ja4_via_high_confidence():
    """The exact hole the trust hierarchy was supposed to close, written
    out as a regression test:

      llm_inference at 0.70 weight × 0.95 confidence = 0.665 effective
      ja4_community_db at 0.80 weight × 0.70 confidence = 0.560 effective

    Pure score sort would give the win to the LLM. The tier gate fixes
    this: JA4 is deterministic, LLM is probabilistic, so LLM cannot win
    when any deterministic proposal exists, regardless of how confident
    the LLM is.
    """
    llm = LabelProposal("llm_inference", "tiktok", "social", 0.95, "LLM very sure")
    ja4 = LabelProposal("ja4_community_db", "youtube", "streaming", 0.70, "JA4 hash")
    decision = resolve([llm, ja4])
    check("tier_gate.ja4_wins_over_higher_score_llm",
          decision.primary.labeler == "ja4_community_db",
          f"expected ja4 to win, got {decision.primary.labeler} "
          f"(scores: llm={llm.effective_score:.3f}, ja4={ja4.effective_score:.3f})")
    check("tier_gate.winner_service", decision.primary.service == "youtube")
    # The LLM proposal is still in the audit trail — we want to see
    # later that the LLM disagreed, even though it didn't win.
    check("tier_gate.llm_in_audit_trail",
          any(p.labeler == "llm_inference" for p in decision.proposals))
    check("tier_gate.ja4_in_audit_trail",
          any(p.labeler == "ja4_community_db" for p in decision.proposals))


def test_tier_gate_probabilistic_only_still_wins_when_alone():
    """When NO deterministic proposal exists, the probabilistic tier
    must still be allowed to produce a winner. Otherwise the LLM and
    ip_asn_heuristic paths could never label anything, defeating Day 4.
    """
    llm = LabelProposal("llm_inference", "discord", "gaming", 0.90, "LLM guess")
    asn = LabelProposal("ip_asn_heuristic", "discord", "gaming", 0.85, "ASN org match")
    decision = resolve([llm, asn])
    check("prob_only.has_winner", decision.primary is not None)
    check("prob_only.llm_wins_on_score",
          decision.primary.labeler == "llm_inference",
          f"got {decision.primary.labeler}")
    # llm: 0.70 * 0.90 = 0.63 → above CONFIDENCE_FLOOR (0.60), usable
    check("prob_only.use_for_primary", decision.use_for_primary_label)


def test_tier_gate_dispute_logic_only_runs_within_winning_tier():
    """A probabilistic proposal must not be able to put a deterministic
    winner into 'disputed' state — that would be the LLM whispering in
    the operator's ear "but I think it's tiktok!" alongside a clean
    SNI match. Disputes should only fire between two deterministic
    proposals at near-equal score.
    """
    sni = LabelProposal("sni_direct", "youtube", "streaming", 0.85, "TLS SNI")
    llm = LabelProposal("llm_inference", "tiktok", "social", 1.0, "LLM very sure")
    decision = resolve([sni, llm])
    # Within the deterministic tier there is only sni → no runner-up,
    # so dispute logic cannot fire even though the LLM disagrees.
    check("tier_dispute.not_disputed_cross_tier", not decision.is_disputed)
    check("tier_dispute.sni_wins", decision.primary.labeler == "sni_direct")
    # Both proposals stay in the audit trail
    check("tier_dispute.both_in_audit", len(decision.proposals) == 2)


def test_tier_gate_constant_membership():
    """Sanity-check that the tier-gate constant matches the plan and
    nobody silently moved a probabilistic labeler into the deterministic
    set. If you change this set, you are changing the trust model — be
    sure that's what you mean.
    """
    expected_deterministic = {
        "manual_seed", "curated_v2fly", "sni_direct", "quic_sni_direct",
        "adguard_services", "ja4_community_db", "dns_correlation",
    }
    check("tier_constant.matches_expected",
          set(DETERMINISTIC_LABELERS) == expected_deterministic,
          f"got {sorted(DETERMINISTIC_LABELERS)}")
    # Things that MUST NOT be in the deterministic set
    check("tier_constant.llm_excluded",
          "llm_inference" not in DETERMINISTIC_LABELERS)
    check("tier_constant.ip_asn_excluded",
          "ip_asn_heuristic" not in DETERMINISTIC_LABELERS)


def test_agreement_boost_does_not_exceed_one():
    # If a proposal is already at confidence 1.0 and gets boosted, it
    # must NOT go above 1.0. The cap matters because effective_score
    # also clamps confidence — silently letting it overflow would mask
    # the protection.
    p1 = LabelProposal("dns_correlation", "youtube", "streaming", 1.0, "")
    p2 = LabelProposal("ja4_community_db", "youtube", "streaming", 0.95, "")
    decision = resolve([p1, p2])
    check("boost_cap.boosted", decision.boosted)
    check("boost_cap.at_or_below_one", decision.primary.confidence <= 1.0)


# ---------------------------------------------------------------------------
# Run all tests
# ---------------------------------------------------------------------------

if __name__ == "__main__":
    tests = [
        test_empty_proposal_list_returns_no_primary,
        test_single_proposal_wins_unconditionally,
        test_gold_standard_overrules_lower_tier_on_disagreement,
        test_two_sources_agree_get_boosted,
        test_two_sources_disagree_close_score_disputed,
        test_low_confidence_winner_is_flagged_and_excluded,
        test_unknown_labeler_uses_safe_default_weight,
        test_confidence_clamped_into_unit_interval,
        test_llm_cannot_overrule_direct_sni_when_both_high_confidence,
        test_proposals_returned_in_score_order,
        test_tier_gate_llm_cannot_outscore_ja4_via_high_confidence,
        test_tier_gate_probabilistic_only_still_wins_when_alone,
        test_tier_gate_dispute_logic_only_runs_within_winning_tier,
        test_tier_gate_constant_membership,
        test_agreement_boost_does_not_exceed_one,
    ]

    for t in tests:
        run(t)

    print()
    print("=" * 60)
    print(f"  {_passed} checks passed, {len(_failures)} failed")
    print("=" * 60)

    if _failures:
        print()
        for name, msg in _failures:
            print(f"  FAIL: {name} — {msg}")
        sys.exit(1)
    sys.exit(0)
