"""Unit tests for the composite risk scoring formula."""

from tools.scoring import composite, contextual_severity


class TestComposite:
    def test_kev_high_epss_ranks_above_unexploited_critical(self):
        # The key invariant: active exploitation beats raw severity.
        # Apache 2.4.49: CVSS 7.5, EPSS 0.97, KEV
        kev_score = composite(7.5, 0.97, kev=True)
        # Hypothetical unexploited critical: CVSS 9.8, EPSS 0.02, no KEV
        unexploited = composite(9.8, 0.02, kev=False)
        assert kev_score > unexploited, (
            f"KEV+high-EPSS score ({kev_score}) should beat unexploited critical ({unexploited})"
        )

    def test_zero_inputs_give_zero(self):
        assert composite(0.0, 0.0, kev=False) == 0

    def test_max_inputs_give_100(self):
        assert composite(10.0, 1.0, kev=True) == 100

    def test_kev_adds_significant_weight(self):
        without = composite(7.5, 0.5, kev=False)
        with_kev = composite(7.5, 0.5, kev=True)
        assert with_kev > without
        assert with_kev - without >= 15  # KEV contributes 20 points max

    def test_epss_dominates_cvss(self):
        # High EPSS, moderate CVSS should beat low EPSS, high CVSS.
        high_epss = composite(5.0, 0.90, kev=False)
        high_cvss = composite(9.8, 0.05, kev=False)
        assert high_epss > high_cvss

    def test_output_clamped_to_0_100(self):
        assert 0 <= composite(0.0, 0.0, kev=False) <= 100
        assert 0 <= composite(10.0, 1.0, kev=True) <= 100

    def test_score_is_integer(self):
        assert isinstance(composite(7.5, 0.97, kev=True), int)


class TestContextualSeverity:
    def test_kev_always_critical(self):
        # Even a low composite score with KEV should be critical.
        assert contextual_severity(10, kev=True) == "critical"

    def test_score_80_plus_is_critical(self):
        assert contextual_severity(80) == "critical"
        assert contextual_severity(95) == "critical"

    def test_score_60_79_is_high(self):
        assert contextual_severity(60) == "high"
        assert contextual_severity(79) == "high"

    def test_score_35_59_is_medium(self):
        assert contextual_severity(35) == "medium"
        assert contextual_severity(59) == "medium"

    def test_score_below_35_is_low(self):
        assert contextual_severity(0) == "low"
        assert contextual_severity(34) == "low"
