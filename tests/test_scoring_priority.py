"""Additional scoring priority checks."""

from tools.scoring import composite


def test_apache_kev_beats_unexploited_baseline():
    # Apache 2.4.49 on KEV with high EPSS should score higher than a clean host.
    assert composite(7.5, 0.97, True) > composite(0, 0, False)
