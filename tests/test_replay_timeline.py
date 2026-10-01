from __future__ import annotations

import unittest
from decimal import Decimal

from incident_replay.timeline import (
    CalibrationPoint,
    EventPoint,
    build_timeline,
)


def point(arrival, source, sequence, clock, digest, received=None, device=None):
    return EventPoint(
        arrival_seq=arrival,
        source_id=source,
        sequence=sequence,
        kind="component_alarm",
        source_clock=clock,
        received_at=received or clock,
        content_digest=digest,
        device_ref=device,
    )


def cal(version, source, effective, offset):
    return CalibrationPoint(
        version=version, source_id=source, kind="offset",
        effective_at=effective, offset_ms=Decimal(offset), basis="test",
    )


class TimelineTests(unittest.TestCase):
    def test_deterministic_order_and_digest(self) -> None:
        events = [
            point(1, "s1", 1, "2026-10-01T00:00:00.500Z", "a" * 64),
            point(2, "s2", 1, "2026-10-01T00:00:00.300Z", "b" * 64),
        ]
        calibrations = [
            cal(1, "s1", "2026-10-01T00:00:00Z", "0"),
            cal(1, "s2", "2026-10-01T00:00:00Z", "120"),
        ]
        first = build_timeline(events, calibrations)
        second = build_timeline(list(events), list(calibrations))
        self.assertEqual(first, second)
        # 到达顺序保留为 1,2；校准顺序 s2(420ms) 先于 s1(500ms)。
        self.assertEqual(first["arrival_order"], [1, 2])
        self.assertEqual([row["arrival_seq"] for row in first["entries"]], [2, 1])
        conflict = [item for item in first["anomalies"] if item["code"] == "ordering_conflict"]
        self.assertTrue(conflict)

    def test_conflicting_duplicates_are_both_kept_and_flagged(self) -> None:
        events = [
            point(1, "s1", 7, "2026-10-01T00:00:00Z", "a" * 64),
            point(2, "s1", 7, "2026-10-01T00:00:00Z", "b" * 64),
        ]
        result = build_timeline(events, [])
        codes = {item["code"] for item in result["anomalies"]}
        self.assertEqual(codes, {"duplicate_sequence"})
        self.assertEqual(len(result["entries"]), 2)

    def test_identical_retransmit_flagged_as_duplicate_content(self) -> None:
        events = [
            point(1, "s1", 7, "2026-10-01T00:00:00Z", "a" * 64),
            point(2, "s1", 7, "2026-10-01T00:00:00Z", "a" * 64),
        ]
        result = build_timeline(events, [])
        self.assertEqual({item["code"] for item in result["anomalies"]}, {"duplicate_content"})

    def test_sequence_gap(self) -> None:
        events = [
            point(1, "s1", 1, "2026-10-01T00:00:00Z", "a" * 64),
            point(2, "s1", 3, "2026-10-01T00:00:02Z", "b" * 64),
        ]
        result = build_timeline(events, [])
        gaps = [item for item in result["anomalies"] if item["code"] == "sequence_gap"]
        self.assertEqual(len(gaps), 1)
        self.assertEqual(gaps[0]["sequence"], 2)

    def test_clock_drift_beyond_threshold(self) -> None:
        events = [
            point(1, "s1", 1, "2026-10-01T00:00:00Z", "a" * 64,
                  received="2026-10-01T00:00:01Z"),
            point(2, "s1", 2, "2026-10-01T00:00:00.100Z", "b" * 64,
                  received="2026-10-01T00:00:01.200Z"),
        ]
        result = build_timeline(
            events, [cal(1, "s1", "2026-10-01T00:00:00Z", "0")], Decimal("50")
        )
        drifts = [item for item in result["anomalies"] if item["code"] == "clock_drift"]
        self.assertEqual(len(drifts), 1)
        self.assertEqual(drifts[0]["residual_ms"], "-100")

    def test_uncalibrated_events_are_counted_not_dropped(self) -> None:
        events = [point(1, "s9", 1, "2026-10-01T00:00:00Z", "a" * 64)]
        result = build_timeline(events, [cal(1, "other", "2026-10-01T00:00:00Z", "0")])
        self.assertEqual(result["uncalibrated_count"], 1)
        self.assertIsNone(result["entries"][0]["calibrated_at"])


if __name__ == "__main__":
    unittest.main()
