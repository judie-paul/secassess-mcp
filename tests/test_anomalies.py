"""Anomaly detectors: each planted scenario is found, near-misses are not."""

from __future__ import annotations

import re

from datetime import datetime, timedelta, timezone

import config
from analysis import detectors
from api.data_access.json_repository import JsonRepository
from api.schemas.auth_logs import AuthEvent

START, END = config.DEFAULT_ASSESSMENT_START, config.DEFAULT_ASSESSMENT_END
T0 = datetime(2026, 10, 1, 7, 0, tzinfo=timezone.utc)  # Thursday 10:00 Nairobi

LOC = {
    "nairobi": ("Kenya", "KE", "Nairobi", -1.2921, 36.8219),
    "london": ("United Kingdom", "GB", "London", 51.5074, -0.1278),
    "mombasa": ("Kenya", "KE", "Mombasa", -4.0435, 39.6682),
}


def event(n, ts, user="u1", loc="nairobi", outcome="success", ip="192.0.2.1", records=None, user_type="human",
          privileged=False, asset="a-1"):
    country, code, city, lat, lon = LOC[loc]
    return AuthEvent(
        event_id=f"E{n:03d}", organization_id="org-x", timestamp=ts, username=user, user_type=user_type,
        privileged=privileged, source_ip=ip, country=country, country_code=code, city=city, latitude=lat, longitude=lon,
        outcome=outcome, auth_method="password", action="login", asset_id=asset, records_accessed=records,
    )


def baseline(count=6, loc="nairobi", user="u1", **kwargs):
    return [event(i, T0 - timedelta(days=count - i), user=user, loc=loc, **kwargs) for i in range(count)]


def demo_anomalies(anomaly_type=None):
    events = JsonRepository().auth_logs_for("org-001")
    return detectors.run_detectors(events, START, END, [anomaly_type] if anomaly_type else None)


# --- new country -------------------------------------------------------------


def test_new_country_detected_after_baseline():
    events = baseline() + [event(99, T0, loc="london")]
    found = detectors.detect_new_country(events, START, END)
    assert [a.supporting_event_ids for a in found] == [["E099"]]
    assert found[0].context["baseline_countries"] == ["KE"]


def test_new_country_needs_minimum_baseline():
    events = baseline(count=config.NEW_COUNTRY_MIN_BASELINE_EVENTS - 1) + [event(99, T0, loc="london")]
    assert detectors.detect_new_country(events, START, END) == []


def test_known_country_and_failed_login_not_flagged():
    events = baseline() + [event(98, T0, loc="mombasa"), event(99, T0, loc="london", outcome="failure")]
    assert detectors.detect_new_country(events, START, END) == []


def test_country_outside_baseline_window_counts_as_new():
    old = event(1, T0 - timedelta(days=config.NEW_COUNTRY_BASELINE_DAYS + 5), loc="london")
    events = [old] + baseline() + [event(99, T0, loc="london")]
    assert len(detectors.detect_new_country(events, START, END)) == 1


def test_demo_new_country_is_alice_in_brazil():
    (anomaly,) = demo_anomalies("new_country")
    assert anomaly.user == "alice.wanjiru" and anomaly.country == "BR"
    assert "BR" not in anomaly.context["baseline_countries"]


# --- impossible travel -----------------------------------------------------------


def test_impossible_travel_detected():
    events = [event(1, T0, loc="nairobi"), event(2, T0 + timedelta(hours=2), loc="london")]
    (anomaly,) = detectors.detect_impossible_travel(events, START, END)
    assert anomaly.supporting_event_ids == ["E001", "E002"]
    assert anomaly.context["implied_speed_kmh"] > config.IMPOSSIBLE_TRAVEL_MAX_SPEED_KMH


def test_plausible_travel_not_flagged():
    events = [event(1, T0, loc="nairobi"), event(2, T0 + timedelta(hours=11), loc="london")]
    assert detectors.detect_impossible_travel(events, START, END) == []


def test_short_distance_not_flagged():
    events = [event(1, T0, loc="nairobi"), event(2, T0 + timedelta(minutes=30), loc="mombasa")]
    assert detectors.detect_impossible_travel(events, START, END) == []


def test_demo_impossible_travel_is_carol():
    (anomaly,) = demo_anomalies("impossible_travel")
    assert anomaly.user == "carol.mendes"
    assert anomaly.context["from_location"] == "Nairobi, Kenya"
    assert anomaly.context["to_location"] == "London, United Kingdom"


# --- off-hours admin -------------------------------------------------------------


def test_off_hours_admin_detected_on_weekend_night():
    sunday_0140_local = datetime(2026, 10, 31, 22, 40, tzinfo=timezone.utc)
    events = [event(1, sunday_0140_local, user="admin1", user_type="admin", privileged=True)]
    (anomaly,) = detectors.detect_off_hours_admin(events, START, END)
    assert anomaly.context["local_time"] == "01:40"
    assert anomaly.context["timezone"] == config.ORGANIZATION_TIMEZONE


def test_working_hours_and_non_admins_not_flagged():
    night = datetime(2026, 10, 31, 22, 40, tzinfo=timezone.utc)
    events = [
        event(1, T0, user="admin1", user_type="admin", privileged=True),  # Thursday 10:00 local
        event(2, night, user="svc", user_type="service", privileged=True),  # service account
        event(3, night, user="bob"),  # non-privileged human
        event(4, night, user="admin1", user_type="admin", privileged=True, outcome="failure"),
    ]
    assert detectors.detect_off_hours_admin(events, START, END) == []


def test_working_hours_boundary_uses_org_timezone():
    # 15:00 UTC = 18:00 Nairobi = first off-hours minute (end is exclusive).
    weekday_1800_local = datetime(2026, 10, 1, 15, 0, tzinfo=timezone.utc)
    weekday_1759_local = weekday_1800_local - timedelta(minutes=1)
    admin = dict(user="admin1", user_type="admin", privileged=True)
    assert detectors.detect_off_hours_admin([event(1, weekday_1759_local, **admin)], START, END) == []
    assert len(detectors.detect_off_hours_admin([event(2, weekday_1800_local, **admin)], START, END)) == 1


def test_demo_off_hours_activity():
    found = demo_anomalies("off_hours_admin")
    assert sorted(a.user for a in found) == ["david.kim", "ops-admin", "ops-admin"]


# --- excessive failed logins -------------------------------------------------------


def failures(count, spacing_minutes, ip="203.0.113.9"):
    return [
        event(i, T0 + timedelta(minutes=i * spacing_minutes), outcome="failure", ip=ip) for i in range(count)
    ]


def test_failed_login_threshold_triggers():
    (anomaly,) = detectors.detect_excessive_failed_logins(failures(config.FAILED_LOGIN_THRESHOLD, 1), START, END)
    assert anomaly.context["failed_attempts"] == config.FAILED_LOGIN_THRESHOLD
    assert anomaly.context["successful_login_followed"] is False


def test_failed_logins_below_threshold_not_flagged():
    events = failures(config.FAILED_LOGIN_THRESHOLD - 1, 1)
    assert detectors.detect_excessive_failed_logins(events, START, END) == []


def test_failed_logins_spread_beyond_window_not_flagged():
    spacing = config.FAILED_LOGIN_WINDOW_MINUTES // (config.FAILED_LOGIN_THRESHOLD - 1) + 1
    events = failures(config.FAILED_LOGIN_THRESHOLD, spacing)
    assert detectors.detect_excessive_failed_logins(events, START, END) == []


def test_success_after_failures_is_reported():
    events = failures(6, 1) + [event(50, T0 + timedelta(minutes=8), ip="203.0.113.9")]
    (anomaly,) = detectors.detect_excessive_failed_logins(events, START, END)
    assert anomaly.context["successful_login_followed"] is True
    assert "E050" in anomaly.supporting_event_ids


def test_demo_failed_logins():
    found = demo_anomalies("excessive_failed_logins")
    assert sorted(a.asset_id for a in found) == ["a-ec2-001", "a-ec2-001", "a-iam-001"]
    # emma's four mistyped passwords stay below the threshold
    assert not any("emma" in a.user for a in found)


# --- unusual data access ---------------------------------------------------------


def test_unusual_data_access_detected():
    events = baseline(records=200) + [event(99, T0, records=20_000)]
    (anomaly,) = detectors.detect_unusual_data_access(events, START, END)
    assert anomaly.context["baseline_mean_records"] == 200


def test_spike_below_absolute_minimum_not_flagged():
    events = baseline(records=10) + [event(99, T0, records=config.UNUSUAL_ACCESS_MIN_RECORDS - 1)]
    assert detectors.detect_unusual_data_access(events, START, END) == []


def test_demo_unusual_access_is_alice_bulk_read():
    (anomaly,) = demo_anomalies("unusual_data_access")
    assert anomaly.user == "alice.wanjiru" and anomaly.context["records_accessed"] == 48_500


# --- general ----------------------------------------------------------------


def test_window_filters_anomalies():
    events = baseline() + [event(99, T0, loc="london")]
    assert detectors.detect_new_country(events, T0 + timedelta(seconds=1), END) == []


def test_demo_detects_every_type_and_ids_are_stable():
    found = demo_anomalies()
    assert {a.type for a in found} == set(config.ANOMALY_TYPES)
    assert len({a.anomaly_id for a in found}) == len(found)


def test_detection_is_reproducible_and_matches_snapshot():
    first = [a.model_dump(mode="json") for a in demo_anomalies()]
    second = [a.model_dump(mode="json") for a in demo_anomalies()]
    assert first == second
    snapshot = [a for a in JsonRepository().anomaly_snapshot()["anomalies"] if a["organization_id"] == "org-001"]
    assert snapshot
    assert first == snapshot


def test_supporting_events_exist():
    event_ids = {e.event_id for e in JsonRepository().auth_logs()}
    for anomaly in demo_anomalies():
        assert anomaly.supporting_event_ids and set(anomaly.supporting_event_ids) <= event_ids


def test_anomaly_ids_and_country_codes_use_report_format():
    for anomaly in demo_anomalies():
        assert re.fullmatch(r"A-[0-9A-F]{8}", anomaly.anomaly_id)
        assert re.fullmatch(r"[A-Z]{2}", anomaly.country)


def test_anomalies_are_newest_first():
    stamps = [a.timestamp for a in demo_anomalies()]
    assert stamps == sorted(stamps, reverse=True)
