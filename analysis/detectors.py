"""Anomaly detectors operating on authentication / access events.

Each detector is a pure function over a list of events (one organization) and
an analysis window. Baselines may look at events before the window start, but
only anomalies whose timestamp falls inside the window are returned.

Detections are signals for investigation, not proof of compromise; the
wording of `detail` reflects that.
"""

from __future__ import annotations

import hashlib
import math
from collections import defaultdict
from datetime import datetime, timedelta
from statistics import mean
from typing import Callable, Dict, Iterable, List, Optional, Sequence
from zoneinfo import ZoneInfo

import config
from api.schemas.anomalies import Anomaly
from api.schemas.auth_logs import AuthEvent

Detector = Callable[[Sequence[AuthEvent], datetime, datetime], List[Anomaly]]


def anomaly_id(anomaly_type: str, event_ids: Iterable[str]) -> str:
    """Stable ID derived from the anomaly type and its supporting events."""
    digest = hashlib.sha256(f"{anomaly_type}|{','.join(sorted(event_ids))}".encode()).hexdigest()
    return f"A-{digest[:8].upper()}"


def _sorted(events: Iterable[AuthEvent]) -> List[AuthEvent]:
    return sorted(events, key=lambda e: (e.timestamp, e.event_id))


def _in_window(ts: datetime, start: datetime, end: datetime) -> bool:
    return start <= ts <= end


def _make(
    anomaly_type: str,
    trigger: AuthEvent,
    supporting: Sequence[AuthEvent],
    detail: str,
    context: Dict,
    user: Optional[str] = None,
) -> Anomaly:
    ids = [e.event_id for e in _sorted(supporting)]
    return Anomaly(
        anomaly_id=anomaly_id(anomaly_type, ids),
        type=anomaly_type,
        user=user or trigger.username,
        asset_id=trigger.asset_id,
        country=trigger.country_code,
        timestamp=trigger.timestamp,
        detail=detail,
        organization_id=trigger.organization_id,
        confidence=config.ANOMALY_CONFIDENCE[anomaly_type],
        supporting_event_ids=ids,
        context=context,
    )


def haversine_km(lat1: float, lon1: float, lat2: float, lon2: float) -> float:
    p1, p2 = math.radians(lat1), math.radians(lat2)
    dp, dl = p2 - p1, math.radians(lon2 - lon1)
    a = math.sin(dp / 2) ** 2 + math.cos(p1) * math.cos(p2) * math.sin(dl / 2) ** 2
    return 2 * config.EARTH_RADIUS_KM * math.asin(math.sqrt(a))


def _successes_by_user(events: Sequence[AuthEvent]) -> Dict[str, List[AuthEvent]]:
    by_user: Dict[str, List[AuthEvent]] = defaultdict(list)
    for event in _sorted(events):
        if event.outcome == "success":
            by_user[event.username].append(event)
    return by_user


# ---------------------------------------------------------------------------
# 1. New country login
# ---------------------------------------------------------------------------


def detect_new_country(events: Sequence[AuthEvent], start: datetime, end: datetime) -> List[Anomaly]:
    baseline_span = timedelta(days=config.NEW_COUNTRY_BASELINE_DAYS)
    anomalies = []
    for username, user_events in _successes_by_user(events).items():
        for index, event in enumerate(user_events):
            if not _in_window(event.timestamp, start, end):
                continue
            baseline = [e for e in user_events[:index] if e.timestamp >= event.timestamp - baseline_span]
            if len(baseline) < config.NEW_COUNTRY_MIN_BASELINE_EVENTS:
                continue  # not enough history to make a claim either way
            seen = sorted({e.country_code for e in baseline})
            if event.country_code in seen:
                continue
            anomalies.append(
                _make(
                    "new_country",
                    event,
                    [event],
                    f"First login from this country in {config.NEW_COUNTRY_BASELINE_DAYS} days "
                    f"({event.city}, {event.country}; previously seen: {', '.join(seen)})",
                    {
                        "baseline_days": config.NEW_COUNTRY_BASELINE_DAYS,
                        "baseline_event_count": len(baseline),
                        "baseline_countries": seen,
                        "source_ip": event.source_ip,
                        "action": event.action,
                    },
                )
            )
    return anomalies


# ---------------------------------------------------------------------------
# 2. Impossible travel
# ---------------------------------------------------------------------------


def _duration(hours: float) -> str:
    minutes = round(hours * 60)
    return f"{minutes} minutes" if minutes < 120 else f"{hours:.1f} hours"


def detect_impossible_travel(events: Sequence[AuthEvent], start: datetime, end: datetime) -> List[Anomaly]:
    max_interval = timedelta(hours=config.IMPOSSIBLE_TRAVEL_MAX_INTERVAL_HOURS)
    anomalies = []
    for user_events in _successes_by_user(events).values():
        for previous, current in zip(user_events, user_events[1:]):
            if not _in_window(current.timestamp, start, end):
                continue
            interval = current.timestamp - previous.timestamp
            if interval > max_interval:
                continue
            distance = haversine_km(previous.latitude, previous.longitude, current.latitude, current.longitude)
            if distance < config.IMPOSSIBLE_TRAVEL_MIN_DISTANCE_KM:
                continue
            hours = interval.total_seconds() / 3600
            speed = math.inf if hours == 0 else distance / hours
            if speed <= config.IMPOSSIBLE_TRAVEL_MAX_SPEED_KMH:
                continue
            anomalies.append(
                _make(
                    "impossible_travel",
                    current,
                    [previous, current],
                    f"Login from {previous.city} and {current.city} {_duration(hours)} apart "
                    f"({distance:,.0f} km)",
                    {
                        "from_location": f"{previous.city}, {previous.country}",
                        "to_location": f"{current.city}, {current.country}",
                        "distance_km": round(distance, 1),
                        "interval_hours": round(hours, 2),
                        "implied_speed_kmh": None if math.isinf(speed) else round(speed, 1),
                        "max_plausible_speed_kmh": config.IMPOSSIBLE_TRAVEL_MAX_SPEED_KMH,
                    },
                )
            )
    return anomalies


# ---------------------------------------------------------------------------
# 3. Off-hours administrative activity
# ---------------------------------------------------------------------------


def is_working_time(ts: datetime, tz: ZoneInfo) -> bool:
    local = ts.astimezone(tz)
    return (
        local.weekday() in config.WORKING_DAYS
        and config.WORKING_HOURS_START <= local.hour < config.WORKING_HOURS_END
    )


def detect_off_hours_admin(events: Sequence[AuthEvent], start: datetime, end: datetime) -> List[Anomaly]:
    tz = ZoneInfo(config.ORGANIZATION_TIMEZONE)
    sessions: Dict[tuple, List[AuthEvent]] = defaultdict(list)
    for event in _sorted(events):
        if event.outcome != "success" or not _in_window(event.timestamp, start, end):
            continue
        if not (event.privileged and event.user_type in config.OFF_HOURS_USER_TYPES):
            continue
        if is_working_time(event.timestamp, tz):
            continue
        local_day = event.timestamp.astimezone(tz).date().isoformat()
        sessions[(event.username, event.asset_id, local_day)].append(event)

    anomalies = []
    for (_user, _asset, local_day), session in sessions.items():
        first = session[0]
        local = first.timestamp.astimezone(tz)
        actions = sorted({e.action for e in session})
        anomalies.append(
            _make(
                "off_hours_admin",
                first,
                session,
                f"Privileged {', '.join(actions)} at {local:%H:%M} local time on {local:%A}",
                {
                    "local_date": local_day,
                    "local_time": local.strftime("%H:%M"),
                    "timezone": config.ORGANIZATION_TIMEZONE,
                    "working_hours": f"{config.WORKING_HOURS_START:02d}:00-{config.WORKING_HOURS_END:02d}:00 Mon-Fri",
                    "actions": actions,
                    "event_count": len(session),
                },
            )
        )
    return anomalies


# ---------------------------------------------------------------------------
# 4. Excessive failed logins
# ---------------------------------------------------------------------------


def detect_excessive_failed_logins(events: Sequence[AuthEvent], start: datetime, end: datetime) -> List[Anomaly]:
    """Clusters of failures from one source IP against one asset inside the time window."""
    window = timedelta(minutes=config.FAILED_LOGIN_WINDOW_MINUTES)
    groups: Dict[tuple, List[AuthEvent]] = defaultdict(list)
    successes: Dict[tuple, List[AuthEvent]] = defaultdict(list)
    for event in _sorted(events):
        target = groups if event.outcome == "failure" else successes
        target[(event.source_ip, event.asset_id)].append(event)

    anomalies = []
    for (source_ip, asset_id), failures in groups.items():
        i = 0
        while i < len(failures):
            j = i
            while j < len(failures) and failures[j].timestamp - failures[i].timestamp <= window:
                j += 1
            cluster = failures[i:j]
            if len(cluster) < config.FAILED_LOGIN_THRESHOLD:
                i += 1
                continue
            last = cluster[-1]
            if _in_window(last.timestamp, start, end):
                usernames = sorted({e.username for e in cluster})
                span = (last.timestamp - cluster[0].timestamp).total_seconds() / 60
                followed = [
                    e
                    for e in successes.get((source_ip, asset_id), [])
                    if last.timestamp < e.timestamp <= last.timestamp + window
                ]
                outcome = "followed by a successful login" if followed else "no successful login followed"
                anomalies.append(
                    _make(
                        "excessive_failed_logins",
                        last,
                        cluster + followed[:1],
                        f"{len(cluster)} failed logins from {source_ip} in {span:.0f} minutes; {outcome}",
                        {
                            "source_ip": source_ip,
                            "failed_attempts": len(cluster),
                            "window_minutes": config.FAILED_LOGIN_WINDOW_MINUTES,
                            "threshold": config.FAILED_LOGIN_THRESHOLD,
                            "targeted_usernames": usernames,
                            "first_attempt": cluster[0].timestamp.isoformat().replace("+00:00", "Z"),
                            "successful_login_followed": bool(followed),
                        },
                        user=", ".join(usernames),
                    )
                )
            i = j
    return anomalies


# ---------------------------------------------------------------------------
# 5. Unusual data access
# ---------------------------------------------------------------------------


def detect_unusual_data_access(events: Sequence[AuthEvent], start: datetime, end: datetime) -> List[Anomaly]:
    baseline_span = timedelta(days=config.UNUSUAL_ACCESS_BASELINE_DAYS)
    groups: Dict[tuple, List[AuthEvent]] = defaultdict(list)
    for event in _sorted(events):
        if event.outcome == "success" and event.records_accessed is not None:
            groups[(event.username, event.asset_id)].append(event)

    anomalies = []
    for access_events in groups.values():
        for index, event in enumerate(access_events):
            if not _in_window(event.timestamp, start, end):
                continue
            baseline = [e for e in access_events[:index] if e.timestamp >= event.timestamp - baseline_span]
            if len(baseline) < config.UNUSUAL_ACCESS_MIN_BASELINE_EVENTS:
                continue
            baseline_mean = mean(e.records_accessed for e in baseline)
            threshold = max(baseline_mean * config.UNUSUAL_ACCESS_MULTIPLIER, config.UNUSUAL_ACCESS_MIN_RECORDS)
            if event.records_accessed <= threshold:
                continue
            ratio = event.records_accessed / baseline_mean if baseline_mean else math.inf
            anomalies.append(
                _make(
                    "unusual_data_access",
                    event,
                    [event],
                    f"Read {event.records_accessed:,} records, {ratio:,.0f}x the "
                    f"{config.UNUSUAL_ACCESS_BASELINE_DAYS}-day average of {baseline_mean:,.0f}",
                    {
                        "records_accessed": event.records_accessed,
                        "baseline_mean_records": round(baseline_mean, 1),
                        "baseline_event_count": len(baseline),
                        "threshold_records": round(threshold, 1),
                        "multiplier": config.UNUSUAL_ACCESS_MULTIPLIER,
                    },
                )
            )
    return anomalies


DETECTORS: Dict[str, Detector] = {
    "new_country": detect_new_country,
    "impossible_travel": detect_impossible_travel,
    "off_hours_admin": detect_off_hours_admin,
    "excessive_failed_logins": detect_excessive_failed_logins,
    "unusual_data_access": detect_unusual_data_access,
}


def run_detectors(
    events: Sequence[AuthEvent],
    start: datetime,
    end: datetime,
    anomaly_types: Optional[Sequence[str]] = None,
) -> List[Anomaly]:
    """Run the selected detectors and return anomalies, newest first (as in the report)."""
    selected = anomaly_types or config.ANOMALY_TYPES
    results: List[Anomaly] = []
    for name in config.ANOMALY_TYPES:
        if name in selected:
            results.extend(DETECTORS[name](events, start, end))
    return sorted(results, key=lambda a: (a.timestamp, a.type, a.anomaly_id), reverse=True)
