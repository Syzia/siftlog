"""HTTP API over the event and alert store.

Security posture, deliberately small:

* **Every route except /health needs a bearer token**, compared in constant time.
* **Nothing is trusted on the way in.** Query parameters are typed and bounded,
  and every value reaches SQLite as a bound parameter.
* **Responses are JSON only.** Usernames and raw log lines are attacker-controlled
  text; they are returned as data, and a client that renders them must escape them.
* **No TLS here.** The CLI binds to loopback by default. Anything beyond that
  belongs behind a reverse proxy that terminates TLS.

Each request opens its own SQLite connection inside the handler. FastAPI runs
plain ``def`` handlers in a thread pool, and a connection opened in one thread
must not be used from another.
"""
# No `from __future__ import annotations` here: FastAPI resolves handler signatures
# at import time, and the dependencies below are local to create_app().
import hmac
from datetime import datetime, timezone
from typing import Any, Dict, List, Literal, Optional, Sequence

from fastapi import APIRouter, Depends, FastAPI, HTTPException, Path, Query, Request
from fastapi.responses import RedirectResponse
from fastapi.security import HTTPAuthorizationCredentials, HTTPBearer
from pydantic import BaseModel, ConfigDict, Field

from siftlog.engine.rules import SEVERITIES, Rule
from siftlog.events import Event
from siftlog.store import STATUSES, EventStore, StoredAlert

Status = Literal["open", "ack", "closed"]
Severity = Literal["low", "medium", "high", "critical"]
assert set(Status.__args__) == set(STATUSES) and set(Severity.__args__) == set(SEVERITIES)  # type: ignore[attr-defined]

MAX_PAGE = 1000


class EventOut(BaseModel):
    id: str
    timestamp: datetime
    source: str
    event_type: str
    src_ip: Optional[str]
    username: Optional[str]
    host: Optional[str]
    outcome: Optional[str]
    count: int
    geo: Optional[Dict[str, Any]]
    extra: Dict[str, Any]
    raw: str
    source_id: str
    offset: int


class EventPage(BaseModel):
    total: int
    events: List[EventOut]


class AlertOut(BaseModel):
    id: str
    rule_id: str
    title: str
    severity: str
    group_key: str
    first_seen: datetime
    last_seen: datetime
    event_count: int
    distinct_count: Optional[int]
    evidence_truncated: bool
    mitre: List[str]
    summary: str
    status: Status
    status_changed_at: Optional[datetime]
    note: str
    superseded: bool


class HistoryOut(BaseModel):
    changed_at: datetime
    old_status: str
    new_status: str
    actor: str
    note: str


class AlertDetail(AlertOut):
    evidence_total: int
    evidence: List[EventOut]
    history: List[HistoryOut]


class AlertPage(BaseModel):
    total: int
    limit: int
    offset: int
    alerts: List[AlertOut]


class StatusUpdate(BaseModel):
    model_config = ConfigDict(extra="forbid")

    status: Status
    note: str = Field("", max_length=2000)


class RuleOut(BaseModel):
    id: str
    title: str
    type: str
    severity: str
    group_by: List[str]
    timespan_seconds: int
    mitre: List[str]
    description: str
    alerts: int


class SourceCount(BaseModel):
    src_ip: str
    failures: int


class DayCount(BaseModel):
    day: str
    alerts: int


class EventStats(BaseModel):
    total: int
    by_type: Dict[str, int]
    first: Optional[datetime]
    last: Optional[datetime]
    dead_letters: int


class AlertStats(BaseModel):
    total: int
    by_status: Dict[str, int]
    by_severity: Dict[str, int]
    by_rule: Dict[str, int]


class StatsOut(BaseModel):
    events: EventStats
    alerts: AlertStats
    top_sources: List[SourceCount]
    alerts_over_time: List[DayCount]


def _utc(value: Optional[datetime]) -> Optional[datetime]:
    """A timestamp given without an offset is taken as UTC, like everything stored."""
    if value is None or value.tzinfo is not None:
        return value
    return value.replace(tzinfo=timezone.utc)


def _event(e: Event) -> EventOut:
    return EventOut(
        id=e.id, timestamp=e.timestamp, source=e.source, event_type=e.event_type, src_ip=e.src_ip,
        username=e.username, host=e.host, outcome=e.outcome, count=e.count, geo=e.geo, extra=e.extra,
        raw=e.raw, source_id=e.source_id, offset=e.offset,
    )  # fmt: skip


def _alert_fields(stored: StoredAlert) -> Dict[str, Any]:
    a = stored.alert
    return dict(
        id=a.id, rule_id=a.rule_id, title=a.title, severity=a.severity, group_key=a.group_key,
        first_seen=a.first_seen, last_seen=a.last_seen, event_count=a.event_count,
        distinct_count=a.distinct_count, evidence_truncated=a.evidence_truncated, mitre=list(a.mitre),
        summary=a.summary, status=stored.status, status_changed_at=stored.status_changed_at,
        note=stored.note, superseded=stored.superseded,
    )  # fmt: skip


def create_app(db_path: str, rules: Sequence[Rule], token: str) -> FastAPI:
    """Build the API for one database. ``token`` is the bearer token every caller must send."""
    if not token:
        raise ValueError("an API token is required")
    expected = token.encode("utf-8")

    app = FastAPI(
        title="Siftlog",
        version="0.1.0",
        description="Events, alerts and their analyst workflow. Send `Authorization: Bearer <token>`.",
    )
    bearer = HTTPBearer(auto_error=False, description="The token printed when the server started.")

    def authorised(credentials: Optional[HTTPAuthorizationCredentials] = Depends(bearer)) -> None:
        supplied = credentials.credentials.encode("utf-8") if credentials else b""
        if not hmac.compare_digest(supplied, expected):
            raise HTTPException(401, "missing or invalid API token", headers={"WWW-Authenticate": "Bearer"})

    @app.middleware("http")
    async def security_headers(request: Request, call_next):  # type: ignore[no-untyped-def]
        response = await call_next(request)
        response.headers["X-Content-Type-Options"] = "nosniff"
        response.headers["Cache-Control"] = "no-store"
        return response

    @app.get("/health", summary="Liveness check (no token needed)")
    def health() -> Dict[str, str]:
        return {"status": "ok"}

    @app.get("/", include_in_schema=False)
    def root() -> RedirectResponse:
        # Someone opening the bare address in a browser should land somewhere useful, not on a 404.
        return RedirectResponse("/docs")

    api = APIRouter(dependencies=[Depends(authorised)])

    @api.get("/alerts", response_model=AlertPage, summary="List alerts, newest activity first")
    def list_alerts(
        status: Optional[Status] = None,
        severity: Optional[Severity] = None,
        rule_id: Optional[str] = Query(None, max_length=200),
        group_key: Optional[str] = Query(None, max_length=500),
        since: Optional[datetime] = Query(None, description="only alerts active at or after this time"),
        until: Optional[datetime] = Query(None, description="only alerts that started before this time"),
        include_superseded: bool = Query(False, description="include alerts the latest replay no longer produces"),
        limit: int = Query(100, ge=1, le=MAX_PAGE),
        offset: int = Query(0, ge=0),
    ) -> AlertPage:
        filters = dict(status=status, severity=severity, rule_id=rule_id, group_key=group_key,
                       since=_utc(since), until=_utc(until), include_superseded=include_superseded)  # fmt: skip
        with EventStore(db_path) as store:
            rows = store.list_alerts(limit=limit, offset=offset, **filters)
            total = store.count_alerts(**filters)
        return AlertPage(total=total, limit=limit, offset=offset, alerts=[AlertOut(**_alert_fields(r)) for r in rows])

    @api.get("/alerts/{alert_id}", response_model=AlertDetail, summary="One alert, with its evidence and history")
    def get_alert(
        alert_id: str = Path(..., max_length=64),
        evidence_limit: int = Query(200, ge=0, le=MAX_PAGE, description="how many evidence events to return"),
    ) -> AlertDetail:
        with EventStore(db_path) as store:
            stored = store.get_alert(alert_id)
            if stored is None:
                raise HTTPException(404, "no such alert")
            evidence = store.alert_events(alert_id)
            history = store.alert_history(alert_id)
        return AlertDetail(
            **_alert_fields(stored),
            evidence_total=len(evidence),
            evidence=[_event(e) for e in evidence[:evidence_limit]],
            history=[HistoryOut(**vars(h)) for h in history],
        )

    @api.patch("/alerts/{alert_id}", response_model=AlertOut, summary="Record a decision about an alert")
    def update_alert(update: StatusUpdate, alert_id: str = Path(..., max_length=64)) -> AlertOut:
        with EventStore(db_path) as store:
            try:
                stored = store.set_alert_status(alert_id, update.status, note=update.note, actor="api")
            except KeyError:
                raise HTTPException(404, "no such alert") from None
        return AlertOut(**_alert_fields(stored))

    @api.get("/events", response_model=EventPage, summary="Search stored events")
    def list_events(
        src_ip: Optional[str] = Query(None, max_length=64),
        username: Optional[str] = Query(None, max_length=500),
        event_type: Optional[str] = Query(None, max_length=64),
        since: Optional[datetime] = Query(None, description="inclusive"),
        until: Optional[datetime] = Query(None, description="exclusive"),
        newest_first: bool = False,
        limit: int = Query(100, ge=1, le=MAX_PAGE),
    ) -> EventPage:
        filters = dict(src_ip=src_ip, username=username, event_type=event_type, since=_utc(since), until=_utc(until))
        with EventStore(db_path) as store:
            events = store.query(limit=limit, descending=newest_first, **filters)
            total = store.count(**filters)
        return EventPage(total=total, events=[_event(e) for e in events])

    @api.get("/stats", response_model=StatsOut, summary="Counts for a dashboard")
    def stats() -> StatsOut:
        with EventStore(db_path) as store:
            first, last = store.time_range()
            by_status = store.alert_breakdown("status")
            return StatsOut(
                events=EventStats(
                    total=store.count(), by_type=store.event_type_counts(), first=first, last=last,
                    dead_letters=store.dead_letter_count(),
                ),  # fmt: skip
                alerts=AlertStats(
                    total=sum(by_status.values()), by_status=by_status,
                    by_severity=store.alert_breakdown("severity"), by_rule=store.alert_breakdown("rule_id"),
                ),  # fmt: skip
                top_sources=[SourceCount(src_ip=ip, failures=n) for ip, n in store.top_sources(10)],
                alerts_over_time=[DayCount(day=day, alerts=n) for day, n in store.alerts_per_day()],
            )

    @api.get("/rules", response_model=List[RuleOut], summary="Loaded rules and how many alerts each has")
    def list_rules() -> List[RuleOut]:
        with EventStore(db_path) as store:
            hits = store.alert_breakdown("rule_id")
        return [
            RuleOut(
                id=r.id, title=r.title, type=r.type, severity=r.severity, group_by=list(r.group_by),
                timespan_seconds=int(r.timespan.total_seconds()), mitre=list(r.mitre),
                description=r.description.strip(), alerts=hits.get(r.id, 0),
            )  # fmt: skip
            for r in rules
        ]

    app.include_router(api)
    return app
