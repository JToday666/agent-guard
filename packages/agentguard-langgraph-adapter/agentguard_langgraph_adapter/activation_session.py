"""Single-flight ACK refresh with explicit availability and drift boundaries."""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime, timezone
from importlib.metadata import version
import math
from threading import Event, RLock, Thread, current_thread
from typing import Any, Callable

from .activation_ack import (
    ActivationAckV1,
    ProductActivationError,
    _max_age_nanoseconds,
)
from .product_manifest import ProductActivationManifest, ProductRuntimeObservation

HeartbeatSender = Callable[[dict[str, Any]], dict[str, Any]]
RuntimeObserver = Callable[[], ProductRuntimeObservation]
_DRIFT_CODES = frozenset(
    {
        "manifest_changed",
        "manifest_not_file_backed",
        "observation_drift",
        "observation_invalid",
        "version_mismatch",
        "runtime_version_unavailable",
        "ack_identity_mismatch",
        "heartbeat_identity_mismatch",
        "V21_PRODUCT_ACTIVATION_NOT_CURRENT",
        "V21_PRODUCT_RUNTIME_IDENTITY_MISMATCH",
        "V21_PRODUCT_RUNTIME_OBSERVATION_MISMATCH",
    }
)


def _now_utc() -> datetime:
    return datetime.now(timezone.utc)


def _installed_version(distribution: str) -> str:
    return version(distribution)


@dataclass(repr=False)
class _RefreshFlight:
    done: Event = field(default_factory=Event)
    ack: ActivationAckV1 | None = None
    error_code: str | None = None


class ProductActivationSession:
    """One protected manifest and registered runtime, never a process-global ACK."""

    def __init__(
        self,
        manifest: ProductActivationManifest,
        *,
        send_heartbeat: HeartbeatSender,
        observe: RuntimeObserver,
        refresh_interval_seconds: float = 30.0,
        max_ack_age_seconds: float = 120.0,
    ) -> None:
        if not isinstance(manifest, ProductActivationManifest):
            raise ProductActivationError("manifest_invalid")
        manifest.assert_unchanged()
        _max_age_nanoseconds(max_ack_age_seconds)
        if (
            isinstance(refresh_interval_seconds, bool)
            or not isinstance(refresh_interval_seconds, (int, float))
            or not 0 < refresh_interval_seconds < max_ack_age_seconds
            or not math.isfinite(refresh_interval_seconds)
        ):
            raise ProductActivationError("invalid_refresh_interval")
        if not callable(send_heartbeat) or not callable(observe):
            raise ProductActivationError("invalid_session_callback")
        self._manifest = manifest
        self._send_heartbeat = send_heartbeat
        self._observe = observe
        self._refresh_interval = float(refresh_interval_seconds)
        self._max_ack_age = float(max_ack_age_seconds)
        self._lock = RLock()
        self._stop = Event()
        self._worker: Thread | None = None
        self._flight: _RefreshFlight | None = None
        self._latest: ActivationAckV1 | None = None
        self._started = False
        self._closed = False
        self._drift_code: str | None = None
        self._unavailable_code = "session_not_started"

    @property
    def manifest(self) -> ProductActivationManifest:
        return self._manifest

    def start(self) -> ActivationAckV1:
        with self._lock:
            self._assert_open()
            already_running = self._worker is not None
            self._started = True
        if already_running:
            return self.snapshot()
        return self.refresh()

    def refresh(self) -> ActivationAckV1:
        with self._lock:
            self._assert_open()
            if not self._started:
                raise ProductActivationError("session_not_started")
            leader = self._flight is None
            if leader:
                self._flight = _RefreshFlight()
            flight = self._flight
            assert flight is not None
        if leader:
            try:
                ack = self._perform_refresh()
                error_code = None
            except ProductActivationError as exc:
                ack, error_code = None, exc.code
            except Exception:
                ack, error_code = None, "heartbeat_unavailable"
            with self._lock:
                if self._closed:
                    ack, error_code = None, "session_closed"
                elif self._drift_code is not None:
                    ack, error_code = None, self._drift_code
                if error_code is not None:
                    self._mark_unavailable(error_code)
                else:
                    self._latest = ack
                flight.ack = ack
                flight.error_code = error_code
                if self._flight is flight:
                    self._flight = None
                flight.done.set()
        else:
            flight.done.wait()
        with self._lock:
            self._assert_open()
            if flight.error_code is not None:
                raise ProductActivationError(flight.error_code)
            if flight.ack is None:
                raise ProductActivationError("heartbeat_unavailable")
            if self._latest is None:
                raise ProductActivationError(self._unavailable_code)
            try:
                flight.ack.remaining_seconds(
                    now=_now_utc(), max_age_seconds=self._max_ack_age
                )
            except ProductActivationError as exc:
                self._mark_unavailable(exc.code)
                raise
            if self._worker is None:
                # A failed initial start may recover through explicit refresh.
                # Its first success must establish the same refresh lifecycle.
                self._worker = Thread(
                    target=self._refresh_loop,
                    name="agentguard-activation-refresh",
                    daemon=True,
                )
                self._worker.start()
            return flight.ack

    def snapshot(self) -> ActivationAckV1:
        with self._lock:
            self._assert_open()
            if self._latest is None:
                raise ProductActivationError(self._unavailable_code)
        # Local observers and filesystem access can block. They must not hold
        # the state lock needed by close or a failed refresh.
        try:
            self.manifest.assert_unchanged()
            self._verify_versions()
            self._observe_heartbeat()
        except ProductActivationError as exc:
            with self._lock:
                self._assert_open()
                self._mark_unavailable(exc.code)
            raise
        with self._lock:
            self._assert_open()
            # Refresh may have completed or failed during the observation.
            # Select its current result, never the ACK seen before observing.
            if self._latest is None:
                raise ProductActivationError(self._unavailable_code)
            try:
                self._latest.remaining_seconds(
                    now=_now_utc(), max_age_seconds=self._max_ack_age
                )
            except ProductActivationError as exc:
                self._mark_unavailable(exc.code)
                raise
            return self._latest

    def close(self) -> None:
        with self._lock:
            self._closed = True
            self._latest = None
            self._stop.set()
            if self._flight is not None:
                self._flight.error_code = "session_closed"
                self._flight.done.set()
            worker = self._worker
        # A synchronous bounded HTTP callback may still be finishing. Its late
        # result is discarded; close never waits indefinitely on that callback.
        if worker is not None and worker is not current_thread():
            worker.join(timeout=1.0)

    def _assert_open(self) -> None:
        if self._closed:
            raise ProductActivationError("session_closed")
        if self._drift_code is not None:
            raise ProductActivationError(self._drift_code)

    def _mark_unavailable(self, code: str) -> None:
        self._latest = None
        self._unavailable_code = code
        if code in _DRIFT_CODES:
            self._drift_code = code
            self._stop.set()

    def _verify_versions(self) -> None:
        try:
            actual_runtime = _installed_version("langgraph")
            actual_adapter = _installed_version("agentguard-langgraph-adapter")
        except Exception:
            raise ProductActivationError("runtime_version_unavailable") from None
        if (
            actual_runtime != self.manifest.runtime_version
            or actual_adapter != self.manifest.plugin_version
        ):
            raise ProductActivationError("version_mismatch")

    def _perform_refresh(self) -> ActivationAckV1:
        self.manifest.assert_unchanged()
        self._verify_versions()
        heartbeat = self._observe_heartbeat()
        with self._lock:
            self._assert_open()
        try:
            response = self._send_heartbeat(heartbeat)
        except ProductActivationError:
            raise
        except Exception:
            raise ProductActivationError("heartbeat_unavailable") from None
        self.manifest.assert_unchanged()
        self._verify_versions()
        self._observe_heartbeat()
        if not isinstance(response, dict) or set(response) != {
            "runtime_status",
            "activation_ack",
        }:
            raise ProductActivationError("invalid_heartbeat_response")
        status = response["runtime_status"]
        if (
            not isinstance(status, dict)
            or status.get("runtime") != self.manifest.runtime
            or status.get("principal_id") != self.manifest.principal_id
            or any(status.get(key) != value for key, value in heartbeat.items())
        ):
            raise ProductActivationError("heartbeat_identity_mismatch")
        return ActivationAckV1.read(
            response["activation_ack"],
            expected=self.manifest,
            now=_now_utc(),
            max_age_seconds=self._max_ack_age,
        )

    def _observe_heartbeat(self) -> dict[str, Any]:
        try:
            observed = self._observe()
        except ProductActivationError:
            raise
        except Exception:
            raise ProductActivationError("observation_unavailable") from None
        return self.manifest.make_heartbeat(observed)

    def _refresh_loop(self) -> None:
        while not self._stop.wait(self._refresh_interval):
            try:
                self.refresh()
            except ProductActivationError:
                # Availability is explicit through snapshot(); no private errors
                # or transport objects are logged from the background worker.
                continue
