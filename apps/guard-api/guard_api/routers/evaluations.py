"""Evaluation run registry routes."""

from __future__ import annotations

from typing import Any

from fastapi import Cookie, FastAPI, Header

from guard_api.auth import ApiAuthError
from guard_api.models import EvaluationRun

from .common import bounded_limit, verify_browser_or_bearer_read
from .context import ApiContext


def evaluation_dataset_registry(runs: list[dict[str, Any]]) -> list[dict[str, Any]]:
    datasets: dict[str, dict[str, Any]] = {}
    version_maps: dict[str, dict[str, dict[str, Any]]] = {}
    for run in runs:
        dataset_id = run.get("dataset_id")
        dataset_version = run.get("dataset_version")
        if not isinstance(dataset_id, str) or not dataset_id:
            continue
        if not isinstance(dataset_version, str) or not dataset_version:
            continue
        dataset = datasets.setdefault(
            dataset_id,
            {
                "dataset_id": dataset_id,
                "run_count": 0,
                "latest_run_id": None,
                "latest_run_at": None,
                "versions": [],
            },
        )
        dataset["run_count"] += 1
        refresh_latest_run(dataset, run)
        versions = version_maps.setdefault(dataset_id, {})
        version = versions.setdefault(
            dataset_version,
            {
                "dataset_version": dataset_version,
                "dataset_digest": run.get("dataset_digest"),
                "locked": bool(run.get("dataset_locked")),
                "run_count": 0,
                "case_count": 0,
                "case_provenance_count": 0,
                "latest_run_id": None,
                "latest_run_at": None,
                "regression_gate": None,
            },
        )
        version["run_count"] += 1
        version["case_count"] += len(run.get("cases") or [])
        version["case_provenance_count"] += sum(
            1 for case in run.get("cases") or [] if case.get("provenance")
        )
        version["locked"] = bool(version["locked"] or run.get("dataset_locked"))
        version["dataset_digest"] = (
            run.get("dataset_digest") or version["dataset_digest"]
        )
        if run.get("regression_gate") is not None:
            version["regression_gate"] = run["regression_gate"]
        refresh_latest_run(version, run)
    for dataset_id, dataset in datasets.items():
        dataset["versions"] = sorted(
            version_maps[dataset_id].values(),
            key=lambda item: str(item["dataset_version"]),
            reverse=True,
        )
    return sorted(datasets.values(), key=lambda item: str(item["dataset_id"]))


def refresh_latest_run(target: dict[str, Any], run: dict[str, Any]) -> None:
    run_at = str(run.get("run_at") or "")
    latest_at = str(target.get("latest_run_at") or "")
    if run_at >= latest_at:
        target["latest_run_id"] = run.get("run_id")
        target["latest_run_at"] = run.get("run_at")


def register_routes(app: FastAPI, context: ApiContext) -> None:
    auth = context.auth
    store = context.store

    @app.post("/v1/evaluations")
    def save_evaluation_run(
        payload: EvaluationRun,
        authorization: str | None = Header(default=None),
    ) -> dict[str, Any]:
        auth.verify_bearer(authorization, "evaluation:write")
        return store.save_evaluation_run(payload)

    @app.get("/v1/evaluations")
    def list_evaluation_runs(
        dataset_id: str | None = None,
        dataset_version: str | None = None,
        limit: int = 100,
        authorization: str | None = Header(default=None),
        agentguard_session: str | None = Cookie(default=None),
    ) -> list[dict[str, Any]]:
        verify_browser_or_bearer_read(
            auth,
            required_scope="evaluation:read",
            authorization=authorization,
            agentguard_session=agentguard_session,
        )
        return store.list_evaluation_runs(
            dataset_id=dataset_id,
            dataset_version=dataset_version,
            limit=bounded_limit(limit),
        )

    @app.get("/v1/evaluations/datasets")
    def list_evaluation_datasets(
        dataset_id: str | None = None,
        authorization: str | None = Header(default=None),
        agentguard_session: str | None = Cookie(default=None),
    ) -> list[dict[str, Any]]:
        verify_browser_or_bearer_read(
            auth,
            required_scope="evaluation:read",
            authorization=authorization,
            agentguard_session=agentguard_session,
        )
        runs = store.list_evaluation_runs(dataset_id=dataset_id, limit=1000)
        return evaluation_dataset_registry(runs)

    @app.get("/v1/evaluations/latest")
    def latest_evaluation_run(
        authorization: str | None = Header(default=None),
        agentguard_session: str | None = Cookie(default=None),
    ) -> dict[str, Any]:
        verify_browser_or_bearer_read(
            auth,
            required_scope="evaluation:read",
            authorization=authorization,
            agentguard_session=agentguard_session,
        )
        run = store.get_latest_evaluation_run()
        if run is None:
            raise ApiAuthError("EVALUATION_NOT_FOUND", status_code=404)
        return run

    @app.get("/v1/evaluations/{run_id}")
    def get_evaluation_run(
        run_id: str,
        authorization: str | None = Header(default=None),
        agentguard_session: str | None = Cookie(default=None),
    ) -> dict[str, Any]:
        verify_browser_or_bearer_read(
            auth,
            required_scope="evaluation:read",
            authorization=authorization,
            agentguard_session=agentguard_session,
        )
        run = store.get_evaluation_run(run_id)
        if run is None:
            raise ApiAuthError("EVALUATION_NOT_FOUND", status_code=404)
        return run
