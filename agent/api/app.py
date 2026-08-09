"""FastAPI adapter over :mod:`agent.state.service`.

The app is normally used with ``httpx.ASGITransport``. It deliberately does
not start a listener or expose a public network surface by itself.
"""

from typing import Annotated

from fastapi import Depends, FastAPI, Header, Query, Request
from fastapi.exceptions import RequestValidationError
from fastapi.responses import JSONResponse

from agent.state.capabilities import CapabilityRegistry
from agent.state.errors import StateError
from agent.state.schemas import (
    AgentProgressInput,
    AgentReportInput,
    AnalysisPlanInput,
    CapabilityContext,
    CreateCycleInput,
    VerificationUpdateInput,
)
from agent.state.service import StateService


def create_state_app(
    state_service: StateService,
    capability_registry: CapabilityRegistry | None = None,
) -> FastAPI:
    registry = capability_registry or CapabilityRegistry()
    app = FastAPI(title="Aion Internal State API", version="1")
    app.state.state_service = state_service
    app.state.capability_registry = registry

    @app.exception_handler(StateError)
    async def state_error_handler(_request: Request, exc: StateError) -> JSONResponse:
        return JSONResponse(
            status_code=exc.status_code,
            content={"code": exc.code, "message": exc.message, "detail": exc.detail},
        )

    @app.exception_handler(RequestValidationError)
    async def validation_error_handler(_request: Request, exc: RequestValidationError) -> JSONResponse:
        detail = [
            {
                "loc": list(item.get("loc", ())),
                "type": item.get("type", "value_error"),
                "message": item.get("msg", "Invalid value"),
            }
            for item in exc.errors()
        ]
        return JSONResponse(status_code=422, content={"code": "validation_error", "message": "Request validation failed", "detail": detail})

    async def capability(
        x_aion_capability: Annotated[str | None, Header(alias="X-Aion-Capability")] = None,
        authorization: Annotated[str | None, Header()] = None,
    ) -> CapabilityContext:
        token = x_aion_capability
        if token is None and authorization and authorization.lower().startswith("bearer "):
            token = authorization[7:].strip()
        context = registry.resolve(token)
        if context is None:
            raise StateError("invalid_capability", "A valid capability is required", status_code=401)
        return context

    Cap = Annotated[CapabilityContext, Depends(capability)]

    @app.get("/internal/v1/runs/{run_id}/overview")
    async def overview(run_id: str, context: Cap) -> dict:
        if context.run_id != run_id or context.role != "chief":
            raise StateError("role_not_allowed", "Chief capability is required", status_code=403)
        return await state_service.get_overview(run_id)

    @app.get("/internal/v1/runs/{run_id}/challenges")
    async def challenges(run_id: str, context: Cap) -> dict:
        if context.run_id != run_id or context.role != "chief":
            raise StateError("role_not_allowed", "Chief capability is required", status_code=403)
        return {"challenges": await state_service.list_challenges(run_id)}

    @app.get("/internal/v1/runs/{run_id}/challenges/{unique_code}/context")
    async def challenge_context(run_id: str, unique_code: str, context: Cap) -> dict:
        if context.run_id != run_id:
            raise StateError("invalid_capability", "capability is not valid for this run", status_code=403)
        return await state_service.get_challenge_context(run_id, unique_code, context)

    @app.post("/internal/v1/runs/{run_id}/challenges/{unique_code}/cycles")
    async def begin_cycle(run_id: str, unique_code: str, payload: CreateCycleInput, context: Cap) -> dict:
        if context.run_id != run_id:
            raise StateError("invalid_capability", "capability is not valid for this run", status_code=403)
        return await state_service.begin_cycle(run_id, unique_code, context, payload)

    @app.put("/internal/v1/runs/{run_id}/cycles/{cycle_id}/analysis-plan")
    async def analysis_plan(run_id: str, cycle_id: str, payload: AnalysisPlanInput, context: Cap) -> dict:
        if context.run_id != run_id:
            raise StateError("invalid_capability", "capability is not valid for this run", status_code=403)
        return await state_service.submit_analysis_plan(run_id, cycle_id, context, payload)

    @app.put("/internal/v1/runs/{run_id}/cycles/{cycle_id}/verification-update")
    async def verification_update(run_id: str, cycle_id: str, payload: VerificationUpdateInput, context: Cap) -> dict:
        if context.run_id != run_id:
            raise StateError("invalid_capability", "capability is not valid for this run", status_code=403)
        return await state_service.commit_cycle(run_id, cycle_id, context, payload)

    @app.get("/internal/v1/runs/{run_id}/agents/{agent_id}/assignment")
    async def assignment(run_id: str, agent_id: str, context: Cap) -> dict:
        if context.run_id != run_id:
            raise StateError("invalid_capability", "capability is not valid for this run", status_code=403)
        return await state_service.get_assignment(run_id, agent_id, context)

    @app.post("/internal/v1/runs/{run_id}/agents/{agent_id}/progress")
    async def progress(run_id: str, agent_id: str, payload: AgentProgressInput, context: Cap) -> dict:
        if context.run_id != run_id:
            raise StateError("invalid_capability", "capability is not valid for this run", status_code=403)
        return await state_service.update_progress(run_id, agent_id, context, payload)

    @app.post("/internal/v1/runs/{run_id}/agents/{agent_id}/reports")
    async def report(run_id: str, agent_id: str, payload: AgentReportInput, context: Cap) -> dict:
        if context.run_id != run_id:
            raise StateError("invalid_capability", "capability is not valid for this run", status_code=403)
        return await state_service.submit_report(run_id, agent_id, context, payload)

    @app.get("/internal/v1/runs/{run_id}/reports")
    async def reports(
        run_id: str,
        context: Cap,
        after_sequence: int = Query(default=0, ge=0),
        wait_seconds: float = Query(default=0.0, ge=0, le=30),
        max_reports: int = Query(default=20, ge=1, le=100),
    ) -> dict:
        if context.run_id != run_id:
            raise StateError("invalid_capability", "capability is not valid for this run", status_code=403)
        return await state_service.list_reports(run_id, context, after_sequence=after_sequence, wait_seconds=wait_seconds, max_reports=max_reports)

    return app
