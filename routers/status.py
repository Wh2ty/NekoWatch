"""Status monitoring API: source cards, LAN users, analyst notifications."""

from __future__ import annotations

from typing import Annotated, Any

from fastapi import APIRouter, HTTPException, Path, Query, status

from domain.status import (
    NetworkUserCreateRequest,
    SourceCreateRequest,
    SourceStatusCard,
    StatusBoardResponse,
    StatusNotificationOut,
    UserStatusCard,
)
from routers.dependencies import ContainerDep

router = APIRouter(prefix="/api/v1/status", tags=["status"])


@router.get(
    "/board",
    response_model=StatusBoardResponse,
    summary="Status board (sources + users + notifications)",
)
async def status_board(
    container: ContainerDep,
    demo: Annotated[
        bool,
        Query(description="Return presentation mock inventory instead of live DB."),
    ] = False,
) -> StatusBoardResponse:
    """Everything the Logener status cards need in one round-trip."""
    return await container.status.board(demo=demo)


@router.get("/sources", summary="List monitored sources")
async def list_sources(
    container: ContainerDep,
    demo: Annotated[bool, Query()] = False,
) -> dict[str, Any]:
    board = await container.status.board(demo=demo)
    return {
        "total": len(board.sources),
        "problematic": sum(
            1 for s in board.sources if s.event_status.value == "problematic"
        ),
        "demo": board.demo,
        "sources": board.sources,
    }


@router.get("/users", summary="List LAN users and ping status")
async def list_users(
    container: ContainerDep,
    demo: Annotated[bool, Query()] = False,
) -> dict[str, Any]:
    board = await container.status.board(demo=demo)
    return {
        "total": len(board.users),
        "connected": sum(1 for u in board.users if u.connection_ok),
        "demo": board.demo,
        "users": board.users,
    }


@router.get(
    "/notifications",
    response_model=list[StatusNotificationOut],
    summary="Analyst notifications",
)
async def list_notifications(
    container: ContainerDep,
    limit: Annotated[int, Query(ge=1, le=100)] = 20,
    demo: Annotated[bool, Query()] = False,
) -> list[StatusNotificationOut]:
    board = await container.status.board(demo=demo)
    return board.notifications[:limit]


@router.post(
    "/notifications/{notification_id}/ack",
    response_model=StatusNotificationOut,
    summary="Acknowledge a notification",
)
async def ack_notification(
    container: ContainerDep,
    notification_id: Annotated[int, Path(ge=1)],
) -> StatusNotificationOut:
    result = await container.status.acknowledge(notification_id)
    if result is None:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND, detail="notification_not_found"
        )
    return result


@router.post(
    "/sources",
    response_model=SourceStatusCard,
    summary="Register a source as owned",
    status_code=201,
)
async def create_source(
    container: ContainerDep, body: SourceCreateRequest
) -> SourceStatusCard:
    """Register a device in inventory — identified as «свой»."""
    return await container.status.register_source(
        agent_id=body.agent_id,
        name=body.name,
        ip_address=body.ip_address,
        registration=body.registration,
        timeout_seconds=body.timeout_seconds,
    )


@router.post(
    "/sources/{source_id}/claim",
    response_model=SourceStatusCard,
    summary="Claim foreign source as own",
)
async def claim_source(
    container: ContainerDep,
    source_id: Annotated[int, Path(ge=1)],
) -> SourceStatusCard:
    result = await container.status.claim_source(source_id)
    if result is None:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND, detail="source_not_found"
        )
    return result


@router.post(
    "/users",
    response_model=UserStatusCard,
    summary="Register a LAN user",
    status_code=201,
)
async def create_user(
    container: ContainerDep, body: NetworkUserCreateRequest
) -> UserStatusCard:
    return await container.status.register_user(
        username=body.username,
        display_name=body.display_name,
        ip_address=body.ip_address,
        registration=body.registration,
    )


@router.post("/ping-now", summary="Run one ping sweep immediately")
async def ping_now(container: ContainerDep) -> dict[str, str]:
    await container.status.ping_all()
    return {"status": "ok"}


@router.post("/evaluate-timeouts", summary="Run one source-timeout sweep")
async def evaluate_timeouts(container: ContainerDep) -> dict[str, int]:
    flipped = await container.status.evaluate_timeouts()
    return {"flipped_to_problematic": flipped}
