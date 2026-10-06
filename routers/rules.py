"""CRUD + catalogue API for user-defined correlation rules."""

from __future__ import annotations

from fastapi import APIRouter, HTTPException, status

from domain.rules import (
    CorrelationRuleCreate,
    CorrelationRuleListResponse,
    CorrelationRuleOut,
    CorrelationRuleUpdate,
    RuleHitOut,
)
from routers.dependencies import ContainerDep

router = APIRouter(prefix="/api/v1/rules", tags=["rules"])


@router.get("", response_model=CorrelationRuleListResponse, summary="List rules")
async def list_rules(container: ContainerDep) -> CorrelationRuleListResponse:
    """All rules plus dropdown catalogue for the constructor UI."""
    return await container.rules.list_rules()


@router.get("/hits", response_model=list[RuleHitOut], summary="Recent rule hits")
async def recent_hits(container: ContainerDep) -> list[RuleHitOut]:
    """In-memory recent firings (this process)."""
    return container.rules.recent_hits()


@router.get("/{rule_id}", response_model=CorrelationRuleOut, summary="Get one rule")
async def get_rule(rule_id: int, container: ContainerDep) -> CorrelationRuleOut:
    rule = await container.rules.get_rule(rule_id)
    if rule is None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="rule_not_found")
    return rule


@router.post(
    "",
    response_model=CorrelationRuleOut,
    status_code=status.HTTP_201_CREATED,
    summary="Create rule",
)
async def create_rule(
    body: CorrelationRuleCreate, container: ContainerDep
) -> CorrelationRuleOut:
    try:
        return await container.rules.create_rule(body)
    except Exception as exc:  # noqa: BLE001 - surface unique name clashes
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST, detail=str(exc)
        ) from exc


@router.patch("/{rule_id}", response_model=CorrelationRuleOut, summary="Update rule")
async def update_rule(
    rule_id: int, body: CorrelationRuleUpdate, container: ContainerDep
) -> CorrelationRuleOut:
    updated = await container.rules.update_rule(rule_id, body)
    if updated is None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="rule_not_found")
    return updated


@router.post(
    "/{rule_id}/enable",
    response_model=CorrelationRuleOut,
    summary="Enable rule",
)
async def enable_rule(rule_id: int, container: ContainerDep) -> CorrelationRuleOut:
    updated = await container.rules.set_enabled(rule_id, True)
    if updated is None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="rule_not_found")
    return updated


@router.post(
    "/{rule_id}/disable",
    response_model=CorrelationRuleOut,
    summary="Disable rule",
)
async def disable_rule(rule_id: int, container: ContainerDep) -> CorrelationRuleOut:
    updated = await container.rules.set_enabled(rule_id, False)
    if updated is None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="rule_not_found")
    return updated


@router.delete(
    "/{rule_id}",
    status_code=status.HTTP_204_NO_CONTENT,
    summary="Delete rule",
)
async def delete_rule(rule_id: int, container: ContainerDep) -> None:
    if not await container.rules.delete_rule(rule_id):
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="rule_not_found")
