"""Zero-dependency standard plug-in translators for external memory stores
(Mem0, Zep/Graphiti, Mories) built on top of ``CallableExternalAdapter``.
"""
from __future__ import annotations

from collections.abc import Mapping
import hashlib
from typing import Any, Callable

from .adapters import (
    CallableExternalAdapter,
    ExternalMemoryItem,
    validate_identifier,
    validate_sha256,
)
from .exceptions import ValidationError


def _strict_positive_int(val: Any, *, default: int = 1, field: str = "revision") -> int:
    if val is None:
        return default
    if type(val) is not int or val < 1:
        raise ValidationError(f"invalid_{field}")
    return val


def _strict_bool(val: Any, *, default: bool = False, field: str = "flag") -> bool:
    if val is None:
        return default
    if not isinstance(val, bool):
        raise ValidationError(f"invalid_{field}")
    return val


def _extract_verified_sha256(rec: Mapping[str, Any], *, text_field: str, provider: str) -> str:
    raw_sha = rec.get("content_sha256")
    raw_text = rec.get(text_field)

    computed_sha: str | None = None
    if raw_text is not None:
        if not isinstance(raw_text, str):
            raise TypeError(f"invalid_{provider}_{text_field}_type")
        computed_sha = hashlib.sha256(raw_text.encode("utf-8")).hexdigest()

    if raw_sha is not None:
        validated = validate_sha256(raw_sha, f"{provider}_content_sha256")
        if computed_sha is not None and validated != computed_sha:
            raise ValidationError(f"{provider}_content_sha256_mismatch")
        return validated

    if computed_sha is not None:
        return computed_sha

    raise ValidationError(f"missing_{provider}_content")


def make_mem0_adapter(
    lookup_fn: Callable[[str], ExternalMemoryItem | Mapping[str, Any]],
    *,
    namespace: str = "default",
) -> CallableExternalAdapter:
    """Adapts a Mem0-style memory lookup callable to ``ExternalMemoryPort``.

    Args:
        lookup_fn: Callable accepting an item ID and returning a Mem0 record dict
            (``id``, ``memory``/``content_sha256``, ``version``/``revision``,
            ``deleted``/``is_deleted``, ``certified``) or ``ExternalMemoryItem``.
        namespace: Logical namespace encoded into the evidence URI.

    Returns:
        A fail-closed ``CallableExternalAdapter`` bound to ``provider='mem0'``.
    """
    validate_identifier(namespace, "mem0_namespace", max_len=64)

    def _translate(item_id: str) -> ExternalMemoryItem:
        rec = lookup_fn(item_id)
        if isinstance(rec, ExternalMemoryItem):
            if rec.provider not in ("external", "mem0"):
                raise ValidationError("mem0_provider_mismatch")
            return ExternalMemoryItem(
                item_id=rec.item_id,
                revision=rec.revision,
                content_sha256=rec.content_sha256,
                state=rec.state,
                certified=rec.certified,
                provider="mem0",
            )
        if not isinstance(rec, Mapping):
            raise TypeError("invalid_mem0_record")

        rec_id = rec.get("id") if rec.get("id") is not None else rec.get("item_id")
        if not isinstance(rec_id, str) or not rec_id:
            raise ValidationError("missing_mem0_id")
        ver_raw = rec.get("version") if rec.get("version") is not None else rec.get("revision")
        revision = _strict_positive_int(ver_raw, default=1, field="mem0_version")
        sha = _extract_verified_sha256(rec, text_field="memory", provider="mem0")

        deleted = _strict_bool(rec.get("deleted"), default=False, field="mem0_deleted")
        is_deleted = _strict_bool(rec.get("is_deleted"), default=False, field="mem0_is_deleted")
        raw_state = rec.get("state", "ACTIVE")
        if raw_state not in ("ACTIVE", "REVOKED"):
            raise ValidationError("invalid_mem0_state")
        state = "REVOKED" if (deleted or is_deleted or raw_state == "REVOKED") else "ACTIVE"
        certified = _strict_bool(rec.get("certified"), default=False, field="mem0_certified")
        return ExternalMemoryItem(
            item_id=rec_id,
            revision=revision,
            content_sha256=sha,
            state=state,
            certified=certified,
            provider="mem0",
        )

    return CallableExternalAdapter(_translate, provider="mem0", namespace=namespace)


def make_zep_adapter(
    lookup_fn: Callable[[str], ExternalMemoryItem | Mapping[str, Any]],
    *,
    graph_id: str = "default",
) -> CallableExternalAdapter:
    """Adapts a Zep / Graphiti temporal fact lookup callable to ``ExternalMemoryPort``.

    Any non-``None`` ``invalid_at``, ``expired_at``, or ``deleted_at`` field
    conservatively marks the record ``REVOKED`` so dependent tasks immediately ``HOLD``.
    """
    validate_identifier(graph_id, "zep_graph_id", max_len=64)

    def _translate(item_id: str) -> ExternalMemoryItem:
        rec = lookup_fn(item_id)
        if isinstance(rec, ExternalMemoryItem):
            if rec.provider not in ("external", "zep"):
                raise ValidationError("zep_provider_mismatch")
            return ExternalMemoryItem(
                item_id=rec.item_id,
                revision=rec.revision,
                content_sha256=rec.content_sha256,
                state=rec.state,
                certified=rec.certified,
                provider="zep",
            )
        if not isinstance(rec, Mapping):
            raise TypeError("invalid_zep_record")

        rec_id = rec.get("uuid")
        if rec_id is None:
            rec_id = rec.get("id") if rec.get("id") is not None else rec.get("item_id")
        if not isinstance(rec_id, str) or not rec_id:
            raise ValidationError("missing_zep_uuid")

        ver_raw = rec.get("revision") if rec.get("revision") is not None else rec.get("version")
        revision = _strict_positive_int(ver_raw, default=1, field="zep_revision")
        sha = _extract_verified_sha256(rec, text_field="fact", provider="zep")

        raw_state = rec.get("state", "ACTIVE")
        if raw_state not in ("ACTIVE", "REVOKED"):
            raise ValidationError("invalid_zep_state")
        invalidated = (
            rec.get("invalid_at") is not None
            or rec.get("expired_at") is not None
            or rec.get("deleted_at") is not None
            or raw_state == "REVOKED"
        )
        state = "REVOKED" if invalidated else "ACTIVE"
        certified = _strict_bool(rec.get("certified"), default=False, field="zep_certified")
        return ExternalMemoryItem(
            item_id=rec_id,
            revision=revision,
            content_sha256=sha,
            state=state,
            certified=certified,
            provider="zep",
        )

    return CallableExternalAdapter(_translate, provider="zep", namespace=graph_id)


def make_mories_adapter(
    lookup_fn: Callable[[str], ExternalMemoryItem | Mapping[str, Any]],
    *,
    project: str = "personal",
) -> CallableExternalAdapter:
    """Adapts a Mories item lookup callable to ``ExternalMemoryPort`` with zero SDK coupling."""
    validate_identifier(project, "mories_project", max_len=64)

    def _translate(item_id: str) -> ExternalMemoryItem:
        rec = lookup_fn(item_id)
        if isinstance(rec, ExternalMemoryItem):
            if rec.provider not in ("external", "mories"):
                raise ValidationError("mories_provider_mismatch")
            return ExternalMemoryItem(
                item_id=rec.item_id,
                revision=rec.revision,
                content_sha256=rec.content_sha256,
                state=rec.state,
                certified=rec.certified,
                provider="mories",
            )
        if not isinstance(rec, Mapping):
            raise TypeError("invalid_mories_record")

        rec_id = rec.get("item_id") if rec.get("item_id") is not None else rec.get("id")
        if not isinstance(rec_id, str) or not rec_id:
            raise ValidationError("missing_mories_item_id")
        revision = _strict_positive_int(rec.get("revision"), default=1, field="mories_revision")
        sha = _extract_verified_sha256(rec, text_field="content", provider="mories")
        raw_state = rec.get("state", "ACTIVE")
        if raw_state not in ("ACTIVE", "REVOKED"):
            raise ValidationError("invalid_mories_state")
        certified = _strict_bool(rec.get("certified"), default=False, field="mories_certified")
        return ExternalMemoryItem(
            item_id=rec_id,
            revision=revision,
            content_sha256=sha,
            state=raw_state,
            certified=certified,
            provider="mories",
        )

    return CallableExternalAdapter(_translate, provider="mories", namespace=project)
