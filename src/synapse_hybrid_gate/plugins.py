"""Zero-dependency standard plug-in translators for external memory stores
(Mem0, Zep/Graphiti, Mories) built on top of ``CallableExternalAdapter``.
"""
from __future__ import annotations

from collections.abc import Mapping, Sequence
from datetime import datetime, timezone
import hashlib
import math
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


def _strict_non_negative_int(val: Any, *, field: str) -> int:
    if type(val) is not int or val < 0:
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


def _is_unset_timestamp(val: Any) -> bool:
    return val is None or (isinstance(val, str) and not val.strip())


def _parse_utc_timestamp(val: Any) -> tuple[str, datetime | None]:
    """Parses ISO-8601 (``Z``/offset, naive treated as UTC) or numeric Unix epoch timestamps.

    Returns:
        ``('UNSET', None)`` for ``None`` or empty/whitespace strings,
        ``('OK', aware_utc_datetime)`` on valid input, or
        ``('MALFORMED', None)`` on invalid or non-finite values.
    """
    if _is_unset_timestamp(val):
        return "UNSET", None
    if isinstance(val, bool):
        return "MALFORMED", None
    if isinstance(val, datetime):
        dt = val.replace(tzinfo=timezone.utc) if val.tzinfo is None else val.astimezone(timezone.utc)
        return "OK", dt
    if isinstance(val, (int, float)):
        if isinstance(val, float) and (math.isnan(val) or math.isinf(val)):
            return "MALFORMED", None
        try:
            return "OK", datetime.fromtimestamp(val, tz=timezone.utc)
        except (OverflowError, OSError, ValueError):
            return "MALFORMED", None
    if isinstance(val, str):
        s = val.strip()
        try:
            dt = datetime.fromisoformat(s)
        except ValueError:
            return "MALFORMED", None
        if dt.tzinfo is None:
            dt = dt.replace(tzinfo=timezone.utc)
        else:
            dt = dt.astimezone(timezone.utc)
        return "OK", dt
    return "MALFORMED", None


def _resolve_as_of_utc(val: Any) -> datetime:
    status, dt = _parse_utc_timestamp(val)
    if status != "OK" or dt is None:
        raise ValidationError("invalid_zep_as_of")
    return dt


def _normalize_temporal_meta_value(val: Any, *, field: str) -> str | int | float:
    if isinstance(val, bool):
        raise ValidationError(f"invalid_{field}")
    if isinstance(val, datetime):
        dt = val.replace(tzinfo=timezone.utc) if val.tzinfo is None else val.astimezone(timezone.utc)
        return dt.isoformat()
    if isinstance(val, (int, float)):
        if isinstance(val, float) and (math.isnan(val) or math.isinf(val)):
            raise ValidationError(f"invalid_{field}")
        return val
    if isinstance(val, str):
        return val
    raise ValidationError(f"invalid_{field}")


def _wrap_batch_translator(
    batch_lookup_fn: Callable[[Sequence[str]], Mapping[str, ExternalMemoryItem | Mapping[str, Any]]] | None,
    translate_record: Callable[[ExternalMemoryItem | Mapping[str, Any]], ExternalMemoryItem],
) -> Callable[[Sequence[str]], dict[str, ExternalMemoryItem]] | None:
    if batch_lookup_fn is None:
        return None
    if not callable(batch_lookup_fn):
        raise TypeError("invalid_batch_lookup_fn")

    def _translate_batch(item_ids: Sequence[str]) -> dict[str, ExternalMemoryItem]:
        raw_map = batch_lookup_fn(item_ids)
        if not isinstance(raw_map, Mapping):
            raise TypeError("invalid_batch_lookup_result")
        out: dict[str, Any] = {}
        for iid, rec in raw_map.items():
            try:
                out[iid] = translate_record(rec)
            except Exception:
                # Preserve per-item fail-closed isolation inside CallableExternalAdapter.inspect_many
                out[iid] = object()
        return out

    return _translate_batch


def make_mem0_adapter(
    lookup_fn: Callable[[str], ExternalMemoryItem | Mapping[str, Any]],
    *,
    namespace: str = "default",
    batch_lookup_fn: Callable[[Sequence[str]], Mapping[str, ExternalMemoryItem | Mapping[str, Any]]] | None = None,
) -> CallableExternalAdapter:
    """Adapts a Mem0-style memory lookup callable to ``ExternalMemoryPort``.

    Args:
        lookup_fn: Callable accepting an item ID and returning a Mem0 record dict
            (``id``, ``memory``/``content_sha256``, ``version``/``revision``,
            ``deleted``/``is_deleted``, ``certified``) or ``ExternalMemoryItem``.
        namespace: Logical namespace encoded into the evidence URI.
        batch_lookup_fn: Optional batched lookup callable ``(item_ids) -> dict[id, record]``.

    Returns:
        A fail-closed ``CallableExternalAdapter`` bound to ``provider='mem0'``.
    """
    validate_identifier(namespace, "mem0_namespace", max_len=64)

    def _translate_record(rec: ExternalMemoryItem | Mapping[str, Any]) -> ExternalMemoryItem:
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
                metadata=rec.metadata,
            )
        if rec is None:
            raise KeyError("mem0_item_not_found")
        if not isinstance(rec, Mapping):
            raise TypeError("invalid_mem0_record")

        rec_id = rec.get("id") if rec.get("id") is not None else rec.get("item_id")
        if not isinstance(rec_id, str) or not rec_id:
            raise ValidationError("missing_mem0_id")
        ver_raw = rec.get("version") if rec.get("version") is not None else rec.get("revision")
        revision = _strict_positive_int(ver_raw, default=1, field="mem0_version")
        text_field = "memory" if rec.get("memory") is not None or rec.get("text") is None else "text"
        sha = _extract_verified_sha256(rec, text_field=text_field, provider="mem0")

        deleted = _strict_bool(rec.get("deleted"), default=False, field="mem0_deleted")
        is_deleted = _strict_bool(rec.get("is_deleted"), default=False, field="mem0_is_deleted")
        replaced_by = rec.get("replaced_by")
        is_replaced = isinstance(replaced_by, str) and bool(replaced_by.strip())
        raw_state = rec.get("state", "ACTIVE")
        if raw_state not in ("ACTIVE", "REVOKED"):
            raise ValidationError("invalid_mem0_state")
        state = "REVOKED" if (deleted or is_deleted or is_replaced or raw_state == "REVOKED") else "ACTIVE"
        certified = _strict_bool(rec.get("certified"), default=False, field="mem0_certified")
        return ExternalMemoryItem(
            item_id=rec_id,
            revision=revision,
            content_sha256=sha,
            state=state,
            certified=certified,
            provider="mem0",
        )

    def _translate(item_id: str) -> ExternalMemoryItem:
        return _translate_record(lookup_fn(item_id))

    return CallableExternalAdapter(
        _translate,
        provider="mem0",
        namespace=namespace,
        batch_lookup_fn=_wrap_batch_translator(batch_lookup_fn, _translate_record),
    )


def make_zep_adapter(
    lookup_fn: Callable[[str], ExternalMemoryItem | Mapping[str, Any]],
    *,
    graph_id: str = "default",
    as_of: datetime | str | int | float | None = None,
    as_of_fn: Callable[[], datetime | str | int | float] | None = None,
    batch_lookup_fn: Callable[[Sequence[str]], Mapping[str, ExternalMemoryItem | Mapping[str, Any]]] | None = None,
) -> CallableExternalAdapter:
    """Adapts a Zep / Graphiti temporal fact lookup callable to ``ExternalMemoryPort``.

    Evaluates temporal validity fields against ``as_of`` / ``as_of_fn`` (defaulting to
    current UTC time):
      - ``None`` and empty/whitespace strings are treated as unset (not revoked).
      - Non-empty ``deleted_at`` marks the record ``REVOKED``.
      - ``invalid_at`` or ``expired_at`` parsed ``<= as_of`` marks ``REVOKED``;
        values ``> as_of`` (future expiration TTL) remain ``ACTIVE``.
      - ``valid_at`` parsed ``> as_of`` (not yet valid) fails closed to ``UNKNOWN``.
      - Any malformed timestamp fails closed to ``UNKNOWN`` (never silently ``ACTIVE``).
    """
    validate_identifier(graph_id, "zep_graph_id", max_len=64)
    if as_of is not None and as_of_fn is not None:
        raise ValidationError("ambiguous_zep_as_of")
    fixed_as_of = _resolve_as_of_utc(as_of) if as_of is not None else None
    if as_of_fn is not None and not callable(as_of_fn):
        raise TypeError("invalid_zep_as_of_fn")

    def _current_as_of() -> datetime:
        if fixed_as_of is not None:
            return fixed_as_of
        if as_of_fn is not None:
            return _resolve_as_of_utc(as_of_fn())
        return datetime.now(timezone.utc)

    def _translate_record(rec: ExternalMemoryItem | Mapping[str, Any]) -> ExternalMemoryItem:
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
                metadata=rec.metadata,
            )
        if rec is None:
            raise KeyError("zep_item_not_found")
        if not isinstance(rec, Mapping):
            # Support Graphiti EntityEdge / Pydantic / dataclass attribute objects
            if hasattr(rec, "model_dump") and callable(rec.model_dump):
                dumped = rec.model_dump()
                if not isinstance(dumped, Mapping):
                    raise TypeError("invalid_zep_record")
                rec = dumped
            elif any(hasattr(rec, attr) for attr in ("uuid", "id", "item_id")) and any(
                hasattr(rec, attr) for attr in ("fact", "content_sha256")
            ):
                rec = {
                    k: getattr(rec, k)
                    for k in (
                        "uuid", "id", "item_id", "revision", "version", "fact", "content_sha256",
                        "state", "deleted_at", "invalid_at", "expired_at", "valid_at", "certified",
                    )
                    if hasattr(rec, k)
                }
            else:
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
        if raw_state not in ("ACTIVE", "REVOKED", "UNKNOWN"):
            raise ValidationError("invalid_zep_state")

        now_utc = _current_as_of()
        deleted_non_empty = False
        expired_or_invalid = False
        not_yet_valid = False
        has_malformed = False

        raw_deleted = rec.get("deleted_at")
        if not _is_unset_timestamp(raw_deleted):
            if isinstance(raw_deleted, bool):
                has_malformed = True
            else:
                deleted_non_empty = True

        for field_name in ("invalid_at", "expired_at"):
            status, parsed_dt = _parse_utc_timestamp(rec.get(field_name))
            if status == "MALFORMED":
                has_malformed = True
            elif status == "OK" and parsed_dt is not None and parsed_dt <= now_utc:
                expired_or_invalid = True

        v_status, v_dt = _parse_utc_timestamp(rec.get("valid_at"))
        if v_status == "MALFORMED":
            has_malformed = True
        elif v_status == "OK" and v_dt is not None and v_dt > now_utc:
            not_yet_valid = True

        if deleted_non_empty or raw_state == "REVOKED" or expired_or_invalid:
            state = "REVOKED"
        elif raw_state == "UNKNOWN" or has_malformed or not_yet_valid:
            state = "UNKNOWN"
        else:
            state = "ACTIVE"

        certified = _strict_bool(rec.get("certified"), default=False, field="zep_certified")
        return ExternalMemoryItem(
            item_id=rec_id,
            revision=revision,
            content_sha256=sha,
            state=state,
            certified=certified,
            provider="zep",
        )

    def _translate(item_id: str) -> ExternalMemoryItem:
        return _translate_record(lookup_fn(item_id))

    return CallableExternalAdapter(
        _translate,
        provider="zep",
        namespace=graph_id,
        batch_lookup_fn=_wrap_batch_translator(batch_lookup_fn, _translate_record),
    )


def make_mories_adapter(
    lookup_fn: Callable[[str], ExternalMemoryItem | Mapping[str, Any]],
    *,
    project: str = "personal",
    batch_lookup_fn: Callable[[Sequence[str]], Mapping[str, ExternalMemoryItem | Mapping[str, Any]]] | None = None,
) -> CallableExternalAdapter:
    """Adapts a Mories item lookup callable to ``ExternalMemoryPort`` with zero SDK coupling.

    Preserves optional ``namespace``, ``namespace_epoch``, ``collection_epoch``, ``valid_from``,
    ``valid_to``, ``last_mutated_ns``, and ``pin_seq`` fields in snapshot ``metadata`` when
    present in the Mories payload.
    """
    validate_identifier(project, "mories_project", max_len=64)

    def _extract_mories_metadata(rec: Mapping[str, Any]) -> dict[str, Any] | None:
        nested = rec.get("metadata")
        nested_map = nested if isinstance(nested, Mapping) else {}
        meta: dict[str, Any] = {}

        ns_val = rec.get("namespace")
        if ns_val is None and "namespace" in nested_map:
            ns_val = nested_map.get("namespace")
        if ns_val is not None:
            validated_ns = validate_identifier(ns_val, "mories_namespace", max_len=128)
            if not validated_ns.strip():
                raise ValidationError("invalid_mories_namespace")
            meta["namespace"] = validated_ns

        for int_key in ("namespace_epoch", "collection_epoch", "last_mutated_ns"):
            val = rec.get(int_key)
            if val is None and int_key in nested_map:
                val = nested_map.get(int_key)
            if val is not None:
                meta[int_key] = _strict_non_negative_int(val, field=f"mories_{int_key}")

        pin_val = rec.get("pin_seq")
        if pin_val is None and "pin_seq" in nested_map:
            pin_val = nested_map.get("pin_seq")
        if pin_val is not None:
            meta["pin_seq"] = _strict_positive_int(pin_val, field="mories_pin_seq")

        for temporal_key in ("valid_from", "valid_to"):
            val = rec.get(temporal_key)
            if val is None and temporal_key in nested_map:
                val = nested_map.get(temporal_key)
            if val is not None:
                meta[temporal_key] = _normalize_temporal_meta_value(val, field=f"mories_{temporal_key}")
        return meta if meta else None

    def _translate_record(rec: ExternalMemoryItem | Mapping[str, Any]) -> ExternalMemoryItem:
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
                metadata=rec.metadata,
            )
        if rec is None:
            raise KeyError("mories_item_not_found")
        if not isinstance(rec, Mapping):
            raise TypeError("invalid_mories_record")

        rec_id = rec.get("item_id") if rec.get("item_id") is not None else rec.get("id")
        if not isinstance(rec_id, str) or not rec_id:
            raise ValidationError("missing_mories_item_id")
        revision = _strict_positive_int(rec.get("revision"), default=1, field="mories_revision")
        text_field = "content" if rec.get("content") is not None or rec.get("verbatim_text") is None else "verbatim_text"
        sha = _extract_verified_sha256(rec, text_field=text_field, provider="mories")
        if text_field == "content" and rec.get("verbatim_text") is not None:
            raw_verbatim = rec.get("verbatim_text")
            if not isinstance(raw_verbatim, str):
                raise TypeError("invalid_mories_verbatim_text_type")
            if hashlib.sha256(raw_verbatim.encode("utf-8")).hexdigest() != sha:
                raise ValidationError("mories_content_sha256_mismatch")
        raw_state = rec.get("state", "ACTIVE")
        if raw_state not in ("ACTIVE", "REVOKED", "UNKNOWN"):
            raise ValidationError("invalid_mories_state")
        certified = _strict_bool(rec.get("certified"), default=False, field="mories_certified")
        metadata = _extract_mories_metadata(rec)
        return ExternalMemoryItem(
            item_id=rec_id,
            revision=revision,
            content_sha256=sha,
            state=raw_state,
            certified=certified,
            provider="mories",
            metadata=metadata,
        )

    def _translate(item_id: str) -> ExternalMemoryItem:
        return _translate_record(lookup_fn(item_id))

    return CallableExternalAdapter(
        _translate,
        provider="mories",
        namespace=project,
        batch_lookup_fn=_wrap_batch_translator(batch_lookup_fn, _translate_record),
    )
