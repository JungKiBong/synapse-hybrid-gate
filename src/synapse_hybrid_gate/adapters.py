"""Vendor-neutral evidence adapters for local files and pluggable external memory stores."""
from __future__ import annotations

from collections.abc import Mapping, Sequence
from dataclasses import dataclass, field
import hashlib
import os
from pathlib import Path
import re
import stat
import threading
import time
from typing import Any, Callable, Protocol

from .exceptions import PathSecurityError, ValidationError


VALID_STATES = ("ACTIVE", "REVOKED", "UNAVAILABLE", "UNKNOWN")
DEFAULT_MAX_FILE_BYTES = 64 * 1024 * 1024  # 64 MiB DoS ceiling
_PROVIDER_SLUG_RE = re.compile(r"^[a-z0-9][a-z0-9_-]{0,63}$")


def validate_identifier(value: str, field: str, max_len: int = 128) -> str:
    """Validates a non-empty bounded string identifier without NUL bytes."""
    if not isinstance(value, str) or not value or len(value) > max_len or "\x00" in value:
        raise ValidationError(f"invalid_{field}")
    return value


def validate_provider(provider: str, *, allow_local: bool = False) -> str:
    """Validates a lowercase provider slug and blocks spoofing of ``'local'``."""
    if not isinstance(provider, str) or not _PROVIDER_SLUG_RE.match(provider):
        raise ValidationError("invalid_provider_name")
    if provider == "local" and not allow_local:
        raise ValidationError("reserved_provider_name:local")
    return provider


def validate_sha256(value: str, field: str = "sha256") -> str:
    """Validates and normalizes a 64-character hexadecimal SHA-256 digest."""
    if not isinstance(value, str) or len(value) != 64:
        raise ValidationError(f"invalid_{field}")
    try:
        int(value, 16)
    except ValueError as exc:
        raise ValidationError(f"invalid_{field}") from exc
    return value.lower()


@dataclass(frozen=True, slots=True)
class EvidenceSnapshot:
    """Immutable point-in-time state of a local file or external memory item."""

    evidence_id: str
    backend: str
    uri: str
    revision: int
    content_sha256: str
    state: str
    certified: bool
    reason: str = "ok"
    metadata: dict[str, Any] | None = field(default=None, hash=False)

    @property
    def provider(self) -> str:
        """Vendor-neutral alias for ``backend``."""
        return self.backend


@dataclass(frozen=True)
class ExternalMemoryItem:
    """Standard normalized state record returned by external memory lookups."""

    item_id: str
    revision: int
    content_sha256: str
    state: str = "ACTIVE"
    certified: bool = True
    provider: str = "external"
    metadata: dict[str, Any] | None = field(default=None, hash=False)

    def __post_init__(self) -> None:
        validate_identifier(self.item_id, "external_item_id")
        if type(self.revision) is not int or self.revision < 1:
            raise ValidationError("invalid_external_revision")
        normalized_sha = validate_sha256(self.content_sha256, "external_content_sha256")
        object.__setattr__(self, "content_sha256", normalized_sha)
        if self.state not in ("ACTIVE", "REVOKED", "UNKNOWN"):
            raise ValidationError("invalid_external_state")
        if not isinstance(self.certified, bool):
            raise ValidationError("invalid_external_certified")
        validate_provider(self.provider, allow_local=False)
        if self.metadata is not None:
            if not isinstance(self.metadata, Mapping):
                raise ValidationError("invalid_external_metadata")
            object.__setattr__(self, "metadata", dict(self.metadata))


@dataclass(frozen=True)
class MoriesItemState(ExternalMemoryItem):
    """Backward-compatible Mories item model built on ``ExternalMemoryItem``."""

    provider: str = "mories"


class ExternalMemoryPort(Protocol):
    """Vendor-neutral read-only inspection port for any external memory or knowledge store."""

    def inspect(self, item_id: str) -> EvidenceSnapshot:
        """Inspects a single external item by ID and returns an ``EvidenceSnapshot``."""
        ...


# Backward-compatible protocol alias
MoriesEvidenceAdapter = ExternalMemoryPort


class OfflineExternalAdapter:
    """Default fail-closed adapter when a configured external memory provider is not attached."""

    def __init__(self, provider: str = "external") -> None:
        self._provider = validate_provider(provider, allow_local=False)

    @property
    def provider(self) -> str:
        return self._provider

    def inspect(self, item_id: str) -> EvidenceSnapshot:
        """Always returns a fail-closed ``UNAVAILABLE`` snapshot."""
        validate_identifier(item_id, "external_item_id")
        reason = (
            "mories_backend_unavailable:offline_adapter"
            if self._provider == "mories"
            else f"external_backend_unavailable:offline_adapter:{self._provider}"
        )
        return EvidenceSnapshot(
            evidence_id=item_id,
            backend=self._provider,
            uri=f"{self._provider}://{item_id}",
            revision=0,
            content_sha256="0" * 64,
            state="UNAVAILABLE",
            certified=False,
            reason=reason,
        )

    def inspect_many(self, item_ids: Sequence[str]) -> dict[str, EvidenceSnapshot]:
        """Batch inspection helper returning fail-closed snapshots for each item ID."""
        return {iid: self.inspect(iid) for iid in item_ids}


class OfflineMoriesAdapter(OfflineExternalAdapter):
    """Backward-compatible offline fail-closed adapter for Mories."""

    def __init__(self) -> None:
        super().__init__(provider="mories")


class CallableExternalAdapter:
    """Wraps a provider lookup callable and converts transport/auth/type errors to fail-closed ``UNAVAILABLE``."""

    def __init__(
        self,
        lookup_fn: Callable[[str], ExternalMemoryItem],
        *,
        provider: str = "external",
        namespace: str = "default",
        batch_lookup_fn: Callable[[Sequence[str]], dict[str, ExternalMemoryItem]] | None = None,
    ) -> None:
        self._lookup = lookup_fn
        self._batch_lookup = batch_lookup_fn
        self._provider = validate_provider(provider, allow_local=False)
        self._namespace = validate_identifier(namespace, "external_namespace", max_len=64)

    @property
    def provider(self) -> str:
        return self._provider

    def _validate_returned_item(self, item_id: str, item: ExternalMemoryItem, uri: str) -> EvidenceSnapshot:
        if not isinstance(item, ExternalMemoryItem):
            raise TypeError("invalid_external_item_type")
        if item.item_id != item_id:
            raise ValidationError("external_item_id_mismatch")
        if item.provider not in ("external", self._provider):
            raise ValidationError("external_item_provider_mismatch")
        if item.state == "ACTIVE":
            reason = "ok"
        elif item.state == "REVOKED":
            reason = "evidence_revoked"
        else:
            reason = "evidence_unknown"
        return EvidenceSnapshot(
            evidence_id=item_id,
            backend=self._provider,
            uri=uri,
            revision=item.revision,
            content_sha256=item.content_sha256,
            state=item.state,
            certified=item.certified,
            reason=reason,
            metadata=dict(item.metadata) if item.metadata is not None else None,
        )

    def inspect(self, item_id: str) -> EvidenceSnapshot:
        """Inspects ``item_id`` via ``lookup_fn``, failing closed to ``UNAVAILABLE`` on any error."""
        validate_identifier(item_id, "external_item_id")
        uri = f"{self._provider}://{self._namespace}/{item_id}"
        try:
            item = self._lookup(item_id)
            return self._validate_returned_item(item_id, item, uri)
        except KeyError:
            not_found_reason = (
                "mories_item_not_found"
                if self._provider == "mories"
                else f"external_item_not_found:{self._provider}"
            )
            return EvidenceSnapshot(
                evidence_id=item_id,
                backend=self._provider,
                uri=uri,
                revision=0,
                content_sha256="0" * 64,
                state="UNAVAILABLE",
                certified=False,
                reason=not_found_reason,
            )
        except Exception as exc:
            err_reason = (
                f"mories_backend_unavailable:{type(exc).__name__}"
                if self._provider == "mories"
                else f"external_backend_unavailable:{self._provider}:{type(exc).__name__}"
            )
            return EvidenceSnapshot(
                evidence_id=item_id,
                backend=self._provider,
                uri=uri,
                revision=0,
                content_sha256="0" * 64,
                state="UNAVAILABLE",
                certified=False,
                reason=err_reason,
            )

    def inspect_many(self, item_ids: Sequence[str]) -> dict[str, EvidenceSnapshot]:
        """Inspects multiple item IDs, using ``batch_lookup_fn`` when supplied to prevent N+1 RPCs."""
        validated_ids = [validate_identifier(iid, "external_item_id") for iid in item_ids]
        if self._batch_lookup is None:
            return {iid: self.inspect(iid) for iid in validated_ids}
        try:
            raw_map = self._batch_lookup(validated_ids)
        except Exception as exc:
            err_reason = (
                f"mories_backend_unavailable:{type(exc).__name__}"
                if self._provider == "mories"
                else f"external_backend_unavailable:{self._provider}:{type(exc).__name__}"
            )
            return {
                iid: EvidenceSnapshot(
                    evidence_id=iid,
                    backend=self._provider,
                    uri=f"{self._provider}://{self._namespace}/{iid}",
                    revision=0,
                    content_sha256="0" * 64,
                    state="UNAVAILABLE",
                    certified=False,
                    reason=err_reason,
                )
                for iid in validated_ids
            }
        out: dict[str, EvidenceSnapshot] = {}
        for iid in validated_ids:
            uri = f"{self._provider}://{self._namespace}/{iid}"
            if iid not in raw_map:
                not_found_reason = (
                    "mories_item_not_found"
                    if self._provider == "mories"
                    else f"external_item_not_found:{self._provider}"
                )
                out[iid] = EvidenceSnapshot(
                    evidence_id=iid,
                    backend=self._provider,
                    uri=uri,
                    revision=0,
                    content_sha256="0" * 64,
                    state="UNAVAILABLE",
                    certified=False,
                    reason=not_found_reason,
                )
            else:
                try:
                    out[iid] = self._validate_returned_item(iid, raw_map[iid], uri)
                except Exception as exc:
                    out[iid] = EvidenceSnapshot(
                        evidence_id=iid,
                        backend=self._provider,
                        uri=uri,
                        revision=0,
                        content_sha256="0" * 64,
                        state="UNAVAILABLE",
                        certified=False,
                        reason=f"external_backend_unavailable:{self._provider}:{type(exc).__name__}",
                    )
        return out


class CallableMoriesAdapter(CallableExternalAdapter):
    """Backward-compatible Mories lookup wrapper built on ``CallableExternalAdapter``."""

    def __init__(self, lookup_fn: Callable[[str], ExternalMemoryItem], *, project: str = "personal") -> None:
        super().__init__(lookup_fn, provider="mories", namespace=project)


class CircuitBreakingAdapter:
    """Thread-safe fail-fast circuit breaker wrapping any ``ExternalMemoryPort``.

    Prevents cascading N * timeout hangs when an external memory provider is
    unreachable: after ``failure_threshold`` consecutive transport/backend outages,
    the circuit opens for ``cooldown_seconds`` and returns instant ``UNAVAILABLE``
    snapshots without invoking network I/O, automatically probing recovery afterward.
    """

    def __init__(
        self,
        inner: ExternalMemoryPort,
        *,
        provider: str | None = None,
        failure_threshold: int = 3,
        cooldown_seconds: float = 10.0,
    ) -> None:
        if inner is None or not callable(getattr(inner, "inspect", None)):
            raise TypeError("invalid_inner_adapter")
        inferred = provider or getattr(inner, "provider", "external")
        self._provider = validate_provider(inferred, allow_local=False)
        if type(failure_threshold) is not int or failure_threshold < 1:
            raise ValidationError("invalid_failure_threshold")
        if not isinstance(cooldown_seconds, (int, float)) or isinstance(cooldown_seconds, bool) or cooldown_seconds <= 0:
            raise ValidationError("invalid_cooldown_seconds")
        self._inner = inner
        self._threshold = failure_threshold
        self._cooldown = float(cooldown_seconds)
        self._lock = threading.Lock()
        self._consecutive_failures = 0
        self._open_until = 0.0

    @property
    def provider(self) -> str:
        return self._provider

    @property
    def is_open(self) -> bool:
        """Returns ``True`` while the circuit breaker is open and fast-failing."""
        with self._lock:
            return time.monotonic() < self._open_until

    def _open_snapshot(self, item_id: str) -> EvidenceSnapshot:
        reason = (
            "mories_backend_unavailable:circuit_open"
            if self._provider == "mories"
            else f"external_backend_unavailable:{self._provider}:circuit_open"
        )
        return EvidenceSnapshot(
            evidence_id=item_id,
            backend=self._provider,
            uri=f"{self._provider}://{item_id}",
            revision=0,
            content_sha256="0" * 64,
            state="UNAVAILABLE",
            certified=False,
            reason=reason,
        )

    def _record_batch_outage(self, had_transport_outage: bool) -> None:
        with self._lock:
            if had_transport_outage:
                self._consecutive_failures += 1
                if self._consecutive_failures >= self._threshold:
                    self._open_until = time.monotonic() + self._cooldown
            else:
                self._consecutive_failures = 0
                self._open_until = 0.0

    def _record_outcome(self, snap: EvidenceSnapshot) -> None:
        is_transport_outage = snap.state == "UNAVAILABLE" and "backend_unavailable" in snap.reason
        self._record_batch_outage(is_transport_outage)

    def inspect(self, item_id: str) -> EvidenceSnapshot:
        """Inspects ``item_id`` or fails fast with ``circuit_open`` while cooling down."""
        validate_identifier(item_id, "external_item_id")
        with self._lock:
            if time.monotonic() < self._open_until:
                return self._open_snapshot(item_id)

        try:
            snap = self._inner.inspect(item_id)
        except Exception as exc:
            err_reason = (
                f"mories_backend_unavailable:{type(exc).__name__}"
                if self._provider == "mories"
                else f"external_backend_unavailable:{self._provider}:{type(exc).__name__}"
            )
            snap = EvidenceSnapshot(
                evidence_id=item_id,
                backend=self._provider,
                uri=f"{self._provider}://{item_id}",
                revision=0,
                content_sha256="0" * 64,
                state="UNAVAILABLE",
                certified=False,
                reason=err_reason,
            )
        self._record_outcome(snap)
        return snap

    def inspect_many(self, item_ids: Sequence[str]) -> dict[str, EvidenceSnapshot]:
        """Batch-inspects ``item_ids`` with circuit-breaker short-circuiting and per-batch failure tracking."""
        validated_ids = [validate_identifier(iid, "external_item_id") for iid in item_ids]
        if not validated_ids:
            return {}
        with self._lock:
            if time.monotonic() < self._open_until:
                return {iid: self._open_snapshot(iid) for iid in validated_ids}

        batch_fn = getattr(self._inner, "inspect_many", None)
        if callable(batch_fn):
            try:
                snaps = batch_fn(validated_ids)
            except Exception as exc:
                err_reason = (
                    f"mories_backend_unavailable:{type(exc).__name__}"
                    if self._provider == "mories"
                    else f"external_backend_unavailable:{self._provider}:{type(exc).__name__}"
                )
                snaps = {
                    iid: EvidenceSnapshot(
                        evidence_id=iid,
                        backend=self._provider,
                        uri=f"{self._provider}://{iid}",
                        revision=0,
                        content_sha256="0" * 64,
                        state="UNAVAILABLE",
                        certified=False,
                        reason=err_reason,
                    )
                    for iid in validated_ids
                }
                self._record_batch_outage(True)
                return snaps

            had_outage = any(
                s.state == "UNAVAILABLE" and "backend_unavailable" in s.reason
                for s in snaps.values()
            )
            self._record_batch_outage(had_outage)
            return snaps
        return {iid: self.inspect(iid) for iid in validated_ids}


class LocalFileEvidenceAdapter:
    """Computes live SHA-256 of regular files with symlink, FIFO/device, root-escape, and size guards."""

    def __init__(
        self,
        project_root: Path | None = None,
        *,
        max_file_bytes: int = DEFAULT_MAX_FILE_BYTES,
    ) -> None:
        if type(max_file_bytes) is not int or max_file_bytes < 1:
            raise ValidationError("invalid_max_file_bytes")
        self._max_file_bytes = max_file_bytes
        if project_root is not None:
            self._raw_root: Path | None = Path(project_root).expanduser().absolute()
            self._root: Path | None = Path(project_root).resolve(strict=True)
        else:
            self._raw_root = None
            self._root = None

    @property
    def resolved_root(self) -> Path | None:
        return self._root

    def _open_verified_fd(self, target: Path) -> int:
        flags = os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0) | getattr(os, "O_NONBLOCK", 0)
        fd = os.open(str(target), flags)
        try:
            st = os.fstat(fd)
            if not stat.S_ISREG(st.st_mode):
                raise PathSecurityError("local_not_regular_file")
            if st.st_size > self._max_file_bytes:
                raise PathSecurityError("local_file_exceeds_max_bytes")
            return fd
        except Exception:
            os.close(fd)
            raise

    def _open_and_hash_regular_file(self, target: Path) -> str:
        fd = self._open_verified_fd(target)
        try:
            digest = hashlib.sha256()
            total = 0
            while True:
                chunk = os.read(fd, 65536)
                if not chunk:
                    break
                total += len(chunk)
                if total > self._max_file_bytes:
                    raise PathSecurityError("local_file_exceeds_max_bytes")
                digest.update(chunk)
            return digest.hexdigest()
        finally:
            os.close(fd)

    def _resolve_verified_target(self, file_path: str | Path) -> tuple[str, Path]:
        raw_str = str(file_path)
        if not raw_str or "\x00" in raw_str:
            raise PathSecurityError("invalid_local_path")
        p = Path(raw_str)
        if ".." in p.parts:
            raise PathSecurityError("local_parent_traversal_rejected")

        if self._root is not None:
            if not p.is_absolute():
                rel_parts = p.parts
            else:
                rel_path: Path | None = None
                for candidate_root in (self._raw_root, self._root):
                    if candidate_root is not None:
                        try:
                            rel_path = p.relative_to(candidate_root)
                            break
                        except ValueError:
                            continue
                if rel_path is None:
                    raise PathSecurityError("local_path_outside_project_root")
                rel_parts = rel_path.parts
            if not rel_parts or ".." in rel_parts:
                raise PathSecurityError("local_path_outside_project_root")

            cur = self._root
            for part in rel_parts:
                if part in ("", "."):
                    continue
                cur = cur / part
                st = os.lstat(str(cur))
                if stat.S_ISLNK(st.st_mode):
                    raise PathSecurityError("local_symlink_rejected")

            resolved = cur.resolve(strict=True)
            if not resolved.is_relative_to(self._root):
                raise PathSecurityError("local_path_outside_project_root")
            stored_uri = str(resolved.relative_to(self._root))
            return stored_uri, cur

        if not p.is_absolute():
            base = Path.cwd().resolve(strict=True)
            cur = base
            for part in p.parts:
                if part in ("", "."):
                    continue
                cur = cur / part
                if stat.S_ISLNK(os.lstat(str(cur)).st_mode):
                    raise PathSecurityError("local_symlink_rejected")
            target = cur
        else:
            if stat.S_ISLNK(os.lstat(str(p)).st_mode):
                raise PathSecurityError("local_symlink_rejected")
            target = p
        return str(target.resolve(strict=True)), target

    def resolve_and_hash(self, file_path: str | Path) -> tuple[str, str]:
        """Resolves ``file_path`` under symlink/root/size guards and returns ``(stored_uri, sha256_hex)``."""
        stored_uri, target = self._resolve_verified_target(file_path)
        hex_digest = self._open_and_hash_regular_file(target)
        return stored_uri, hex_digest

    def read_verified_text(self, file_path: str | Path) -> tuple[str, str, str]:
        """Reads UTF-8 text and SHA-256 atomically from a single verified file descriptor."""
        stored_uri, target = self._resolve_verified_target(file_path)
        fd = self._open_verified_fd(target)
        try:
            chunks: list[bytes] = []
            digest = hashlib.sha256()
            total = 0
            while True:
                chunk = os.read(fd, 65536)
                if not chunk:
                    break
                total += len(chunk)
                if total > self._max_file_bytes:
                    raise PathSecurityError("local_file_exceeds_max_bytes")
                digest.update(chunk)
                chunks.append(chunk)
            raw_bytes = b"".join(chunks)
            return stored_uri, digest.hexdigest(), raw_bytes.decode("utf-8")
        finally:
            os.close(fd)

    def inspect(self, evidence_id: str, stored_uri: str, active_revision: int) -> EvidenceSnapshot:
        """Inspects a registered local file without leaking raw host filesystem paths on error."""
        try:
            _, live_sha = self.resolve_and_hash(stored_uri)
            return EvidenceSnapshot(
                evidence_id=evidence_id,
                backend="local",
                uri=stored_uri,
                revision=active_revision,
                content_sha256=live_sha,
                state="ACTIVE",
                certified=True,
                reason="ok",
            )
        except FileNotFoundError:
            return EvidenceSnapshot(
                evidence_id=evidence_id,
                backend="local",
                uri=stored_uri,
                revision=active_revision,
                content_sha256="0" * 64,
                state="UNAVAILABLE",
                certified=False,
                reason="local_source_missing",
            )
        except PermissionError:
            return EvidenceSnapshot(
                evidence_id=evidence_id,
                backend="local",
                uri=stored_uri,
                revision=active_revision,
                content_sha256="0" * 64,
                state="UNAVAILABLE",
                certified=False,
                reason="local_source_permission_denied",
            )
        except PathSecurityError as exc:
            return EvidenceSnapshot(
                evidence_id=evidence_id,
                backend="local",
                uri=stored_uri,
                revision=active_revision,
                content_sha256="0" * 64,
                state="UNAVAILABLE",
                certified=False,
                reason=f"local_source_unreadable:{exc.code}",
            )
        except (OSError, ValueError) as exc:
            return EvidenceSnapshot(
                evidence_id=evidence_id,
                backend="local",
                uri=stored_uri,
                revision=active_revision,
                content_sha256="0" * 64,
                state="UNAVAILABLE",
                certified=False,
                reason=f"local_source_io_error:{type(exc).__name__}",
            )
