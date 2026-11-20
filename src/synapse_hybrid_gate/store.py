"""SQLite WAL zero-copy dependency, hash-chained receipt, lossless token-cache,
and parallel optimistic-concurrency gate with Universal Memory Port.
"""
from __future__ import annotations

from collections.abc import Callable, Iterable, Mapping, Sequence
from dataclasses import dataclass
import hashlib
import html
import json
import os
from pathlib import Path
import random
import sqlite3
import stat
import time
from typing import Any
import uuid

from .adapters import (
    DEFAULT_MAX_FILE_BYTES,
    EvidenceSnapshot,
    ExternalMemoryPort,
    LocalFileEvidenceAdapter,
    MoriesEvidenceAdapter,
    OfflineExternalAdapter,
    OfflineMoriesAdapter,
    validate_identifier,
    validate_provider,
    validate_sha256,
)
from .context_cache import CachedStepOutcome, KVPinnedContextPlan, WorkLease
from .core_hook import NormativeGatePort
from .exceptions import (
    EvidenceConflictError,
    PathSecurityError,
    ReadOnlyGateError,
    SchemaVersionError,
    StaleWorkConflictError,
    ValidationError,
)


SCHEMA_VERSION = "synapse-hybrid-gate-sqlite-v3"
LEGACY_SCHEMA_V1 = "synapse-hybrid-gate-sqlite-v1"
LEGACY_SCHEMA_V2 = "synapse-hybrid-gate-sqlite-v2"
GENESIS_CHAIN_HASH = "0" * 64
DEFAULT_MAX_PAYLOAD_BYTES = 4 * 1024 * 1024  # 4 MiB cached payload ceiling


@dataclass(frozen=True, slots=True)
class GateCheckResult:
    """Deterministic gate evaluation verdict for a bound task or fast-path key."""

    task_id: str
    decision: str  # 'ALLOW' | 'HOLD' | 'DENY'
    reason: str
    receipt_id: str | None = None
    outcome_sha256: str | None = None
    checked_dependencies: int = 0


def _canonical_json(obj: Any) -> str:
    return json.dumps(obj, sort_keys=True, separators=(",", ":"), ensure_ascii=True)


def _compute_dependency_digest(rows: list[tuple[str, int, int, str]]) -> str:
    ordered = sorted(rows, key=lambda r: r[0])
    payload = _canonical_json(
        [
            {"epoch": int(epoch), "evidence_id": eid, "revision": int(rev), "sha256": sha}
            for eid, epoch, rev, sha in ordered
        ]
    )
    return hashlib.sha256(payload.encode("utf-8")).hexdigest()


def _compute_chain_hash(
    prev_chain_sha256: str,
    seq: int,
    receipt_id: str,
    task_id: str,
    decision: str,
    reason: str,
    dependency_digest: str,
    outcome_sha256: str,
    created_ns: int,
) -> str:
    body = _canonical_json(
        {
            "created_ns": int(created_ns),
            "decision": decision,
            "dependency_digest": dependency_digest,
            "outcome_sha256": outcome_sha256,
            "reason": reason,
            "receipt_id": receipt_id,
            "seq": int(seq),
            "task_id": task_id,
        }
    )
    return hashlib.sha256(f"{prev_chain_sha256}:{body}".encode("utf-8")).hexdigest()


def _apply_owner_only_permissions(path: Path) -> None:
    if os.name != "posix":
        return
    for candidate in (path, Path(f"{path}-wal"), Path(f"{path}-shm")):
        try:
            st = os.lstat(str(candidate))
            if stat.S_ISREG(st.st_mode):
                os.chmod(candidate, 0o600)
        except OSError:
            pass


def _ensure_kv_order_columns(conn: sqlite3.Connection) -> bool:
    """Idempotently adds KV-prefix stable ordering columns on existing SQLite schemas."""
    changed = False
    ev_cols = {
        r["name"]
        for r in conn.execute("PRAGMA table_info(evidence_sources)").fetchall()
    }
    if ev_cols and "last_mutated_ns" not in ev_cols:
        conn.execute(
            "ALTER TABLE evidence_sources ADD COLUMN last_mutated_ns INTEGER NOT NULL DEFAULT 0"
        )
        changed = True

    dep_cols = {
        r["name"]
        for r in conn.execute("PRAGMA table_info(task_dependencies)").fetchall()
    }
    if dep_cols:
        if "bind_seq" not in dep_cols:
            conn.execute(
                "ALTER TABLE task_dependencies ADD COLUMN bind_seq INTEGER NOT NULL DEFAULT 0"
            )
            changed = True
        if "last_mutated_ns" not in dep_cols:
            conn.execute(
                "ALTER TABLE task_dependencies ADD COLUMN last_mutated_ns INTEGER NOT NULL DEFAULT 0"
            )
            changed = True
    return changed


def migrate_database(db_path: str | Path, *, secure_permissions: bool = True) -> dict[str, Any]:
    """Atomically upgrades a ``v1`` (0.1.0) or ``v2`` (0.2.0) SQLite database to ``v3`` (0.3.0).

    Args:
        db_path: Path to an existing SQLite gate database.
        secure_permissions: If True, tightens file mode to ``0600`` on POSIX.

    Returns:
        Dictionary summarizing ``migrated_from``, ``migrated_to``, and ``changed``.

    Raises:
        SchemaVersionError: If the database is missing ``gate_meta`` or has an unknown schema.
    """
    target = Path(db_path)
    if not target.is_file():
        raise SchemaVersionError("database_file_not_found")
    if stat.S_ISLNK(os.lstat(str(target)).st_mode):
        raise PathSecurityError("database_symlink_rejected")
    conn = sqlite3.connect(str(target), isolation_level=None, timeout=10.0)
    conn.row_factory = sqlite3.Row
    try:
        conn.execute("PRAGMA busy_timeout=10000")
        conn.execute("PRAGMA foreign_keys=OFF")
        conn.execute("BEGIN IMMEDIATE")
        try:
            tables = {
                r["name"]
                for r in conn.execute("SELECT name FROM sqlite_master WHERE type='table'").fetchall()
            }
            if "gate_meta" not in tables:
                raise SchemaVersionError("corrupted_gate_meta")
            meta = {
                r["key"]: r["value"]
                for r in conn.execute("SELECT key, value FROM gate_meta").fetchall()
            }
            if "project_root" not in meta or "head_seq" not in meta or "head_chain_sha256" not in meta:
                raise SchemaVersionError("corrupted_gate_meta")
            current = meta.get("schema")
            if current == SCHEMA_VERSION:
                patched = _ensure_kv_order_columns(conn)
                conn.execute("COMMIT")
                return {"migrated_from": SCHEMA_VERSION, "migrated_to": SCHEMA_VERSION, "changed": patched}
            if current not in (LEGACY_SCHEMA_V1, LEGACY_SCHEMA_V2):
                raise SchemaVersionError("incompatible_schema_version")

            if current == LEGACY_SCHEMA_V1:
                conn.execute(
                    """
                    CREATE TABLE evidence_sources_v3 (
                        evidence_id TEXT PRIMARY KEY,
                        kind TEXT NOT NULL CHECK(kind IN ('local', 'external')),
                        provider TEXT NOT NULL,
                        uri TEXT NOT NULL,
                        external_id TEXT NOT NULL,
                        epoch INTEGER NOT NULL CHECK(epoch >= 1),
                        active_revision INTEGER NOT NULL CHECK(active_revision >= 1),
                        content_sha256 TEXT NOT NULL,
                        state TEXT NOT NULL CHECK(state IN ('ACTIVE', 'REVOKED')),
                        certified INTEGER NOT NULL CHECK(certified IN (0, 1)),
                        require_certified INTEGER NOT NULL CHECK(require_certified IN (0, 1)),
                        updated_ns INTEGER NOT NULL,
                        last_mutated_ns INTEGER NOT NULL DEFAULT 0,
                        CHECK((kind = 'local' AND provider = 'local') OR (kind = 'external' AND provider <> 'local'))
                    )
                    """
                )
                conn.execute(
                    """
                    INSERT INTO evidence_sources_v3(
                        evidence_id, kind, provider, uri, external_id, epoch, active_revision,
                        content_sha256, state, certified, require_certified, updated_ns, last_mutated_ns
                    )
                    SELECT
                        evidence_id,
                        CASE WHEN backend = 'local' THEN 'local' ELSE 'external' END,
                        backend,
                        uri,
                        external_id,
                        epoch,
                        active_revision,
                        content_sha256,
                        state,
                        certified,
                        require_certified,
                        updated_ns,
                        0
                    FROM evidence_sources
                    """
                )
                conn.execute("DROP TABLE evidence_sources")
                conn.execute("ALTER TABLE evidence_sources_v3 RENAME TO evidence_sources")
                conn.execute("CREATE INDEX IF NOT EXISTS idx_evidence_provider ON evidence_sources(provider)")

            _ensure_kv_order_columns(conn)

            conn.execute(
                """
                CREATE TABLE IF NOT EXISTS verified_outcome_cache (
                    task_id TEXT NOT NULL REFERENCES task_specs(task_id) ON DELETE CASCADE,
                    prompt_sha256 TEXT NOT NULL,
                    receipt_id TEXT NOT NULL REFERENCES audit_receipts(receipt_id),
                    dependency_digest TEXT NOT NULL,
                    outcome_sha256 TEXT NOT NULL,
                    payload_text TEXT NOT NULL,
                    input_tokens INTEGER NOT NULL CHECK(input_tokens >= 0),
                    output_tokens INTEGER NOT NULL CHECK(output_tokens >= 0),
                    hit_count INTEGER NOT NULL DEFAULT 0 CHECK(hit_count >= 0),
                    created_ns INTEGER NOT NULL,
                    PRIMARY KEY (task_id, prompt_sha256)
                )
                """
            )
            for k in (
                "avoided_calls",
                "saved_input_tokens",
                "saved_output_tokens",
                "executed_calls",
                "executed_input_tokens",
                "executed_output_tokens",
                "kv_prompts_built",
                "kv_prefix_chars_total",
                "kv_prompt_chars_total",
            ):
                conn.execute("INSERT OR IGNORE INTO gate_meta(key, value) VALUES (?, '0')", (k,))
            conn.execute("UPDATE gate_meta SET value = ? WHERE key = 'schema'", (SCHEMA_VERSION,))
            fk_violations = conn.execute("PRAGMA foreign_key_check").fetchall()
            if fk_violations:
                raise SchemaVersionError("migration_foreign_key_violation")
            conn.execute("COMMIT")
            conn.execute("PRAGMA foreign_keys=ON")
        except Exception:
            if conn.in_transaction:
                try:
                    conn.execute("ROLLBACK")
                except sqlite3.Error:
                    pass
            raise
    finally:
        conn.close()

    if secure_permissions:
        _apply_owner_only_permissions(target)
    return {"migrated_from": current, "migrated_to": SCHEMA_VERSION, "changed": True}


class HybridEvidenceGate:
    """Vendor-neutral SQLite WAL evidence dependency gate with lossless token-saving cache,
    KV-prefix pinning, multi-process concurrency support, and optional normative hooks.
    """

    def __init__(
        self,
        db_path: str | Path,
        *,
        project_root: str | Path | None = None,
        providers: Mapping[str, ExternalMemoryPort] | None = None,
        mories_adapter: MoriesEvidenceAdapter | None = None,
        normative_gate: NormativeGatePort | None = None,
        read_only: bool = False,
        busy_timeout_ms: int = 10_000,
        max_file_bytes: int = DEFAULT_MAX_FILE_BYTES,
        max_payload_bytes: int = DEFAULT_MAX_PAYLOAD_BYTES,
        secure_permissions: bool = True,
    ) -> None:
        if not isinstance(read_only, bool):
            raise ValidationError("invalid_read_only_flag")
        if type(busy_timeout_ms) is not int or busy_timeout_ms < 0:
            raise ValidationError("invalid_busy_timeout_ms")
        if type(max_payload_bytes) is not int or max_payload_bytes < 1:
            raise ValidationError("invalid_max_payload_bytes")

        self._closed = False
        self._read_only = read_only
        self._busy_timeout_ms = busy_timeout_ms
        self._max_file_bytes = max_file_bytes
        self._max_payload_bytes = max_payload_bytes
        self._secure_permissions = secure_permissions
        self._db_path = Path(db_path)

        supplied_root = Path(project_root).resolve(strict=True) if project_root is not None else None
        self._root: Path | None = supplied_root

        resolved_providers: dict[str, ExternalMemoryPort] = {}
        if providers is not None:
            if not isinstance(providers, Mapping):
                raise TypeError("invalid_providers_mapping")
            for prov_name, adapter in providers.items():
                slug = validate_provider(prov_name, allow_local=False)
                if adapter is None or not callable(getattr(adapter, "inspect", None)):
                    raise TypeError(f"invalid_provider_adapter:{slug}")
                resolved_providers[slug] = adapter
        if mories_adapter is not None:
            if "mories" in resolved_providers and resolved_providers["mories"] is not mories_adapter:
                raise ValidationError("duplicate_mories_provider_configuration")
            if not callable(getattr(mories_adapter, "inspect", None)):
                raise TypeError("invalid_provider_adapter:mories")
            resolved_providers["mories"] = mories_adapter

        self._providers = resolved_providers
        self._normative = normative_gate

        timeout_sec = max(0.1, busy_timeout_ms / 1000.0)
        if read_only:
            if not self._db_path.is_file():
                raise SchemaVersionError("database_file_not_found")
            ro_uri = f"{self._db_path.resolve(strict=True).as_uri()}?mode=ro"
            self._conn = sqlite3.connect(ro_uri, uri=True, isolation_level=None, timeout=timeout_sec)
        else:
            self._db_path.parent.mkdir(parents=True, exist_ok=True)
            self._conn = sqlite3.connect(str(self._db_path), isolation_level=None, timeout=timeout_sec)
            if secure_permissions:
                _apply_owner_only_permissions(self._db_path)

        try:
            self._conn.row_factory = sqlite3.Row
            self._conn.execute(f"PRAGMA busy_timeout={int(busy_timeout_ms)}")
            self._conn.execute("PRAGMA foreign_keys=ON")
            if read_only:
                self._conn.execute("PRAGMA query_only=ON")
                self._verify_existing_schema(
                    supplied_root,
                    raw_project_root=Path(project_root) if project_root is not None else None,
                )
            else:
                self._conn.execute("PRAGMA journal_mode=WAL")
                self._conn.execute("PRAGMA synchronous=NORMAL")
                self._init_schema(
                    supplied_root,
                    raw_project_root=Path(project_root) if project_root is not None else None,
                )
                if secure_permissions:
                    _apply_owner_only_permissions(self._db_path)
        except Exception:
            self.close()
            raise

    def __enter__(self) -> HybridEvidenceGate:
        return self

    def __exit__(self, exc_type: Any, exc: Any, tb: Any) -> None:
        self.close()

    @property
    def closed(self) -> bool:
        """Returns True if the underlying SQLite connection has been closed."""
        return self._closed

    def close(self) -> None:
        """Idempotently closes the underlying SQLite connection and releases file descriptors."""
        if not self._closed:
            self._closed = True
            try:
                self._conn.close()
            except sqlite3.Error:
                pass

    def _require_writable(self) -> None:
        if self._read_only:
            raise ReadOnlyGateError("read_only_gate_cannot_write")

    def _resolve_provider(self, provider: str) -> ExternalMemoryPort:
        slug = validate_provider(provider, allow_local=False)
        adapter = self._providers.get(slug)
        if adapter is not None:
            return adapter
        return OfflineMoriesAdapter() if slug == "mories" else OfflineExternalAdapter(slug)

    def _bind_verified_root(
        self,
        meta: dict[str, str],
        supplied_root: Path | None,
        raw_project_root: Path | None,
    ) -> Path | None:
        if meta.get("schema") != SCHEMA_VERSION:
            raise SchemaVersionError("incompatible_schema_version")
        if "project_root" not in meta or "head_seq" not in meta or "head_chain_sha256" not in meta:
            raise SchemaVersionError("corrupted_gate_meta")
        stored_root = meta["project_root"]
        if stored_root == "":
            if supplied_root is not None:
                raise SchemaVersionError("project_root_mismatch")
            self._root = None
            return None
        resolved_stored = Path(stored_root).resolve(strict=True)
        if supplied_root is not None and supplied_root != resolved_stored:
            raise SchemaVersionError("project_root_mismatch")
        self._root = resolved_stored
        return raw_project_root if raw_project_root is not None else resolved_stored

    def _verify_existing_schema(self, supplied_root: Path | None, *, raw_project_root: Path | None) -> None:
        try:
            meta = {
                r["key"]: r["value"]
                for r in self._conn.execute("SELECT key, value FROM gate_meta").fetchall()
            }
        except sqlite3.Error as exc:
            raise SchemaVersionError("corrupted_gate_meta") from exc
        effective_raw_root = self._bind_verified_root(meta, supplied_root, raw_project_root)
        dep_cols = {
            r["name"]
            for r in self._conn.execute("PRAGMA table_info(task_dependencies)").fetchall()
        }
        ev_cols = {
            r["name"]
            for r in self._conn.execute("PRAGMA table_info(evidence_sources)").fetchall()
        }
        self._has_dep_order_cols = "bind_seq" in dep_cols and "last_mutated_ns" in dep_cols
        self._has_ev_mutated_col = "last_mutated_ns" in ev_cols
        self._local = LocalFileEvidenceAdapter(effective_raw_root, max_file_bytes=self._max_file_bytes)

    def _init_schema(self, supplied_root: Path | None, *, raw_project_root: Path | None) -> None:
        ddl_statements = (
            """
            CREATE TABLE IF NOT EXISTS gate_meta (
                key TEXT PRIMARY KEY,
                value TEXT NOT NULL
            )
            """,
            """
            CREATE TABLE IF NOT EXISTS evidence_sources (
                evidence_id TEXT PRIMARY KEY,
                kind TEXT NOT NULL CHECK(kind IN ('local', 'external')),
                provider TEXT NOT NULL,
                uri TEXT NOT NULL,
                external_id TEXT NOT NULL,
                epoch INTEGER NOT NULL CHECK(epoch >= 1),
                active_revision INTEGER NOT NULL CHECK(active_revision >= 1),
                content_sha256 TEXT NOT NULL,
                state TEXT NOT NULL CHECK(state IN ('ACTIVE', 'REVOKED')),
                certified INTEGER NOT NULL CHECK(certified IN (0, 1)),
                require_certified INTEGER NOT NULL CHECK(require_certified IN (0, 1)),
                updated_ns INTEGER NOT NULL,
                last_mutated_ns INTEGER NOT NULL DEFAULT 0,
                CHECK((kind = 'local' AND provider = 'local') OR (kind = 'external' AND provider <> 'local'))
            )
            """,
            "CREATE INDEX IF NOT EXISTS idx_evidence_provider ON evidence_sources(provider)",
            """
            CREATE TABLE IF NOT EXISTS task_specs (
                task_id TEXT PRIMARY KEY,
                title TEXT NOT NULL,
                created_ns INTEGER NOT NULL
            )
            """,
            """
            CREATE TABLE IF NOT EXISTS task_dependencies (
                task_id TEXT NOT NULL REFERENCES task_specs(task_id) ON DELETE CASCADE,
                evidence_id TEXT NOT NULL REFERENCES evidence_sources(evidence_id),
                bound_epoch INTEGER NOT NULL CHECK(bound_epoch >= 1),
                bound_revision INTEGER NOT NULL CHECK(bound_revision >= 1),
                bound_sha256 TEXT NOT NULL,
                bind_seq INTEGER NOT NULL DEFAULT 0,
                last_mutated_ns INTEGER NOT NULL DEFAULT 0,
                PRIMARY KEY (task_id, evidence_id)
            )
            """,
            "CREATE INDEX IF NOT EXISTS idx_task_dep_evidence ON task_dependencies(evidence_id)",
            """
            CREATE TABLE IF NOT EXISTS audit_receipts (
                seq INTEGER PRIMARY KEY AUTOINCREMENT,
                receipt_id TEXT NOT NULL UNIQUE,
                task_id TEXT NOT NULL REFERENCES task_specs(task_id),
                decision TEXT NOT NULL CHECK(decision IN ('ALLOW', 'HOLD', 'DENY')),
                reason TEXT NOT NULL,
                dependency_digest TEXT NOT NULL,
                outcome_sha256 TEXT NOT NULL,
                prev_chain_sha256 TEXT NOT NULL,
                chain_sha256 TEXT NOT NULL,
                created_ns INTEGER NOT NULL
            )
            """,
            "CREATE INDEX IF NOT EXISTS idx_receipts_task_seq ON audit_receipts(task_id, seq DESC)",
            """
            CREATE TABLE IF NOT EXISTS fast_file_cache (
                cache_key TEXT PRIMARY KEY,
                file_uri TEXT NOT NULL,
                file_sha256 TEXT NOT NULL,
                outcome_sha256 TEXT NOT NULL,
                updated_ns INTEGER NOT NULL
            )
            """,
            """
            CREATE TABLE IF NOT EXISTS verified_outcome_cache (
                task_id TEXT NOT NULL REFERENCES task_specs(task_id) ON DELETE CASCADE,
                prompt_sha256 TEXT NOT NULL,
                receipt_id TEXT NOT NULL REFERENCES audit_receipts(receipt_id),
                dependency_digest TEXT NOT NULL,
                outcome_sha256 TEXT NOT NULL,
                payload_text TEXT NOT NULL,
                input_tokens INTEGER NOT NULL CHECK(input_tokens >= 0),
                output_tokens INTEGER NOT NULL CHECK(output_tokens >= 0),
                hit_count INTEGER NOT NULL DEFAULT 0 CHECK(hit_count >= 0),
                created_ns INTEGER NOT NULL,
                PRIMARY KEY (task_id, prompt_sha256)
            )
            """,
        )
        counter_keys = (
            "avoided_calls",
            "saved_input_tokens",
            "saved_output_tokens",
            "executed_calls",
            "executed_input_tokens",
            "executed_output_tokens",
            "kv_prompts_built",
            "kv_prefix_chars_total",
            "kv_prompt_chars_total",
        )
        with self._tx():
            meta_exists = self._conn.execute(
                "SELECT name FROM sqlite_master WHERE type='table' AND name='gate_meta'"
            ).fetchone()
            if meta_exists is not None:
                existing_meta = {
                    r["key"]: r["value"]
                    for r in self._conn.execute("SELECT key, value FROM gate_meta").fetchall()
                }
                if "schema" in existing_meta and existing_meta["schema"] != SCHEMA_VERSION:
                    raise SchemaVersionError("incompatible_schema_version")

            for stmt in ddl_statements:
                self._conn.execute(stmt)
            voc_cols = {
                r["name"]
                for r in self._conn.execute("PRAGMA table_info(verified_outcome_cache)").fetchall()
            }
            if "hit_count" not in voc_cols:
                self._conn.execute(
                    "ALTER TABLE verified_outcome_cache ADD COLUMN hit_count INTEGER NOT NULL DEFAULT 0"
                )
            _ensure_kv_order_columns(self._conn)
            meta = {
                r["key"]: r["value"]
                for r in self._conn.execute("SELECT key, value FROM gate_meta").fetchall()
            }
            if "schema" not in meta:
                encoded_root = str(supplied_root) if supplied_root is not None else ""
                self._conn.execute(
                    """
                    INSERT INTO gate_meta(key, value) VALUES
                        ('schema', ?),
                        ('project_root', ?),
                        ('head_seq', '0'),
                        ('head_chain_sha256', ?)
                    """,
                    (SCHEMA_VERSION, encoded_root, GENESIS_CHAIN_HASH),
                )
                for k in counter_keys:
                    self._conn.execute("INSERT INTO gate_meta(key, value) VALUES (?, '0')", (k,))
                effective_raw_root = raw_project_root
            else:
                effective_raw_root = self._bind_verified_root(meta, supplied_root, raw_project_root)
                for k in counter_keys:
                    self._conn.execute("INSERT OR IGNORE INTO gate_meta(key, value) VALUES (?, '0')", (k,))

        self._has_dep_order_cols = True
        self._has_ev_mutated_col = True
        self._local = LocalFileEvidenceAdapter(effective_raw_root, max_file_bytes=self._max_file_bytes)

    class _TxContext:
        def __init__(self, conn: sqlite3.Connection, busy_timeout_ms: int) -> None:
            self._conn = conn
            self._deadline_sec = max(0.05, busy_timeout_ms / 1000.0)

        def __enter__(self) -> sqlite3.Connection:
            deadline = time.monotonic() + self._deadline_sec
            while True:
                try:
                    self._conn.execute("BEGIN IMMEDIATE")
                    return self._conn
                except sqlite3.OperationalError as exc:
                    msg = str(exc).lower()
                    if ("locked" in msg or "busy" in msg) and time.monotonic() < deadline:
                        time.sleep(random.uniform(0.004, 0.02))
                        continue
                    raise

        def __exit__(self, exc_type: Any, exc: Any, tb: Any) -> None:
            if exc_type is None:
                self._conn.execute("COMMIT")
            elif self._conn.in_transaction:
                try:
                    self._conn.execute("ROLLBACK")
                except sqlite3.Error:
                    pass

    def _tx(self) -> _TxContext:
        self._require_writable()
        return self._TxContext(self._conn, self._busy_timeout_ms)

    class _ReadSnapshotContext:
        """Acquires a zero-blocking SQLite WAL MVCC point-in-time read snapshot across multi-statement reads."""

        def __init__(self, conn: sqlite3.Connection) -> None:
            self._conn = conn
            self._started = False

        def __enter__(self) -> sqlite3.Connection:
            if not self._conn.in_transaction:
                self._conn.execute("BEGIN DEFERRED")
                self._started = True
            return self._conn

        def __exit__(self, exc_type: Any, exc: Any, tb: Any) -> None:
            if self._started and self._conn.in_transaction:
                try:
                    if exc_type is None:
                        self._conn.execute("COMMIT")
                    else:
                        self._conn.execute("ROLLBACK")
                except sqlite3.Error:
                    pass

    def _read_snapshot(self) -> _ReadSnapshotContext:
        return self._ReadSnapshotContext(self._conn)

    # ------------------------------------------------------------------
    # Evidence Registration & Lifecycle
    # ------------------------------------------------------------------
    def _next_evidence_mutated_ns(self, now_ns: int) -> int:
        row = self._conn.execute(
            "SELECT COALESCE(MAX(last_mutated_ns), 0) AS max_ns FROM evidence_sources"
        ).fetchone()
        max_ns = int(row["max_ns"]) if row is not None else 0
        return max(now_ns, max_ns + 1)

    def register_local_evidence(self, evidence_id: str, file_path: str | Path) -> EvidenceSnapshot:
        """Registers or updates a regular local file evidence pointer.

        Args:
            evidence_id: Unique logical identifier for this evidence item.
            file_path: Path to a regular file (within ``project_root`` if bounded).

        Returns:
            ``EvidenceSnapshot`` containing the active revision and SHA-256 digest.

        Raises:
            PathSecurityError: On symlink, traversal, root escape, non-regular file, or size limit breach.
            EvidenceConflictError: If ``evidence_id`` was previously registered to an external provider.
        """
        self._require_writable()
        validate_identifier(evidence_id, "evidence_id")
        stored_uri, digest = self._local.resolve_and_hash(file_path)
        now_ns = time.time_ns()
        with self._tx():
            existing = self._conn.execute(
                """
                SELECT kind, provider, uri, epoch, active_revision, content_sha256, state, last_mutated_ns
                FROM evidence_sources WHERE evidence_id = ?
                """,
                (evidence_id,),
            ).fetchone()
            if existing is None:
                rev = 1
                self._conn.execute(
                    """
                    INSERT INTO evidence_sources(
                        evidence_id, kind, provider, uri, external_id, epoch, active_revision,
                        content_sha256, state, certified, require_certified, updated_ns, last_mutated_ns
                    ) VALUES (?, 'local', 'local', ?, ?, 1, ?, ?, 'ACTIVE', 1, 1, ?, 0)
                    """,
                    (evidence_id, stored_uri, stored_uri, rev, digest, now_ns),
                )
            else:
                if existing["kind"] != "local" or existing["provider"] != "local":
                    raise EvidenceConflictError("evidence_backend_mismatch")
                unchanged = (
                    existing["content_sha256"] == digest
                    and existing["state"] == "ACTIVE"
                    and existing["uri"] == stored_uri
                )
                epoch = (
                    int(existing["epoch"]) + 1
                    if existing["state"] != "ACTIVE" or existing["uri"] != stored_uri
                    else int(existing["epoch"])
                )
                rev = int(existing["active_revision"]) if unchanged else int(existing["active_revision"]) + 1
                mutated_ns = (
                    int(existing["last_mutated_ns"])
                    if unchanged
                    else self._next_evidence_mutated_ns(now_ns)
                )
                self._conn.execute(
                    """
                    UPDATE evidence_sources
                    SET uri = ?, external_id = ?, epoch = ?, active_revision = ?, content_sha256 = ?,
                        state = 'ACTIVE', certified = 1, updated_ns = ?, last_mutated_ns = ?
                    WHERE evidence_id = ?
                    """,
                    (stored_uri, stored_uri, epoch, rev, digest, now_ns, mutated_ns, evidence_id),
                )
        return EvidenceSnapshot(
            evidence_id=evidence_id,
            backend="local",
            uri=stored_uri,
            revision=rev,
            content_sha256=digest,
            state="ACTIVE",
            certified=True,
        )

    def register_external_evidence(
        self,
        evidence_id: str,
        item_id: str,
        *,
        provider: str = "external",
        require_certified: bool = True,
    ) -> EvidenceSnapshot:
        """Registers or refreshes an external memory item pointer from ``provider``.

        Args:
            evidence_id: Unique logical identifier in the gate database.
            item_id: Upstream item identifier in the external memory store.
            provider: Lowercase provider slug (e.g. ``'mem0'``, ``'zep'``, ``'postgres'``, ``'mories'``).
            require_certified: Whether ``check_task`` requires ``certified=True`` on live inspection.

        Returns:
            Normalized ``EvidenceSnapshot`` recorded in SQLite.

        Raises:
            ValidationError: On malformed IDs, reserved ``provider='local'``, or invalid snapshot fields.
            EvidenceConflictError: If inactive/unavailable upstream or conflicting with an existing provider.
        """
        self._require_writable()
        validate_identifier(evidence_id, "evidence_id")
        validate_identifier(item_id, "external_item_id")
        slug = validate_provider(provider, allow_local=False)
        if not isinstance(require_certified, bool):
            raise ValidationError("invalid_require_certified")

        adapter = self._resolve_provider(slug)
        try:
            snap = adapter.inspect(item_id)
        except Exception as exc:
            raise EvidenceConflictError(f"external_inspect_failed:{slug}:{type(exc).__name__}") from exc
        if not isinstance(snap, EvidenceSnapshot) or snap.state != "ACTIVE":
            reason = getattr(snap, "reason", "invalid_snapshot")
            raise EvidenceConflictError(f"cannot_register_inactive_external_evidence:{slug}:{reason}")
        if snap.evidence_id != item_id:
            raise ValidationError(f"external_snapshot_item_id_mismatch:{slug}")
        if snap.backend not in (slug, "external"):
            raise ValidationError(f"external_snapshot_provider_mismatch:{snap.backend}:{slug}")
        validated_sha = validate_sha256(snap.content_sha256, "external_snapshot_sha256")
        if type(snap.revision) is not int or snap.revision < 1:
            raise ValidationError("invalid_external_snapshot_revision")
        if not isinstance(snap.certified, bool):
            raise ValidationError("invalid_external_snapshot_certified")

        normalized_snap = EvidenceSnapshot(
            evidence_id=snap.evidence_id,
            backend=slug,
            uri=snap.uri,
            revision=snap.revision,
            content_sha256=validated_sha,
            state=snap.state,
            certified=snap.certified,
            reason=snap.reason,
            metadata=dict(snap.metadata) if snap.metadata is not None else None,
        )

        now_ns = time.time_ns()
        with self._tx():
            existing = self._conn.execute(
                """
                SELECT kind, provider, external_id, epoch, active_revision, content_sha256, state, last_mutated_ns
                FROM evidence_sources WHERE evidence_id = ?
                """,
                (evidence_id,),
            ).fetchone()
            if existing is None:
                self._conn.execute(
                    """
                    INSERT INTO evidence_sources(
                        evidence_id, kind, provider, uri, external_id, epoch, active_revision,
                        content_sha256, state, certified, require_certified, updated_ns, last_mutated_ns
                    ) VALUES (?, 'external', ?, ?, ?, 1, ?, ?, 'ACTIVE', ?, ?, ?, 0)
                    """,
                    (
                        evidence_id,
                        slug,
                        normalized_snap.uri,
                        item_id,
                        normalized_snap.revision,
                        validated_sha,
                        int(normalized_snap.certified),
                        int(require_certified),
                        now_ns,
                    ),
                )
            else:
                if existing["kind"] != "external":
                    raise EvidenceConflictError("evidence_backend_mismatch")
                if existing["provider"] != slug:
                    raise EvidenceConflictError(f"evidence_provider_mismatch:{existing['provider']}->{slug}")
                new_epoch = (
                    int(existing["epoch"]) + 1
                    if existing["external_id"] != item_id
                    else int(existing["epoch"])
                )
                unchanged = (
                    existing["external_id"] == item_id
                    and existing["state"] == "ACTIVE"
                    and int(existing["active_revision"]) == normalized_snap.revision
                    and existing["content_sha256"] == validated_sha
                )
                mutated_ns = (
                    int(existing["last_mutated_ns"])
                    if unchanged
                    else self._next_evidence_mutated_ns(now_ns)
                )
                self._conn.execute(
                    """
                    UPDATE evidence_sources
                    SET uri = ?, external_id = ?, epoch = ?, active_revision = ?,
                        content_sha256 = ?, state = 'ACTIVE', certified = ?,
                        require_certified = ?, updated_ns = ?, last_mutated_ns = ?
                    WHERE evidence_id = ?
                    """,
                    (
                        normalized_snap.uri,
                        item_id,
                        new_epoch,
                        normalized_snap.revision,
                        validated_sha,
                        int(normalized_snap.certified),
                        int(require_certified),
                        now_ns,
                        mutated_ns,
                        evidence_id,
                    ),
                )
        return normalized_snap

    def refresh_external_evidence(self, evidence_id: str) -> EvidenceSnapshot:
        """Re-inspects an existing external evidence item and updates its stored revision/hash."""
        self._require_writable()
        validate_identifier(evidence_id, "evidence_id")
        row = self._conn.execute(
            "SELECT kind, provider, external_id, require_certified FROM evidence_sources WHERE evidence_id = ?",
            (evidence_id,),
        ).fetchone()
        if row is None or row["kind"] != "external":
            raise ValidationError("unknown_external_evidence")
        return self.register_external_evidence(
            evidence_id,
            row["external_id"],
            provider=row["provider"],
            require_certified=bool(row["require_certified"]),
        )

    def register_mories_evidence(
        self,
        evidence_id: str,
        mories_item_id: str,
        *,
        require_certified: bool = True,
    ) -> EvidenceSnapshot:
        """Backward-compatible helper delegating to ``register_external_evidence(..., provider='mories')``."""
        return self.register_external_evidence(
            evidence_id,
            mories_item_id,
            provider="mories",
            require_certified=require_certified,
        )

    def refresh_mories_evidence(self, evidence_id: str) -> EvidenceSnapshot:
        """Backward-compatible helper refreshing a ``provider='mories'`` evidence item."""
        self._require_writable()
        validate_identifier(evidence_id, "evidence_id")
        row = self._conn.execute(
            "SELECT kind, provider, external_id, require_certified FROM evidence_sources WHERE evidence_id = ?",
            (evidence_id,),
        ).fetchone()
        if row is None or row["kind"] != "external" or row["provider"] != "mories":
            raise ValidationError("unknown_mories_evidence")
        return self.register_external_evidence(
            evidence_id,
            row["external_id"],
            provider="mories",
            require_certified=bool(row["require_certified"]),
        )

    def revoke_evidence(self, evidence_id: str) -> list[str]:
        """Marks ``evidence_id`` as ``REVOKED``, increments its monotonic ``epoch``, and returns affected tasks."""
        self._require_writable()
        validate_identifier(evidence_id, "evidence_id")
        now_ns = time.time_ns()
        with self._tx():
            mutated_ns = self._next_evidence_mutated_ns(now_ns)
            cur = self._conn.execute(
                """
                UPDATE evidence_sources
                SET state = 'REVOKED', epoch = epoch + 1, active_revision = active_revision + 1,
                    updated_ns = ?, last_mutated_ns = ?
                WHERE evidence_id = ?
                """,
                (now_ns, mutated_ns, evidence_id),
            )
            if cur.rowcount == 0:
                raise ValidationError("unknown_evidence_id")
        return self.affected_tasks(evidence_id)

    def affected_tasks(self, evidence_id: str) -> list[str]:
        """Returns sorted ``task_id``s currently bound to ``evidence_id``."""
        validate_identifier(evidence_id, "evidence_id")
        rows = self._conn.execute(
            "SELECT task_id FROM task_dependencies WHERE evidence_id = ? ORDER BY task_id",
            (evidence_id,),
        ).fetchall()
        return [r["task_id"] for r in rows]

    # ------------------------------------------------------------------
    # Tasks, Bindings, Optimistic Leases & Hash-Chained Receipts
    # ------------------------------------------------------------------
    def register_task(self, task_id: str, title: str) -> None:
        """Registers or updates a task specification."""
        self._require_writable()
        validate_identifier(task_id, "task_id")
        if not isinstance(title, str) or not title.strip():
            raise ValidationError("invalid_task_title")
        with self._tx():
            self._conn.execute(
                """
                INSERT INTO task_specs(task_id, title, created_ns)
                VALUES (?, ?, ?)
                ON CONFLICT(task_id) DO UPDATE SET title = excluded.title
                """,
                (task_id, title.strip(), time.time_ns()),
            )

    @staticmethod
    def _validate_pin_order(
        pin_order: Sequence[str] | None,
        *,
        allowed_ids: set[str] | None = None,
    ) -> list[str] | None:
        if pin_order is None:
            return None
        if isinstance(pin_order, (str, bytes)) or not isinstance(pin_order, Iterable):
            raise ValidationError("invalid_pin_order")
        seen: set[str] = set()
        validated: list[str] = []
        for raw_eid in pin_order:
            eid = validate_identifier(raw_eid, "evidence_id")
            if eid in seen:
                raise ValidationError(f"duplicate_pin_order_evidence_id:{eid}")
            if allowed_ids is not None and eid not in allowed_ids:
                raise ValidationError(f"pin_order_unknown_evidence_id:{eid}")
            seen.add(eid)
            validated.append(eid)
        return validated

    @classmethod
    def _order_kv_rows(
        cls,
        rows: list[sqlite3.Row],
        *,
        pin_order: Sequence[str] | None = None,
    ) -> tuple[str, ...]:
        pin_list = cls._validate_pin_order(pin_order)
        if pin_list:
            pin_rank = {eid: idx for idx, eid in enumerate(pin_list)}
            ordered = sorted(
                rows,
                key=lambda r: (
                    0 if r["evidence_id"] in pin_rank else 1,
                    pin_rank.get(r["evidence_id"], 0),
                    int(r["last_mutated_ns"]),
                    int(r["bind_seq"]),
                    str(r["evidence_id"]),
                ),
            )
        else:
            ordered = sorted(
                rows,
                key=lambda r: (
                    int(r["last_mutated_ns"]),
                    int(r["bind_seq"]),
                    str(r["evidence_id"]),
                ),
            )
        return tuple(str(r["evidence_id"]) for r in ordered)

    def bind_task(
        self,
        task_id: str,
        evidence_ids: Iterable[str],
        *,
        pin_order: Sequence[str] | None = None,
    ) -> str:
        """Binds ``task_id`` to the current active ``(epoch, revision, sha256)`` of ``evidence_ids``.

        Preserves deterministic KV-prefix ordering metadata (``bind_seq``, ``last_mutated_ns``)
        so unchanged dependencies keep their existing prefix positions while mutated or newly
        added dependencies advance monotonically to the tail. Pass ``pin_order`` to explicitly
        pin specific evidence IDs in a caller-chosen order.
        """
        self._require_writable()
        validate_identifier(task_id, "task_id")
        ev_list = sorted({validate_identifier(eid, "evidence_id") for eid in evidence_ids})
        if not ev_list:
            raise ValidationError("empty_evidence_bindings")
        pin_list = self._validate_pin_order(pin_order, allowed_ids=set(ev_list))
        now_ns = time.time_ns()
        with self._tx():
            t_row = self._conn.execute(
                "SELECT task_id FROM task_specs WHERE task_id = ?", (task_id,)
            ).fetchone()
            if t_row is None:
                raise ValidationError("unknown_task_id")

            prev_rows = self._conn.execute(
                """
                SELECT evidence_id, bound_epoch, bound_revision, bound_sha256, bind_seq, last_mutated_ns
                FROM task_dependencies
                WHERE task_id = ?
                """,
                (task_id,),
            ).fetchall()
            prev_by_id = {
                str(r["evidence_id"]): (
                    int(r["bound_epoch"]),
                    int(r["bound_revision"]),
                    str(r["bound_sha256"]),
                    int(r["bind_seq"]),
                    int(r["last_mutated_ns"]),
                )
                for r in prev_rows
            }

            ev_rows: dict[str, sqlite3.Row] = {}
            for eid in ev_list:
                ev = self._conn.execute(
                    """
                    SELECT epoch, active_revision, content_sha256, state, last_mutated_ns
                    FROM evidence_sources WHERE evidence_id = ?
                    """,
                    (eid,),
                ).fetchone()
                if ev is None:
                    raise ValidationError(f"unknown_evidence_id:{eid}")
                if ev["state"] != "ACTIVE":
                    raise EvidenceConflictError(f"cannot_bind_revoked_evidence:{eid}")
                ev_rows[eid] = ev

            assignments: dict[str, tuple[int, int]] = {}
            if pin_list is not None:
                pin_rank = {eid: idx for idx, eid in enumerate(pin_list, start=1)}
                for eid, seq in pin_rank.items():
                    assignments[eid] = (seq, 0)
                remaining = [eid for eid in ev_list if eid not in pin_rank]
                next_seq = len(pin_rank) + 1
                monotonic_mut_ns = max((v[4] for v in prev_by_id.values()), default=0)
                if not prev_by_id:
                    for eid in remaining:
                        assignments[eid] = (next_seq, int(ev_rows[eid]["last_mutated_ns"]))
                        next_seq += 1
                else:
                    rem_unchanged: list[tuple[int, int, str]] = []
                    rem_changed: list[str] = []
                    for eid in remaining:
                        ev = ev_rows[eid]
                        prev = prev_by_id.get(eid)
                        if prev is not None and (
                            int(ev["epoch"]) == prev[0]
                            and int(ev["active_revision"]) == prev[1]
                            and str(ev["content_sha256"]) == prev[2]
                        ):
                            rem_unchanged.append((prev[4], prev[3], eid))
                        else:
                            rem_changed.append(eid)
                    rem_unchanged.sort()
                    for prev_mut, _, eid in rem_unchanged:
                        assignments[eid] = (next_seq, prev_mut)
                        next_seq += 1
                    rem_changed.sort(key=lambda eid: (int(ev_rows[eid]["last_mutated_ns"]), eid))
                    for eid in rem_changed:
                        ev_mut = int(ev_rows[eid]["last_mutated_ns"])
                        cand = ev_mut if ev_mut > monotonic_mut_ns else max(now_ns, monotonic_mut_ns + 1)
                        monotonic_mut_ns = cand
                        assignments[eid] = (next_seq, cand)
                        next_seq += 1
            elif not prev_by_id:
                for idx, eid in enumerate(ev_list, start=1):
                    assignments[eid] = (idx, int(ev_rows[eid]["last_mutated_ns"]))
            else:
                next_seq = max((v[3] for v in prev_by_id.values()), default=0) + 1
                monotonic_mut_ns = max((v[4] for v in prev_by_id.values()), default=0)
                changed_or_new: list[str] = []
                for eid in ev_list:
                    ev = ev_rows[eid]
                    prev = prev_by_id.get(eid)
                    if prev is not None and (
                        int(ev["epoch"]) == prev[0]
                        and int(ev["active_revision"]) == prev[1]
                        and str(ev["content_sha256"]) == prev[2]
                    ):
                        assignments[eid] = (prev[3], prev[4])
                    else:
                        changed_or_new.append(eid)
                changed_or_new.sort(key=lambda eid: (int(ev_rows[eid]["last_mutated_ns"]), eid))
                for eid in changed_or_new:
                    ev_mut = int(ev_rows[eid]["last_mutated_ns"])
                    cand = ev_mut if ev_mut > monotonic_mut_ns else max(now_ns, monotonic_mut_ns + 1)
                    monotonic_mut_ns = cand
                    assignments[eid] = (next_seq, cand)
                    next_seq += 1

            self._conn.execute("DELETE FROM task_dependencies WHERE task_id = ?", (task_id,))
            digest_rows: list[tuple[str, int, int, str]] = []
            for eid in ev_list:
                ev = ev_rows[eid]
                bind_seq, last_mutated_ns = assignments[eid]
                self._conn.execute(
                    """
                    INSERT INTO task_dependencies(
                        task_id, evidence_id, bound_epoch, bound_revision, bound_sha256,
                        bind_seq, last_mutated_ns
                    ) VALUES (?, ?, ?, ?, ?, ?, ?)
                    """,
                    (
                        task_id,
                        eid,
                        ev["epoch"],
                        ev["active_revision"],
                        ev["content_sha256"],
                        bind_seq,
                        last_mutated_ns,
                    ),
                )
                digest_rows.append((eid, int(ev["epoch"]), int(ev["active_revision"]), ev["content_sha256"]))
        return _compute_dependency_digest(digest_rows)

    def _fetch_task_dep_rows(self, task_id: str) -> list[sqlite3.Row]:
        order_cols = (
            "d.bind_seq, d.last_mutated_ns"
            if self._has_dep_order_cols
            else "0 AS bind_seq, 0 AS last_mutated_ns"
        )
        return self._conn.execute(
            f"""
            SELECT d.evidence_id, d.bound_epoch, d.bound_revision, d.bound_sha256,
                   {order_cols},
                   e.kind, e.provider, e.uri, e.external_id, e.epoch AS current_epoch, e.active_revision,
                   e.state AS recorded_state, e.require_certified
            FROM task_dependencies d
            JOIN evidence_sources e ON e.evidence_id = d.evidence_id
            WHERE d.task_id = ?
            ORDER BY d.evidence_id
            """,
            (task_id,),
        ).fetchall()

    def _batch_inspect_external_deps(
        self,
        deps: list[sqlite3.Row],
    ) -> tuple[dict[tuple[str, str], EvidenceSnapshot], dict[str, str]]:
        """Performs at most one batched ``inspect_many`` RPC per external provider (fallback to ``inspect``)."""
        ext_by_provider: dict[str, list[str]] = {}
        seen_by_provider: dict[str, set[str]] = {}
        for r in deps:
            if r["kind"] == "external":
                prov = str(r["provider"])
                xid = str(r["external_id"])
                seen = seen_by_provider.setdefault(prov, set())
                if xid not in seen:
                    seen.add(xid)
                    ext_by_provider.setdefault(prov, []).append(xid)

        batched_snaps: dict[tuple[str, str], EvidenceSnapshot] = {}
        batch_errors: dict[str, str] = {}
        for prov, ext_ids in ext_by_provider.items():
            try:
                slug = validate_provider(prov, allow_local=False)
            except ValidationError:
                batch_errors[prov] = "corrupted_evidence_provider"
                continue
            adapter = self._resolve_provider(slug)
            inspect_many = getattr(adapter, "inspect_many", None)
            if callable(inspect_many):
                try:
                    many = inspect_many(ext_ids)
                    if not isinstance(many, Mapping):
                        raise TypeError("invalid_inspect_many_result")
                    for xid, snap in many.items():
                        batched_snaps[(slug, str(xid))] = snap
                except Exception as exc:
                    batch_errors[prov] = (
                        f"mories_backend_unavailable:{type(exc).__name__}"
                        if slug == "mories"
                        else f"external_backend_unavailable:{slug}:{type(exc).__name__}"
                    )
            else:
                for xid in ext_ids:
                    try:
                        batched_snaps[(slug, xid)] = adapter.inspect(xid)
                    except Exception as exc:
                        err_prefix = (
                            f"mories_backend_unavailable:{type(exc).__name__}"
                            if slug == "mories"
                            else f"external_backend_unavailable:{slug}:{type(exc).__name__}"
                        )
                        batched_snaps[(slug, xid)] = EvidenceSnapshot(
                            evidence_id=xid,
                            backend=slug,
                            uri=f"{slug}://{xid}",
                            revision=0,
                            content_sha256="0" * 64,
                            state="UNAVAILABLE",
                            certified=False,
                            reason=err_prefix,
                        )
        return batched_snaps, batch_errors

    @staticmethod
    def _evaluate_external_dep_snapshot(
        r: sqlite3.Row,
        snap: EvidenceSnapshot | None,
        batch_error: str | None,
    ) -> tuple[bool, str, str | None]:
        eid = str(r["evidence_id"])
        if r["recorded_state"] != "ACTIVE":
            return False, f"evidence_revoked:{eid}", None
        if int(r["current_epoch"]) != int(r["bound_epoch"]):
            return False, f"evidence_epoch_changed_after_revocation:{eid}", None
        prov = str(r["provider"])
        if batch_error is not None:
            return False, f"{batch_error}:{eid}", None
        try:
            slug = validate_provider(prov, allow_local=False)
        except ValidationError:
            return False, f"corrupted_evidence_provider:{eid}", None

        if snap is None:
            not_found = "mories_item_not_found" if slug == "mories" else f"external_item_not_found:{slug}"
            return False, f"{not_found}:{eid}", None
        if not isinstance(snap, EvidenceSnapshot):
            return False, f"invalid_external_snapshot:{slug}:{eid}", None
        if snap.state == "UNAVAILABLE":
            return False, f"{snap.reason}:{eid}", None
        if snap.evidence_id != r["external_id"] or snap.backend not in (slug, "external"):
            return False, f"external_snapshot_identity_mismatch:{slug}:{eid}", None
        if snap.state == "UNKNOWN":
            return False, f"{snap.reason}:{eid}", None
        if snap.state != "ACTIVE":
            return False, f"evidence_revoked:{eid}", None
        if r["require_certified"] and snap.certified is not True:
            return False, f"evidence_uncertified:{eid}", None
        try:
            live_sha = validate_sha256(snap.content_sha256, "live_external_sha256")
        except ValidationError:
            return False, f"invalid_external_snapshot_sha256:{slug}:{eid}", None
        if type(snap.revision) is not int or snap.revision != int(r["bound_revision"]) or live_sha != r["bound_sha256"]:
            return False, f"evidence_revision_changed:{eid}", live_sha
        return True, "verified_active_dependencies", live_sha

    def _inspect_live_dep_rows(self, deps: list[sqlite3.Row]) -> tuple[bool, str, list[tuple[str, str]]]:
        """Verifies all bound dependencies against live files and external providers (batch-capable)."""
        batched_snaps, batch_errors = self._batch_inspect_external_deps(deps)

        verified_pairs: list[tuple[str, str]] = []
        for r in deps:
            eid = str(r["evidence_id"])
            if r["recorded_state"] != "ACTIVE":
                return False, f"evidence_revoked:{eid}", []
            if int(r["current_epoch"]) != int(r["bound_epoch"]):
                return False, f"evidence_epoch_changed_after_revocation:{eid}", []
            if r["kind"] == "local":
                if r["provider"] != "local":
                    return False, f"corrupted_local_provider:{eid}", []
                snap = self._local.inspect(eid, r["uri"], int(r["active_revision"]))
                if snap.state != "ACTIVE":
                    return False, f"{snap.reason}:{eid}", []
                if snap.content_sha256 != r["bound_sha256"] or snap.revision != int(r["bound_revision"]):
                    return False, f"local_source_drifted:{eid}", []
                verified_pairs.append((eid, snap.content_sha256))
            elif r["kind"] == "external":
                prov = str(r["provider"])
                try:
                    slug = validate_provider(prov, allow_local=False)
                    snap = batched_snaps.get((slug, str(r["external_id"])))
                except ValidationError:
                    snap = None
                ok, reason, live_sha = self._evaluate_external_dep_snapshot(r, snap, batch_errors.get(prov))
                if not ok or live_sha is None:
                    return False, reason, []
                verified_pairs.append((eid, live_sha))
            else:
                return False, f"unknown_evidence_kind:{r['kind']}:{eid}", []

        return True, "verified_active_dependencies", verified_pairs

    def begin_work(self, task_id: str) -> WorkLease:
        """Acquires an optimistic-concurrency ``WorkLease`` verifying live dependencies before parallel work.

        Pass ``lease.dependency_digest`` as ``expected_dependency_digest`` when calling
        ``record_receipt`` or ``store_verified_outcome`` so in-flight mutations by other
        sessions or parallel subagents are deterministically rejected.
        """
        validate_identifier(task_id, "task_id")
        deps = self._fetch_task_dep_rows(task_id)
        if not deps:
            raise ValidationError("task_has_no_bound_dependencies")
        ok, reason, pairs = self._inspect_live_dep_rows(deps)
        if not ok:
            raise StaleWorkConflictError(f"cannot_begin_work_on_stale_dependencies:{reason}")
        digest = _compute_dependency_digest(
            [(r["evidence_id"], int(r["bound_epoch"]), int(r["bound_revision"]), r["bound_sha256"]) for r in deps]
        )
        return WorkLease(
            task_id=task_id,
            dependency_digest=digest,
            evidence_digests=tuple(pairs),
            issued_ns=time.time_ns(),
        )

    def _append_receipt_in_tx(
        self,
        task_id: str,
        *,
        outcome_sha256: str,
        decision: str,
        reason: str,
        expected_dependency_digest: str | None,
    ) -> dict[str, Any]:
        deps = self._fetch_task_dep_rows(task_id)
        if not deps:
            raise ValidationError("task_has_no_bound_dependencies")
        dep_digest = _compute_dependency_digest(
            [(r["evidence_id"], int(r["bound_epoch"]), int(r["bound_revision"]), r["bound_sha256"]) for r in deps]
        )
        if expected_dependency_digest is not None:
            if dep_digest != expected_dependency_digest:
                raise StaleWorkConflictError("stale_work_conflict_bound_digest_changed")
            ok, live_reason, _ = self._inspect_live_dep_rows(deps)
            if not ok:
                raise StaleWorkConflictError(f"stale_work_conflict_live_drift:{live_reason}")

        head_meta = {
            r["key"]: r["value"]
            for r in self._conn.execute(
                "SELECT key, value FROM gate_meta WHERE key IN ('head_seq', 'head_chain_sha256')"
            ).fetchall()
        }
        head_seq = int(head_meta["head_seq"])
        prev_chain = head_meta["head_chain_sha256"]
        next_seq = head_seq + 1
        created_ns = time.time_ns()
        receipt_id = f"rcpt_{next_seq:06d}_{uuid.uuid4().hex[:12]}"
        chain_hash = _compute_chain_hash(
            prev_chain,
            next_seq,
            receipt_id,
            task_id,
            decision,
            reason,
            dep_digest,
            outcome_sha256,
            created_ns,
        )
        self._conn.execute(
            """
            INSERT INTO audit_receipts(
                seq, receipt_id, task_id, decision, reason,
                dependency_digest, outcome_sha256, prev_chain_sha256, chain_sha256, created_ns
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """,
            (
                next_seq,
                receipt_id,
                task_id,
                decision,
                reason,
                dep_digest,
                outcome_sha256,
                prev_chain,
                chain_hash,
                created_ns,
            ),
        )
        self._conn.execute("UPDATE gate_meta SET value = ? WHERE key = 'head_seq'", (str(next_seq),))
        self._conn.execute("UPDATE gate_meta SET value = ? WHERE key = 'head_chain_sha256'", (chain_hash,))
        return {
            "seq": next_seq,
            "receipt_id": receipt_id,
            "task_id": task_id,
            "decision": decision,
            "dependency_digest": dep_digest,
            "chain_sha256": chain_hash,
        }

    def record_receipt(
        self,
        task_id: str,
        *,
        outcome_sha256: str,
        decision: str = "ALLOW",
        reason: str = "verified_outcome",
        expected_dependency_digest: str | None = None,
    ) -> dict[str, Any]:
        """Appends a hash-chained audit receipt for ``task_id``.

        Args:
            task_id: Bound task identifier.
            outcome_sha256: 64-hex SHA-256 of the task's verified output.
            decision: ``'ALLOW'``, ``'HOLD'``, or ``'DENY'``.
            reason: Non-empty audit reason label.
            expected_dependency_digest: Optional lease digest from ``begin_work(task_id)``
                enforcing in-flight optimistic concurrency against parallel edits.
        """
        self._require_writable()
        validate_identifier(task_id, "task_id")
        outcome_sha256 = validate_sha256(outcome_sha256, "outcome_sha256")
        if expected_dependency_digest is not None:
            expected_dependency_digest = validate_sha256(
                expected_dependency_digest, "expected_dependency_digest"
            )
        if decision not in ("ALLOW", "HOLD", "DENY"):
            raise ValidationError("invalid_receipt_decision")
        if not isinstance(reason, str) or not reason or "\x00" in reason:
            raise ValidationError("invalid_receipt_reason")

        with self._tx():
            return self._append_receipt_in_tx(
                task_id,
                outcome_sha256=outcome_sha256,
                decision=decision,
                reason=reason,
                expected_dependency_digest=expected_dependency_digest,
            )

    def _verify_receipt_row_and_head(self, row: sqlite3.Row) -> bool:
        try:
            meta = {
                r["key"]: r["value"]
                for r in self._conn.execute(
                    "SELECT key, value FROM gate_meta WHERE key IN ('head_seq', 'head_chain_sha256')"
                ).fetchall()
            }
            head_seq = int(meta["head_seq"])
            head_hash = meta["head_chain_sha256"]
        except (KeyError, ValueError, TypeError):
            return False

        if head_seq < 1:
            return False
        head_row = self._conn.execute(
            """
            SELECT seq, receipt_id, task_id, decision, reason, dependency_digest,
                   outcome_sha256, prev_chain_sha256, chain_sha256, created_ns
            FROM audit_receipts WHERE seq = ?
            """,
            (head_seq,),
        ).fetchone()
        if head_row is None or head_row["chain_sha256"] != head_hash:
            return False

        seq = int(row["seq"])
        if seq < 1 or seq > head_seq:
            return False
        if seq == 1:
            expected_prev = GENESIS_CHAIN_HASH
        else:
            prev_row = self._conn.execute(
                "SELECT chain_sha256 FROM audit_receipts WHERE seq = ?",
                (seq - 1,),
            ).fetchone()
            if prev_row is None:
                return False
            expected_prev = str(prev_row["chain_sha256"])

        if row["prev_chain_sha256"] != expected_prev:
            return False

        recomputed = _compute_chain_hash(
            expected_prev,
            seq,
            row["receipt_id"],
            row["task_id"],
            row["decision"],
            row["reason"],
            row["dependency_digest"],
            row["outcome_sha256"],
            int(row["created_ns"]),
        )
        return recomputed == row["chain_sha256"]

    def check_task(
        self,
        task_id: str,
        *,
        action: int | None = None,
        normative_context: Any = None,
    ) -> GateCheckResult:
        """Evaluates whether ``task_id``'s latest verified receipt remains safe to reuse (``ALLOW``).

        Performs O(1) receipt row + head hash-chain verification, live local file SHA-256
        checks, live external provider inspection, and optional normative action gating.
        """
        validate_identifier(task_id, "task_id")
        with self._read_snapshot():
            latest = self._conn.execute(
                """
                SELECT seq, receipt_id, task_id, decision, reason, dependency_digest,
                       outcome_sha256, prev_chain_sha256, chain_sha256, created_ns
                FROM audit_receipts
                WHERE task_id = ?
                ORDER BY seq DESC
                LIMIT 1
                """,
                (task_id,),
            ).fetchone()
            if latest is None:
                return GateCheckResult(task_id, "HOLD", "missing_verified_receipt")

            if not self._verify_receipt_row_and_head(latest):
                return GateCheckResult(task_id, "HOLD", "corrupted_audit_receipt")

            if latest["decision"] != "ALLOW":
                return GateCheckResult(
                    task_id,
                    latest["decision"],
                    f"latest_receipt_not_allow:{latest['reason']}",
                    receipt_id=latest["receipt_id"],
                    outcome_sha256=None,
                )

            deps = self._fetch_task_dep_rows(task_id)
        if not deps:
            return GateCheckResult(task_id, "HOLD", "missing_task_dependencies")

        expected_digest = _compute_dependency_digest(
            [(r["evidence_id"], int(r["bound_epoch"]), int(r["bound_revision"]), r["bound_sha256"]) for r in deps]
        )
        if expected_digest != latest["dependency_digest"]:
            return GateCheckResult(
                task_id,
                "HOLD",
                "task_bindings_changed_since_receipt",
                receipt_id=latest["receipt_id"],
                checked_dependencies=len(deps),
            )

        ok, live_reason, _ = self._inspect_live_dep_rows(deps)
        if not ok:
            return GateCheckResult(
                task_id,
                "HOLD",
                live_reason,
                receipt_id=latest["receipt_id"],
                checked_dependencies=len(deps),
            )

        if self._normative is not None or action is not None or normative_context is not None:
            if self._normative is None or action is None or normative_context is None:
                return GateCheckResult(
                    task_id,
                    "HOLD",
                    "normative_gate_incomplete_configuration",
                    receipt_id=latest["receipt_id"],
                    outcome_sha256=None,
                    checked_dependencies=len(deps),
                )
            try:
                verdict = self._normative.evaluate(action, normative_context)
            except Exception as exc:
                return GateCheckResult(
                    task_id,
                    "HOLD",
                    f"normative_gate_error:{type(exc).__name__}",
                    receipt_id=latest["receipt_id"],
                    outcome_sha256=None,
                    checked_dependencies=len(deps),
                )
            v_decision = verdict.decision if verdict.decision in ("ALLOW", "HOLD", "DENY") else "HOLD"
            if v_decision != "ALLOW":
                return GateCheckResult(
                    task_id,
                    v_decision,
                    verdict.reason,
                    receipt_id=latest["receipt_id"],
                    outcome_sha256=None,
                    checked_dependencies=len(deps),
                )

        return GateCheckResult(
            task_id,
            "ALLOW",
            "verified_active_dependencies",
            receipt_id=latest["receipt_id"],
            outcome_sha256=latest["outcome_sha256"],
            checked_dependencies=len(deps),
        )

    # ------------------------------------------------------------------
    # PoC-Validated Lossless Outcome Cache & KV-Prefix Context Pinning
    # ------------------------------------------------------------------
    def store_verified_outcome(
        self,
        task_id: str,
        prompt_sha256: str,
        payload_text: str,
        *,
        input_tokens: int = 0,
        output_tokens: int = 0,
        expected_dependency_digest: str | None = None,
    ) -> dict[str, Any]:
        """Atomically records a hash-chained receipt and stores the lossless verified LLM output payload."""
        self._require_writable()
        validate_identifier(task_id, "task_id")
        p_sha = validate_sha256(prompt_sha256, "prompt_sha256")
        if not isinstance(payload_text, str):
            raise ValidationError("invalid_payload_text")
        raw_bytes = payload_text.encode("utf-8")
        if len(raw_bytes) > self._max_payload_bytes:
            raise ValidationError("payload_exceeds_max_bytes")
        if type(input_tokens) is not int or input_tokens < 0:
            raise ValidationError("invalid_input_tokens")
        if type(output_tokens) is not int or output_tokens < 0:
            raise ValidationError("invalid_output_tokens")
        if expected_dependency_digest is not None:
            expected_dependency_digest = validate_sha256(
                expected_dependency_digest, "expected_dependency_digest"
            )

        out_sha = hashlib.sha256(raw_bytes).hexdigest()
        with self._tx():
            rcpt = self._append_receipt_in_tx(
                task_id,
                outcome_sha256=out_sha,
                decision="ALLOW",
                reason="verified_cached_step",
                expected_dependency_digest=expected_dependency_digest,
            )
            self._conn.execute(
                """
                INSERT INTO verified_outcome_cache(
                    task_id, prompt_sha256, receipt_id, dependency_digest,
                    outcome_sha256, payload_text, input_tokens, output_tokens, hit_count, created_ns
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, 0, ?)
                ON CONFLICT(task_id, prompt_sha256) DO UPDATE SET
                    receipt_id = excluded.receipt_id,
                    dependency_digest = excluded.dependency_digest,
                    outcome_sha256 = excluded.outcome_sha256,
                    payload_text = excluded.payload_text,
                    input_tokens = excluded.input_tokens,
                    output_tokens = excluded.output_tokens,
                    hit_count = 0,
                    created_ns = excluded.created_ns
                """,
                (
                    task_id,
                    p_sha,
                    rcpt["receipt_id"],
                    rcpt["dependency_digest"],
                    out_sha,
                    payload_text,
                    input_tokens,
                    output_tokens,
                    time.time_ns(),
                ),
            )
            self._conn.execute(
                "UPDATE gate_meta SET value = CAST(CAST(value AS INTEGER) + 1 AS TEXT) WHERE key = 'executed_calls'"
            )
            self._conn.execute(
                "UPDATE gate_meta SET value = CAST(CAST(value AS INTEGER) + ? AS TEXT) WHERE key = 'executed_input_tokens'",
                (input_tokens,),
            )
            self._conn.execute(
                "UPDATE gate_meta SET value = CAST(CAST(value AS INTEGER) + ? AS TEXT) WHERE key = 'executed_output_tokens'",
                (output_tokens,),
            )
        return rcpt

    def lookup_verified_outcome(
        self,
        task_id: str,
        prompt_sha256: str,
        *,
        record_savings: bool = True,
        action: int | None = None,
        normative_context: Any = None,
    ) -> CachedStepOutcome:
        """Returns a lossless cached LLM output ONLY when ``check_task == ALLOW`` and all chained digests match."""
        validate_identifier(task_id, "task_id")
        p_sha = validate_sha256(prompt_sha256, "prompt_sha256")
        chk = self.check_task(task_id, action=action, normative_context=normative_context)
        if chk.decision != "ALLOW":
            return CachedStepOutcome(task_id, False, chk.decision, chk.reason)

        with self._read_snapshot():
            row = self._conn.execute(
                """
                SELECT c.dependency_digest AS cache_dep_digest,
                       c.outcome_sha256 AS cache_outcome_sha256,
                       c.payload_text,
                       c.input_tokens,
                       c.output_tokens,
                       r.seq, r.receipt_id, r.task_id, r.decision, r.reason,
                       r.dependency_digest, r.outcome_sha256,
                       r.prev_chain_sha256, r.chain_sha256, r.created_ns
                FROM verified_outcome_cache c
                JOIN audit_receipts r ON r.receipt_id = c.receipt_id
                WHERE c.task_id = ? AND c.prompt_sha256 = ?
                """,
                (task_id, p_sha),
            ).fetchone()
            if row is None:
                return CachedStepOutcome(task_id, False, "HOLD", "outcome_cache_miss")

            if not self._verify_receipt_row_and_head(row):
                return CachedStepOutcome(task_id, False, "HOLD", "corrupted_audit_receipt")

            deps = self._fetch_task_dep_rows(task_id)
        live_dep_digest = _compute_dependency_digest(
            [(r["evidence_id"], int(r["bound_epoch"]), int(r["bound_revision"]), r["bound_sha256"]) for r in deps]
        )
        payload_sha = hashlib.sha256(str(row["payload_text"]).encode("utf-8")).hexdigest()
        if (
            row["task_id"] != task_id
            or row["decision"] != "ALLOW"
            or row["cache_dep_digest"] != live_dep_digest
            or row["dependency_digest"] != live_dep_digest
            or payload_sha != row["cache_outcome_sha256"]
            or payload_sha != row["outcome_sha256"]
        ):
            return CachedStepOutcome(task_id, False, "HOLD", "outcome_cache_stale_or_corrupted")

        in_tok = int(row["input_tokens"])
        out_tok = int(row["output_tokens"])
        if record_savings and not self._read_only:
            with self._tx():
                self._conn.execute(
                    "UPDATE gate_meta SET value = CAST(CAST(value AS INTEGER) + 1 AS TEXT) WHERE key = 'avoided_calls'"
                )
                self._conn.execute(
                    "UPDATE gate_meta SET value = CAST(CAST(value AS INTEGER) + ? AS TEXT) WHERE key = 'saved_input_tokens'",
                    (in_tok,),
                )
                self._conn.execute(
                    "UPDATE gate_meta SET value = CAST(CAST(value AS INTEGER) + ? AS TEXT) WHERE key = 'saved_output_tokens'",
                    (out_tok,),
                )
                self._conn.execute(
                    "UPDATE verified_outcome_cache SET hit_count = hit_count + 1 WHERE task_id = ? AND prompt_sha256 = ?",
                    (task_id, p_sha),
                )

        return CachedStepOutcome(
            task_id=task_id,
            cache_hit=True,
            decision="ALLOW",
            reason="verified_outcome_cache_hit",
            payload_text=str(row["payload_text"]),
            outcome_sha256=payload_sha,
            receipt_id=str(row["receipt_id"]),
            saved_input_tokens=in_tok,
            saved_output_tokens=out_tok,
        )

    def run_cached_step(
        self,
        task_id: str,
        prompt_text: str,
        step_fn: Callable[[str], str | tuple[str, int, int]],
        *,
        action: int | None = None,
        normative_context: Any = None,
    ) -> CachedStepOutcome:
        """Executes ``step_fn(prompt_text)`` only on cache miss/``HOLD``, bypassing 100% of LLM tokens on ``ALLOW``.

        ``step_fn`` may return either ``payload_str`` or ``(payload_str, input_tokens, output_tokens)``.
        Uses ``begin_work`` optimistic concurrency so parallel mutations abort stale writes safely.
        """
        self._require_writable()
        if not isinstance(prompt_text, str) or not prompt_text:
            raise ValidationError("invalid_prompt_text")
        p_sha = hashlib.sha256(prompt_text.encode("utf-8")).hexdigest()
        hit = self.lookup_verified_outcome(
            task_id,
            p_sha,
            record_savings=True,
            action=action,
            normative_context=normative_context,
        )
        if hit.cache_hit:
            return hit

        if self._normative is not None or action is not None or normative_context is not None:
            if self._normative is None or action is None or normative_context is None:
                return CachedStepOutcome(task_id, False, "HOLD", "normative_gate_incomplete_configuration")
            try:
                verdict = self._normative.evaluate(action, normative_context)
            except Exception as exc:
                return CachedStepOutcome(task_id, False, "HOLD", f"normative_gate_error:{type(exc).__name__}")
            v_decision = verdict.decision if verdict.decision in ("ALLOW", "HOLD", "DENY") else "HOLD"
            if v_decision != "ALLOW":
                return CachedStepOutcome(task_id, False, v_decision, verdict.reason)

        lease = self.begin_work(task_id)
        result = step_fn(prompt_text)
        if isinstance(result, tuple):
            if len(result) != 3:
                raise ValidationError("invalid_step_fn_tuple_arity")
            payload_text, in_tok, out_tok = result
        else:
            payload_text, in_tok, out_tok = result, 0, 0

        rcpt = self.store_verified_outcome(
            task_id,
            p_sha,
            payload_text,
            input_tokens=in_tok,
            output_tokens=out_tok,
            expected_dependency_digest=lease.dependency_digest,
        )
        return CachedStepOutcome(
            task_id=task_id,
            cache_hit=False,
            decision="ALLOW",
            reason="executed_and_cached",
            payload_text=payload_text,
            outcome_sha256=hashlib.sha256(payload_text.encode("utf-8")).hexdigest(),
            receipt_id=rcpt["receipt_id"],
            saved_input_tokens=0,
            saved_output_tokens=0,
        )

    def token_savings_summary(self) -> dict[str, int]:
        """Returns cumulative avoided LLM calls and saved input/output token counts."""
        meta = {
            r["key"]: int(r["value"])
            for r in self._conn.execute(
                "SELECT key, value FROM gate_meta WHERE key IN ('avoided_calls', 'saved_input_tokens', 'saved_output_tokens')"
            ).fetchall()
        }
        avoided = meta.get("avoided_calls", 0)
        saved_in = meta.get("saved_input_tokens", 0)
        saved_out = meta.get("saved_output_tokens", 0)
        return {
            "avoided_calls": avoided,
            "saved_input_tokens": saved_in,
            "saved_output_tokens": saved_out,
            "saved_total_tokens": saved_in + saved_out,
        }

    def token_monitoring_report(
        self,
        *,
        input_price_per_1m: float = 3.0,
        output_price_per_1m: float = 15.0,
    ) -> dict[str, Any]:
        """Returns a comprehensive token & USD cost savings monitoring report with per-task breakdown.

        Args:
            input_price_per_1m: Reference LLM input price in USD per 1,000,000 tokens.
            output_price_per_1m: Reference LLM output price in USD per 1,000,000 tokens.
        """
        if (
            not isinstance(input_price_per_1m, (int, float))
            or isinstance(input_price_per_1m, bool)
            or input_price_per_1m < 0
            or not isinstance(output_price_per_1m, (int, float))
            or isinstance(output_price_per_1m, bool)
            or output_price_per_1m < 0
        ):
            raise ValidationError("invalid_token_pricing")

        keys = (
            "avoided_calls",
            "saved_input_tokens",
            "saved_output_tokens",
            "executed_calls",
            "executed_input_tokens",
            "executed_output_tokens",
            "kv_prompts_built",
            "kv_prefix_chars_total",
            "kv_prompt_chars_total",
        )
        placeholders = ",".join("?" for _ in keys)
        meta = {
            r["key"]: int(r["value"])
            for r in self._conn.execute(
                f"SELECT key, value FROM gate_meta WHERE key IN ({placeholders})",
                keys,
            ).fetchall()
        }
        avoided = meta.get("avoided_calls", 0)
        exec_calls = meta.get("executed_calls", 0)
        total_reqs = avoided + exec_calls

        saved_in = meta.get("saved_input_tokens", 0)
        saved_out = meta.get("saved_output_tokens", 0)
        saved_tot = saved_in + saved_out

        exec_in = meta.get("executed_input_tokens", 0)
        exec_out = meta.get("executed_output_tokens", 0)
        exec_tot = exec_in + exec_out

        denom_toks = exec_tot + saved_tot
        savings_pct = round((saved_tot / denom_toks) * 100.0, 2) if denom_toks > 0 else 0.0
        hit_rate_pct = round((avoided / total_reqs) * 100.0, 2) if total_reqs > 0 else 0.0

        spent_usd = (exec_in / 1_000_000.0) * float(input_price_per_1m) + (exec_out / 1_000_000.0) * float(output_price_per_1m)
        saved_usd = (saved_in / 1_000_000.0) * float(input_price_per_1m) + (saved_out / 1_000_000.0) * float(output_price_per_1m)
        denom_usd = spent_usd + saved_usd
        cost_red_pct = round((saved_usd / denom_usd) * 100.0, 2) if denom_usd > 0 else 0.0

        kv_built = meta.get("kv_prompts_built", 0)
        kv_pref_chars = meta.get("kv_prefix_chars_total", 0)
        kv_tot_chars = meta.get("kv_prompt_chars_total", 0)
        kv_share_pct = round((kv_pref_chars / kv_tot_chars) * 100.0, 2) if kv_tot_chars > 0 else 0.0

        top_rows = self._conn.execute(
            """
            SELECT task_id,
                   SUM(hit_count) AS hit_count,
                   SUM(hit_count * input_tokens) AS saved_in,
                   SUM(hit_count * output_tokens) AS saved_out,
                   SUM(hit_count * (input_tokens + output_tokens)) AS saved_tot
            FROM verified_outcome_cache
            GROUP BY task_id
            HAVING SUM(hit_count) > 0
            ORDER BY saved_tot DESC, task_id ASC
            """
        ).fetchall()
        top_tasks = [
            {
                "task_id": str(r["task_id"]),
                "hit_count": int(r["hit_count"]),
                "saved_input_tokens": int(r["saved_in"]),
                "saved_output_tokens": int(r["saved_out"]),
                "saved_total_tokens": int(r["saved_tot"]),
            }
            for r in top_rows
        ]

        return {
            "executed_calls": exec_calls,
            "avoided_calls": avoided,
            "total_requests": total_reqs,
            "call_hit_rate_pct": hit_rate_pct,
            "executed_input_tokens": exec_in,
            "executed_output_tokens": exec_out,
            "executed_total_tokens": exec_tot,
            "saved_input_tokens": saved_in,
            "saved_output_tokens": saved_out,
            "saved_total_tokens": saved_tot,
            "overall_token_savings_pct": savings_pct,
            "estimated_cost_spent_usd": round(spent_usd, 6),
            "estimated_cost_saved_usd": round(saved_usd, 6),
            "overall_cost_savings_pct": cost_red_pct,
            "kv_prompts_built": kv_built,
            "kv_prefix_char_share_pct": kv_share_pct,
            "top_tasks": top_tasks,
        }

    def partition_for_kv_cache(
        self,
        task_id: str,
        *,
        pin_order: Sequence[str] | None = None,
    ) -> KVPinnedContextPlan:
        """Partitions bound dependencies into deterministic ``stable_prefix_ids`` and ``changed_suffix_ids``.

        Orders items by ``(last_mutated_ns ASC, bind_seq ASC, evidence_id ASC)`` (or explicit
        ``pin_order`` when provided) and inspects external providers with a single batched
        ``inspect_many`` call per provider.
        """
        validate_identifier(task_id, "task_id")
        validated_pin = self._validate_pin_order(pin_order)
        deps = self._fetch_task_dep_rows(task_id)
        if not deps:
            raise ValidationError("task_has_no_bound_dependencies")

        batched_snaps, batch_errors = self._batch_inspect_external_deps(deps)
        stable_rows: list[sqlite3.Row] = []
        changed_rows: list[sqlite3.Row] = []
        for r in deps:
            eid = str(r["evidence_id"])
            if r["kind"] == "local":
                ok = False
                if (
                    r["recorded_state"] == "ACTIVE"
                    and int(r["current_epoch"]) == int(r["bound_epoch"])
                    and r["provider"] == "local"
                ):
                    snap = self._local.inspect(eid, r["uri"], int(r["active_revision"]))
                    ok = (
                        snap.state == "ACTIVE"
                        and snap.content_sha256 == r["bound_sha256"]
                        and snap.revision == int(r["bound_revision"])
                    )
            elif r["kind"] == "external":
                prov = str(r["provider"])
                try:
                    slug = validate_provider(prov, allow_local=False)
                    snap = batched_snaps.get((slug, str(r["external_id"])))
                except ValidationError:
                    snap = None
                ok, _, _ = self._evaluate_external_dep_snapshot(r, snap, batch_errors.get(prov))
            else:
                ok = False

            if ok:
                stable_rows.append(r)
            else:
                changed_rows.append(r)

        return KVPinnedContextPlan(
            task_id=task_id,
            stable_prefix_ids=self._order_kv_rows(stable_rows, pin_order=validated_pin),
            changed_suffix_ids=self._order_kv_rows(changed_rows, pin_order=validated_pin),
        )

    def build_kv_pinned_prompt(
        self,
        task_id: str,
        *,
        question: str,
        system_header: str = "Answer strictly using the verified evidence blocks below.",
        external_texts: Mapping[str, str] | None = None,
        pin_order: Sequence[str] | None = None,
    ) -> KVPinnedContextPlan:
        """Builds a 100% lossless KV-cache-optimized prompt for ``task_id``.

        Places ``system_header`` + unchanged ``stable_prefix_ids`` first in stable
        ``(last_mutated_ns ASC, bind_seq ASC, evidence_id ASC)`` order (or explicit
        ``pin_order`` when supplied) so re-bound mutated items stay at the tail instead of
        thrashing unchanged prefix items. Followed by 100% full raw text of
        ``changed_suffix_ids``, and ``<QUESTION>`` at the tail. Uses independent collision-free
        tag escalation so evidence delimiters depend strictly on evidence payloads (never on
        ``question``) while ``question`` gets its own isolated safe tag. External providers are
        inspected via a single batched ``inspect_many`` call per provider, while local files use
        single-FD ``read_verified_text`` TOCTOU protection.
        """
        validate_identifier(task_id, "task_id")
        if not isinstance(question, str) or not question.strip():
            raise ValidationError("invalid_question")
        validated_pin = self._validate_pin_order(pin_order)
        deps = self._fetch_task_dep_rows(task_id)
        if not deps:
            raise ValidationError("task_has_no_bound_dependencies")

        batched_snaps, batch_errors = self._batch_inspect_external_deps(deps)
        stable_rows: list[sqlite3.Row] = []
        changed_rows: list[sqlite3.Row] = []
        item_bodies: dict[str, tuple[str, str | None, str, str]] = {}
        # value: (provider, raw_body_or_none, escaped_uri, sha_for_pointer)

        for r in deps:
            eid = str(r["evidence_id"])
            if r["kind"] == "local":
                base_ok = (
                    r["recorded_state"] == "ACTIVE"
                    and int(r["current_epoch"]) == int(r["bound_epoch"])
                    and r["provider"] == "local"
                    and int(r["active_revision"]) == int(r["bound_revision"])
                )
                try:
                    _, live_sha, raw_txt = self._local.read_verified_text(r["uri"])
                    if base_ok and live_sha == r["bound_sha256"]:
                        stable_rows.append(r)
                    else:
                        changed_rows.append(r)
                    item_bodies[eid] = ("local", raw_txt, r["uri"], live_sha)
                except Exception:
                    changed_rows.append(r)
                    item_bodies[eid] = ("local", None, r["uri"], "0" * 64)
            else:
                prov = str(r["provider"])
                live_sha_for_ptr = "0" * 64
                live_active_sha: str | None = None
                snap: EvidenceSnapshot | None = None
                err = batch_errors.get(prov)
                if err is None:
                    try:
                        slug = validate_provider(prov, allow_local=False)
                        snap = batched_snaps.get((slug, str(r["external_id"])))
                        if isinstance(snap, EvidenceSnapshot) and snap.state == "ACTIVE":
                            live_active_sha = validate_sha256(snap.content_sha256, "live_external_sha256")
                            live_sha_for_ptr = live_active_sha
                    except Exception:
                        live_sha_for_ptr = "0" * 64

                ok, _, _ = self._evaluate_external_dep_snapshot(r, snap, err)
                if external_texts is not None and eid in external_texts:
                    ext_body = external_texts[eid]
                    if not isinstance(ext_body, str):
                        raise ValidationError("invalid_external_text")
                    ext_sha = hashlib.sha256(ext_body.encode("utf-8")).hexdigest()
                    if ok and ext_sha != r["bound_sha256"]:
                        raise ValidationError(f"external_text_sha256_mismatch:{eid}")
                    if live_active_sha is not None and ext_sha != live_active_sha:
                        raise ValidationError(f"external_text_sha256_mismatch:{eid}")
                    item_bodies[eid] = (prov, ext_body, r["uri"], ext_sha)
                else:
                    item_bodies[eid] = (prov, None, r["uri"], live_sha_for_ptr)

                if ok:
                    stable_rows.append(r)
                else:
                    changed_rows.append(r)

        stable_ids = self._order_kv_rows(stable_rows, pin_order=validated_pin)
        changed_ids = self._order_kv_rows(changed_rows, pin_order=validated_pin)

        # Deterministic collision-free delimiter escalation:
        # 1. Compute <CONTEXT>/<EVIDENCE> tags strictly from system_header + evidence payloads
        #    (NEVER from question) so user questions containing <EVIDENCE> never bust KV prefix.
        # 2. Compute <QUESTION> tag independently so question content is safely isolated at the tail.
        evidence_raw_strings = [system_header] + [
            body for (_, body, _, _) in item_bodies.values() if body is not None
        ]
        ev_esc_idx = 0
        while True:
            ev_sfx = "" if ev_esc_idx == 0 else f"_{ev_esc_idx}"
            ctx_tag, ev_tag = f"CONTEXT{ev_sfx}", f"EVIDENCE{ev_sfx}"
            ev_markers = (f"<{ctx_tag}", f"</{ctx_tag}", f"<{ev_tag}", f"</{ev_tag}")
            if not any(m in text for text in evidence_raw_strings for m in ev_markers):
                break
            ev_esc_idx += 1

        q_check_strings = [question] + evidence_raw_strings
        q_esc_idx = 0
        while True:
            q_sfx = "" if q_esc_idx == 0 else f"_{q_esc_idx}"
            q_tag = f"QUESTION{q_sfx}"
            q_markers = (f"<{q_tag}", f"</{q_tag}")
            if not any(m in text for text in q_check_strings for m in q_markers):
                break
            q_esc_idx += 1

        def _render_one(eid: str) -> str:
            prov, raw_body, uri, ptr_sha = item_bodies[eid]
            safe_eid = html.escape(eid, quote=True)
            safe_prov = html.escape(prov, quote=True)
            if raw_body is not None:
                return f"<{ev_tag} id=\"{safe_eid}\" provider=\"{safe_prov}\">\n{raw_body}\n</{ev_tag}>"
            safe_uri = html.escape(uri, quote=True)
            return f"<{ev_tag} id=\"{safe_eid}\" provider=\"{safe_prov}\" uri=\"{safe_uri}\" sha256=\"{ptr_sha}\" />"

        prefix_blocks = [_render_one(eid) for eid in stable_ids]
        suffix_blocks = [_render_one(eid) for eid in changed_ids]

        prefix_section = f"{system_header.strip()}\n\n<{ctx_tag}>\n" + "\n\n".join(prefix_blocks)
        prefix_len = len(prefix_section)
        if suffix_blocks:
            sep = "\n\n" if prefix_blocks else ""
            full_ctx = f"{prefix_section}{sep}" + "\n\n".join(suffix_blocks) + f"\n</{ctx_tag}>"
        else:
            full_ctx = f"{prefix_section}\n</{ctx_tag}>"

        rendered = f"{full_ctx}\n\n<{q_tag}>\n{question.strip()}\n</{q_tag}>\n"
        if not self._read_only:
            with self._tx():
                self._conn.execute(
                    "UPDATE gate_meta SET value = CAST(CAST(value AS INTEGER) + 1 AS TEXT) WHERE key = 'kv_prompts_built'"
                )
                self._conn.execute(
                    "UPDATE gate_meta SET value = CAST(CAST(value AS INTEGER) + ? AS TEXT) WHERE key = 'kv_prefix_chars_total'",
                    (prefix_len,),
                )
                self._conn.execute(
                    "UPDATE gate_meta SET value = CAST(CAST(value AS INTEGER) + ? AS TEXT) WHERE key = 'kv_prompt_chars_total'",
                    (len(rendered),),
                )
        return KVPinnedContextPlan(
            task_id=task_id,
            stable_prefix_ids=stable_ids,
            changed_suffix_ids=changed_ids,
            rendered_prompt=rendered,
            prefix_char_length=prefix_len,
        )

    # ------------------------------------------------------------------
    # Fast-Path Router for Single-File Standalone Checks
    # ------------------------------------------------------------------
    def fast_record(self, cache_key: str, file_path: str | Path, *, outcome_sha256: str) -> dict[str, str]:
        """Records a lightweight single-file hash cache entry without task-graph overhead."""
        self._require_writable()
        validate_identifier(cache_key, "cache_key")
        outcome_sha256 = validate_sha256(outcome_sha256, "outcome_sha256")
        uri, file_sha = self._local.resolve_and_hash(file_path)
        with self._tx():
            self._conn.execute(
                """
                INSERT INTO fast_file_cache(cache_key, file_uri, file_sha256, outcome_sha256, updated_ns)
                VALUES (?, ?, ?, ?, ?)
                ON CONFLICT(cache_key) DO UPDATE SET
                    file_uri = excluded.file_uri,
                    file_sha256 = excluded.file_sha256,
                    outcome_sha256 = excluded.outcome_sha256,
                    updated_ns = excluded.updated_ns
                """,
                (cache_key, uri, file_sha, outcome_sha256, time.time_ns()),
            )
        return {"cache_key": cache_key, "file_uri": uri, "file_sha256": file_sha, "outcome_sha256": outcome_sha256}

    def fast_check(self, cache_key: str, file_path: str | Path) -> GateCheckResult:
        """Checks whether ``file_path`` still matches the recorded ``cache_key`` URI and SHA-256."""
        validate_identifier(cache_key, "cache_key")
        row = self._conn.execute(
            "SELECT file_uri, file_sha256, outcome_sha256 FROM fast_file_cache WHERE cache_key = ?",
            (cache_key,),
        ).fetchone()
        if row is None:
            return GateCheckResult(cache_key, "HOLD", "fast_cache_miss")
        try:
            live_uri, live_sha = self._local.resolve_and_hash(file_path)
        except Exception as exc:
            code = getattr(exc, "code", type(exc).__name__)
            return GateCheckResult(cache_key, "HOLD", f"fast_cache_unreadable:{code}")
        if live_uri != row["file_uri"]:
            return GateCheckResult(cache_key, "HOLD", "fast_cache_file_uri_mismatch")
        if live_sha != row["file_sha256"]:
            return GateCheckResult(cache_key, "HOLD", "fast_cache_file_changed")
        return GateCheckResult(
            cache_key,
            "ALLOW",
            "fast_cache_hit",
            outcome_sha256=row["outcome_sha256"],
            checked_dependencies=1,
        )

    # ------------------------------------------------------------------
    # Online Backup, Audit Chain Verification & Diagnostics
    # ------------------------------------------------------------------
    def backup_to(self, dest_path: str | Path) -> dict[str, Any]:
        """Creates an online atomic snapshot using ``sqlite3.Connection.backup()`` and verifies its chain."""
        dst = Path(dest_path)
        dst.parent.mkdir(parents=True, exist_ok=True)
        if os.path.lexists(dst) and stat.S_ISLNK(os.lstat(str(dst)).st_mode):
            raise PathSecurityError("backup_destination_symlink_rejected")
        if dst.resolve(strict=False) == self._db_path.resolve(strict=False):
            raise ValidationError("backup_destination_matches_source")
        if os.name == "posix" and self._secure_permissions:
            flags = os.O_CREAT | os.O_RDWR | getattr(os, "O_NOFOLLOW", 0)
            fd = os.open(str(dst), flags, 0o600)
            try:
                os.fchmod(fd, 0o600)
            finally:
                os.close(fd)
        dst_conn = sqlite3.connect(str(dst))
        try:
            self._conn.backup(dst_conn)
        finally:
            dst_conn.close()
        if self._secure_permissions:
            _apply_owner_only_permissions(dst)
        with HybridEvidenceGate(dst, read_only=True) as verified_copy:
            chain = verified_copy.verify_chain()
        return {
            "ok": bool(chain["ok"]),
            "dest_path": str(dst),
            "checked_receipts": int(chain["checked_receipts"]),
            "head_chain_sha256": chain.get("head_chain_sha256"),
        }

    def receipt_count(self) -> int:
        """Returns the total number of hash-chained receipts stored in ``audit_receipts``."""
        row = self._conn.execute("SELECT COUNT(*) AS n FROM audit_receipts").fetchone()
        return int(row["n"]) if row is not None else 0

    def verify_chain(self) -> dict[str, Any]:
        """Verifies every receipt row and head anchor against modification, gap, or tail truncation."""
        with self._read_snapshot():
            try:
                meta = {
                    r["key"]: r["value"]
                    for r in self._conn.execute(
                        "SELECT key, value FROM gate_meta WHERE key IN ('head_seq', 'head_chain_sha256')"
                    ).fetchall()
                }
                head_seq = int(meta["head_seq"])
                head_chain = meta["head_chain_sha256"]
            except (KeyError, ValueError, TypeError):
                return {
                    "ok": False,
                    "reason": "corrupted_head_meta",
                    "first_bad_seq": 0,
                    "checked_receipts": 0,
                }

            rows = self._conn.execute(
                """
                SELECT seq, receipt_id, task_id, decision, reason, dependency_digest,
                       outcome_sha256, prev_chain_sha256, chain_sha256, created_ns
                FROM audit_receipts
                ORDER BY seq ASC
                """
            ).fetchall()
        expected_prev = GENESIS_CHAIN_HASH
        for idx, r in enumerate(rows, start=1):
            seq = int(r["seq"])
            if seq != idx:
                return {
                    "ok": False,
                    "reason": "sequence_gap_detected",
                    "first_bad_seq": seq,
                    "checked_receipts": idx - 1,
                }
            if r["prev_chain_sha256"] != expected_prev:
                return {
                    "ok": False,
                    "reason": "prev_chain_mismatch",
                    "first_bad_seq": seq,
                    "checked_receipts": idx - 1,
                }
            recomputed = _compute_chain_hash(
                expected_prev,
                seq,
                r["receipt_id"],
                r["task_id"],
                r["decision"],
                r["reason"],
                r["dependency_digest"],
                r["outcome_sha256"],
                int(r["created_ns"]),
            )
            if recomputed != r["chain_sha256"]:
                return {
                    "ok": False,
                    "reason": "chain_hash_mismatch",
                    "first_bad_seq": seq,
                    "checked_receipts": idx - 1,
                }
            expected_prev = recomputed

        if len(rows) != head_seq or expected_prev != head_chain:
            return {
                "ok": False,
                "reason": "tail_truncation_or_head_mismatch",
                "first_bad_seq": len(rows) + 1,
                "checked_receipts": len(rows),
            }

        return {
            "ok": True,
            "reason": "verified",
            "first_bad_seq": None,
            "checked_receipts": len(rows),
            "head_chain_sha256": expected_prev,
        }

    def status_summary(self) -> dict[str, Any]:
        """Returns database counts, attached provider slugs, and cumulative token savings."""
        ev_n = self._conn.execute("SELECT COUNT(*) AS n FROM evidence_sources").fetchone()["n"]
        task_n = self._conn.execute("SELECT COUNT(*) AS n FROM task_specs").fetchone()["n"]
        rcpt_n = self.receipt_count()
        fast_n = self._conn.execute("SELECT COUNT(*) AS n FROM fast_file_cache").fetchone()["n"]
        cached_n = self._conn.execute("SELECT COUNT(*) AS n FROM verified_outcome_cache").fetchone()["n"]
        by_provider = {
            r["provider"]: int(r["n"])
            for r in self._conn.execute(
                "SELECT provider, COUNT(*) AS n FROM evidence_sources GROUP BY provider ORDER BY provider"
            ).fetchall()
        }
        return {
            "schema": SCHEMA_VERSION,
            "project_root": str(self._root) if self._root is not None else None,
            "read_only": self._read_only,
            "attached_providers": sorted(self._providers.keys()),
            "evidence_count": int(ev_n),
            "evidence_by_provider": by_provider,
            "task_count": int(task_n),
            "receipt_count": int(rcpt_n),
            "fast_cache_count": int(fast_n),
            "verified_outcome_cache_count": int(cached_n),
            "token_savings": self.token_savings_summary(),
        }
