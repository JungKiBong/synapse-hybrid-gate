"""Public CLI for synapse-hybrid-gate (works under isolated Python -I -B and -m)."""
from __future__ import annotations

import argparse
from dataclasses import asdict
import hashlib
import json
import os
from pathlib import Path
import stat
import sys
from typing import NoReturn

if __package__ in (None, ""):
    sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from synapse_hybrid_gate.adapters import DEFAULT_MAX_FILE_BYTES
from synapse_hybrid_gate.exceptions import PathSecurityError, SynapseGateError, ValidationError
from synapse_hybrid_gate.store import HybridEvidenceGate


def _read_bounded_utf8_file(file_path: str, *, max_bytes: int = DEFAULT_MAX_FILE_BYTES) -> str:
    """Safely reads a regular UTF-8 file without following leaf symlinks and within ``max_bytes``."""
    p = Path(file_path)
    flags = os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0) | getattr(os, "O_NONBLOCK", 0)
    try:
        fd = os.open(str(p), flags)
    except OSError as exc:
        raise PathSecurityError("cli_input_file_open_failed") from exc
    try:
        st = os.fstat(fd)
        if not stat.S_ISREG(st.st_mode):
            raise PathSecurityError("cli_input_not_regular_file")
        if st.st_size > max_bytes:
            raise PathSecurityError("cli_input_exceeds_max_bytes")
        chunks: list[bytes] = []
        total = 0
        while True:
            chunk = os.read(fd, 65536)
            if not chunk:
                break
            total += len(chunk)
            if total > max_bytes:
                raise PathSecurityError("cli_input_exceeds_max_bytes")
            chunks.append(chunk)
    finally:
        os.close(fd)
    try:
        return b"".join(chunks).decode("utf-8")
    except UnicodeDecodeError as exc:
        raise ValidationError("cli_input_not_utf8") from exc


def _resolve_prompt_sha256(prompt_sha256: str | None, prompt_file: str | None) -> str:
    if bool(prompt_sha256) == bool(prompt_file):
        raise ValidationError("provide_exactly_one_of_prompt_sha256_or_prompt_file")
    if prompt_sha256 is not None:
        return prompt_sha256
    assert prompt_file is not None
    txt = _read_bounded_utf8_file(prompt_file)
    return hashlib.sha256(txt.encode("utf-8")).hexdigest()


def _resolve_payload_text(payload: str | None, payload_file: str | None) -> str:
    if (payload is not None) == (payload_file is not None):
        raise ValidationError("provide_exactly_one_of_payload_or_payload_file")
    if payload is not None:
        return payload
    assert payload_file is not None
    return _read_bounded_utf8_file(payload_file)


class _JsonArgumentParser(argparse.ArgumentParser):
    """ArgumentParser that raises ValidationError instead of exiting with code 2 (which is reserved for HOLD)."""

    def error(self, message: str) -> NoReturn:
        raise ValidationError(f"cli_argument_error:{message}")


def build_parser() -> argparse.ArgumentParser:
    """Builds the command-line parser for ``synapse-hybrid-gate``."""
    parser = _JsonArgumentParser(prog="synapse-hybrid-gate")
    parser.add_argument("--db", required=True, help="Path to SQLite WAL gate database")
    parser.add_argument("--project-root", default=None, help="Optional bounded project root")
    parser.add_argument("--read-only", action="store_true", help="Open database in read-only worker mode")
    sub = parser.add_subparsers(dest="cmd", required=True)

    sub.add_parser("init", help="Initialize database schema")
    sub.add_parser("status", help="Show ledger counts and schema status")
    sub.add_parser("verify-chain", help="Verify cryptographic receipt hash chain")

    p_bak = sub.add_parser("backup", help="Create online atomic SQLite backup and verify chain")
    p_bak.add_argument("--dest", required=True, help="Destination backup database path")

    p_reg_loc = sub.add_parser("register-local", help="Register or update a local file evidence")
    p_reg_loc.add_argument("--evidence-id", required=True)
    p_reg_loc.add_argument("--file", required=True)

    p_bind = sub.add_parser("bind-task", help="Register task and bind evidence IDs")
    p_bind.add_argument("--task-id", required=True)
    p_bind.add_argument("--title", required=True)
    p_bind.add_argument("--evidence-id", action="append", required=True, dest="evidence_ids")

    p_rec = sub.add_parser("record-receipt", help="Record verified outcome receipt for a bound task")
    p_rec.add_argument("--task-id", required=True)
    p_rec.add_argument("--outcome-sha256", required=True)
    p_rec.add_argument("--decision", default="ALLOW", choices=["ALLOW", "HOLD", "DENY"])
    p_rec.add_argument("--reason", default="verified_outcome")
    p_rec.add_argument("--expected-digest", default=None, help="Optional optimistic concurrency lease digest")

    p_chk = sub.add_parser("check-task", help="Evaluate whether a task outcome remains valid")
    p_chk.add_argument("--task-id", required=True)

    p_bw = sub.add_parser("begin-work", help="Acquire an optimistic concurrency lease for parallel execution")
    p_bw.add_argument("--task-id", required=True)

    p_bp = sub.add_parser("build-prompt", help="Build a 100%% lossless KV-prefix-pinned prompt for a bound task")
    p_bp.add_argument("--task-id", required=True)
    p_bp.add_argument("--question", required=True, help="Task question placed at prompt tail")
    p_bp.add_argument(
        "--system-header",
        default="Answer strictly using the verified evidence blocks below.",
        help="Deterministic system header placed before pinned evidence",
    )
    p_bp.add_argument(
        "--format",
        default="json",
        choices=["json", "raw"],
        help="Output JSON metadata + prompt ('json') or raw prompt text only ('raw')",
    )

    p_cl = sub.add_parser("cache-lookup", help="Look up lossless cached LLM output if task is ALLOW (lock-free read)")
    p_cl.add_argument("--task-id", required=True)
    p_cl.add_argument("--prompt-sha256", default=None, help="64-hex SHA-256 of rendered prompt")
    p_cl.add_argument("--prompt-file", default=None, help="Path to rendered prompt file to hash")

    p_cs = sub.add_parser("cache-store", help="Atomically record receipt and cache verified LLM output")
    p_cs.add_argument("--task-id", required=True)
    p_cs.add_argument("--prompt-sha256", default=None, help="64-hex SHA-256 of rendered prompt")
    p_cs.add_argument("--prompt-file", default=None, help="Path to rendered prompt file to hash")
    p_cs.add_argument("--payload", default=None, help="Verified LLM output string")
    p_cs.add_argument("--payload-file", default=None, help="Path to file containing verified LLM output")
    p_cs.add_argument("--input-tokens", type=int, default=0, help="Input tokens consumed by this LLM call")
    p_cs.add_argument("--output-tokens", type=int, default=0, help="Output tokens generated by this LLM call")
    p_cs.add_argument("--expected-digest", default=None, help="Optional optimistic concurrency lease digest")

    p_rev = sub.add_parser("revoke-evidence", help="Revoke evidence and list affected tasks")
    p_rev.add_argument("--evidence-id", required=True)

    return parser


def main(argv: list[str] | None = None) -> int:
    """Entry point returning ``0`` (ALLOW/OK), ``2`` (HOLD), or ``3`` (ERROR/DENY/TAMPERED)."""
    gate: HybridEvidenceGate | None = None
    try:
        args = build_parser().parse_args(argv)
        gate = HybridEvidenceGate(
            args.db,
            project_root=args.project_root,
            read_only=bool(args.read_only),
        )
        if args.cmd in ("init", "status"):
            out = gate.status_summary()
            code = 0
        elif args.cmd == "backup":
            out = gate.backup_to(args.dest)
            code = 0 if out["ok"] else 3
        elif args.cmd == "register-local":
            snap = gate.register_local_evidence(args.evidence_id, args.file)
            out = asdict(snap)
            code = 0
        elif args.cmd == "bind-task":
            gate.register_task(args.task_id, args.title)
            digest = gate.bind_task(args.task_id, args.evidence_ids)
            out = {"task_id": args.task_id, "dependency_digest": digest}
            code = 0
        elif args.cmd == "record-receipt":
            out = gate.record_receipt(
                args.task_id,
                outcome_sha256=args.outcome_sha256,
                decision=args.decision,
                reason=args.reason,
                expected_dependency_digest=args.expected_digest,
            )
            code = 0
        elif args.cmd == "check-task":
            res = gate.check_task(args.task_id)
            out = asdict(res)
            code = 0 if res.decision == "ALLOW" else (2 if res.decision == "HOLD" else 3)
        elif args.cmd == "begin-work":
            lease = gate.begin_work(args.task_id)
            out = {
                "task_id": lease.task_id,
                "dependency_digest": lease.dependency_digest,
                "checked_dependencies": len(lease.evidence_digests),
                "evidence_digests": [list(pair) for pair in lease.evidence_digests],
                "issued_ns": lease.issued_ns,
            }
            code = 0
        elif args.cmd == "build-prompt":
            plan = gate.build_kv_pinned_prompt(
                args.task_id,
                question=args.question,
                system_header=args.system_header,
            )
            if args.format == "raw":
                sys.stdout.write(plan.rendered_prompt)
                return 0
            p_sha = hashlib.sha256(plan.rendered_prompt.encode("utf-8")).hexdigest()
            out = {
                "task_id": plan.task_id,
                "prompt_sha256": p_sha,
                "stable_prefix_ids": list(plan.stable_prefix_ids),
                "changed_suffix_ids": list(plan.changed_suffix_ids),
                "prefix_char_length": plan.prefix_char_length,
                "total_prompt_chars": len(plan.rendered_prompt),
                "rendered_prompt": plan.rendered_prompt,
            }
            code = 0
        elif args.cmd == "cache-lookup":
            p_sha = _resolve_prompt_sha256(args.prompt_sha256, args.prompt_file)
            hit = gate.lookup_verified_outcome(args.task_id, p_sha)
            out = asdict(hit)
            out["prompt_sha256"] = p_sha
            code = 0 if (hit.cache_hit and hit.decision == "ALLOW") else (2 if hit.decision == "HOLD" else 3)
        elif args.cmd == "cache-store":
            p_sha = _resolve_prompt_sha256(args.prompt_sha256, args.prompt_file)
            payload_text = _resolve_payload_text(args.payload, args.payload_file)
            rcpt = gate.store_verified_outcome(
                args.task_id,
                p_sha,
                payload_text,
                input_tokens=args.input_tokens,
                output_tokens=args.output_tokens,
                expected_dependency_digest=args.expected_digest,
            )
            out = dict(rcpt)
            out["prompt_sha256"] = p_sha
            code = 0
        elif args.cmd == "revoke-evidence":
            affected = gate.revoke_evidence(args.evidence_id)
            out = {"evidence_id": args.evidence_id, "affected_tasks": affected}
            code = 0
        elif args.cmd == "verify-chain":
            out = gate.verify_chain()
            code = 0 if out["ok"] else 3
        else:
            out = {"status": "ERROR", "error": f"unknown_command:{args.cmd}"}
            code = 3
    except SystemExit as exc:
        return 0 if exc.code in (0, None) else 3
    except SynapseGateError as exc:
        out = {"status": "ERROR", "error": f"{type(exc).__name__}:{exc.code}"}
        code = 3
    except Exception as exc:
        out = {"status": "ERROR", "error": f"{type(exc).__name__}:{exc}"}
        code = 3
    finally:
        if gate is not None:
            gate.close()

    print(json.dumps(out, ensure_ascii=False, sort_keys=True))
    return code


if __name__ == "__main__":
    raise SystemExit(main())
