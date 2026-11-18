"""Public CLI for synapse-hybrid-gate (works under isolated Python -I -B and -m)."""
from __future__ import annotations

import argparse
from dataclasses import asdict
import json
from pathlib import Path
import sys
from typing import NoReturn

if __package__ in (None, ""):
    sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from synapse_hybrid_gate.adapters import (
    CallableExternalAdapter,
    CallableMoriesAdapter,
    ExternalMemoryItem,
    MoriesItemState,
)
from synapse_hybrid_gate.exceptions import SynapseGateError, ValidationError
from synapse_hybrid_gate.store import HybridEvidenceGate, migrate_database


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
    sub.add_parser("status", help="Show counts, schema status, and token savings")
    sub.add_parser("token-stats", help="Show cumulative lossless token savings counters")
    sub.add_parser("verify-chain", help="Verify cryptographic receipt hash chain")
    sub.add_parser("migrate", help="Migrate legacy v1/v2 database schema to v3")

    p_mon = sub.add_parser("monitor", help="Show detailed token & cost savings monitoring report")
    p_mon.add_argument("--format", default="json", choices=["json", "table"], help="Output format (json or table)")
    p_mon.add_argument("--input-price-per-1m", type=float, default=3.0, help="USD per 1M input tokens")
    p_mon.add_argument("--output-price-per-1m", type=float, default=15.0, help="USD per 1M output tokens")

    p_bak = sub.add_parser("backup", help="Create online atomic SQLite backup and verify chain")
    p_bak.add_argument("--dest", required=True, help="Destination backup database path")

    p_reg_loc = sub.add_parser("register-local", help="Register or update a local file evidence")
    p_reg_loc.add_argument("--evidence-id", required=True)
    p_reg_loc.add_argument("--file", required=True)

    p_reg_ext = sub.add_parser("register-external", help="Register verified external memory pointer for any provider")
    p_reg_ext.add_argument("--provider", required=True, help="Provider slug (e.g. mem0, zep, postgres, mories)")
    p_reg_ext.add_argument("--evidence-id", required=True)
    p_reg_ext.add_argument("--item-id", required=True)
    p_reg_ext.add_argument("--revision", type=int, required=True)
    p_reg_ext.add_argument("--content-sha256", required=True)
    p_reg_ext.add_argument("--namespace", default="default")
    p_reg_ext.add_argument("--uncertified", action="store_true")
    p_reg_ext.add_argument("--allow-uncertified", action="store_true")

    p_reg_mor = sub.add_parser("register-mories", help="Register verified Mories evidence pointer (compat alias)")
    p_reg_mor.add_argument("--evidence-id", required=True)
    p_reg_mor.add_argument("--mories-item-id", required=True)
    p_reg_mor.add_argument("--revision", type=int, required=True)
    p_reg_mor.add_argument("--content-sha256", required=True)
    p_reg_mor.add_argument("--project", default="personal")
    p_reg_mor.add_argument("--uncertified", action="store_true")
    p_reg_mor.add_argument("--allow-uncertified", action="store_true")

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

    p_rev = sub.add_parser("revoke-evidence", help="Revoke evidence and list affected tasks")
    p_rev.add_argument("--evidence-id", required=True)

    p_frec = sub.add_parser("fast-record", help="Record fast-path single-file hash cache entry")
    p_frec.add_argument("--key", required=True)
    p_frec.add_argument("--file", required=True)
    p_frec.add_argument("--outcome-sha256", required=True)

    p_fast = sub.add_parser("fast-check", help="Fast-path single-file hash cache lookup")
    p_fast.add_argument("--key", required=True)
    p_fast.add_argument("--file", required=True)

    return parser


def main(argv: list[str] | None = None) -> int:
    """Entry point returning ``0`` (ALLOW/OK), ``2`` (HOLD), or ``3`` (ERROR/DENY/TAMPERED)."""
    gate: HybridEvidenceGate | None = None
    try:
        args = build_parser().parse_args(argv)
        if args.cmd == "migrate":
            out = migrate_database(args.db)
            print(json.dumps(out, ensure_ascii=False, sort_keys=True))
            return 0

        providers = None
        mories_adapter = None
        if args.cmd == "register-external":
            ext_item = ExternalMemoryItem(
                item_id=args.item_id,
                revision=args.revision,
                content_sha256=args.content_sha256,
                state="ACTIVE",
                certified=not args.uncertified,
                provider=args.provider,
            )
            providers = {
                args.provider: CallableExternalAdapter(
                    lambda k: ext_item if k == ext_item.item_id else (_ for _ in ()).throw(KeyError(k)),
                    provider=args.provider,
                    namespace=args.namespace,
                )
            }
        elif args.cmd == "register-mories":
            state = MoriesItemState(
                item_id=args.mories_item_id,
                revision=args.revision,
                content_sha256=args.content_sha256,
                state="ACTIVE",
                certified=not args.uncertified,
            )
            mories_adapter = CallableMoriesAdapter(
                lambda k: state if k == state.item_id else (_ for _ in ()).throw(KeyError(k)),
                project=args.project,
            )

        gate = HybridEvidenceGate(
            args.db,
            project_root=args.project_root,
            providers=providers,
            mories_adapter=mories_adapter,
            read_only=bool(args.read_only),
        )
        if args.cmd in ("init", "status"):
            out = gate.status_summary()
            code = 0
        elif args.cmd == "token-stats":
            out = gate.token_savings_summary()
            code = 0
        elif args.cmd == "monitor":
            rep = gate.token_monitoring_report(
                input_price_per_1m=args.input_price_per_1m,
                output_price_per_1m=args.output_price_per_1m,
            )
            if args.format == "table":
                lines = [
                    "================================================================",
                    "  SYNAPSE HYBRID GATE — LOSSLESS TOKEN & COST MONITOR",
                    "================================================================",
                    f"  Calls      : {rep['avoided_calls']} avoided / {rep['total_requests']} total ({rep['call_hit_rate_pct']:.1f}% hit rate)",
                    f"  Saved Toks : {rep['saved_total_tokens']:,} ({rep['saved_input_tokens']:,} in + {rep['saved_output_tokens']:,} out | {rep['overall_token_savings_pct']:.1f}% saved)",
                    f"  Est. Cost  : ${rep['estimated_cost_saved_usd']:.4f} saved vs ${rep['estimated_cost_spent_usd']:.4f} spent ({rep['overall_cost_savings_pct']:.1f}% reduction)",
                    f"  KV Prefix  : {rep['kv_prompts_built']} prompts built ({rep['kv_prefix_char_share_pct']:.1f}% pinned prefix share)",
                ]
                if rep["top_tasks"]:
                    lines.append("----------------------------------------------------------------")
                    lines.append("  Top Saved Tasks (Task ID | Hits | Saved Tokens)")
                    for item in rep["top_tasks"][:10]:
                        lines.append(
                            f"  - {item['task_id']}: {item['hit_count']} hits | {item['saved_total_tokens']:,} tokens"
                        )
                lines.append("================================================================")
                print("\n".join(lines))
                return 0
            out = rep
            code = 0
        elif args.cmd == "backup":
            out = gate.backup_to(args.dest)
            code = 0 if out["ok"] else 3
        elif args.cmd == "register-local":
            snap = gate.register_local_evidence(args.evidence_id, args.file)
            out = asdict(snap)
            code = 0
        elif args.cmd == "register-external":
            snap = gate.register_external_evidence(
                args.evidence_id,
                args.item_id,
                provider=args.provider,
                require_certified=not args.allow_uncertified,
            )
            out = asdict(snap)
            code = 0
        elif args.cmd == "register-mories":
            snap = gate.register_mories_evidence(
                args.evidence_id,
                args.mories_item_id,
                require_certified=not args.allow_uncertified,
            )
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
        elif args.cmd == "revoke-evidence":
            affected = gate.revoke_evidence(args.evidence_id)
            out = {"evidence_id": args.evidence_id, "affected_tasks": affected}
            code = 0
        elif args.cmd == "fast-record":
            out = gate.fast_record(args.key, args.file, outcome_sha256=args.outcome_sha256)
            code = 0
        elif args.cmd == "fast-check":
            res = gate.fast_check(args.key, args.file)
            out = asdict(res)
            code = 0 if res.decision == "ALLOW" else 2
        elif args.cmd == "verify-chain":
            out = gate.verify_chain()
            code = 0 if out["ok"] else 3
        else:
            out = {"status": "ERROR", "error": f"unknown_command:{args.cmd}"}
            code = 3
    except SystemExit as exc:
        # Preserve exit 0 on --help/-h while mapping non-zero exits to 3
        return 0 if exc.code in (0, None) else 3
    except SynapseGateError as exc:
        out = {"status": "ERROR", "error": f"{type(exc).__name__}:{exc.code}"}
        code = 3
    except Exception as exc:
        out = {"status": "ERROR", "error": f"{type(exc).__name__}"}
        code = 3
    finally:
        if gate is not None:
            gate.close()

    print(json.dumps(out, ensure_ascii=False, sort_keys=True))
    return code


if __name__ == "__main__":
    raise SystemExit(main())
