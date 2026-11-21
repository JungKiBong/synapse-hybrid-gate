#!/usr/bin/env python3
"""Zero-API-key runnable demo of synapse-hybrid-gate lossless caching, KV-prefix pinning & OCC safety.

Run from the repository root:
    PYTHONPATH=src python3 examples/demo_lossless_savings.py
Or after `pip install .`:
    python3 examples/demo_lossless_savings.py
"""
from __future__ import annotations

from pathlib import Path
import sys
import tempfile

if __package__ in (None, ""):
    repo_src = Path(__file__).resolve().parents[1] / "src"
    if repo_src.is_dir():
        sys.path.insert(0, str(repo_src))

from synapse_hybrid_gate import HybridEvidenceGate, StaleWorkConflictError
from synapse_hybrid_gate.cli import main as cli_main


def main() -> None:
    with tempfile.TemporaryDirectory() as tmp:
        root = Path(tmp)
        db_path = root / "demo_gate.db"

        arch = root / "architecture.md"
        conn = root / "connector_spec.md"
        therm = root / "thermal_spec.md"

        arch.write_text("Gateway mTLS handshake ceiling: 350ms. Audit VLAN: 4091.\n" * 12, encoding="utf-8")
        conn.write_text(
            "Connector nominal limit: 25.0A.\n"
            "Footnote 4.3: Below 0C over cable > 1.8m, Pin-B2 derates to 20.5A.\n" * 10,
            encoding="utf-8",
        )
        therm.write_text("Sub-zero charging current: 18.0A (cable length 2.2m).\n", encoding="utf-8")

        llm_invocations = 0

        def simulated_llm(prompt: str) -> tuple[str, int, int]:
            nonlocal llm_invocations
            llm_invocations += 1
            if "24.0A" in prompt and "20.5A" in prompt:
                return '{"overall_safe": false, "current_margin_amps": -3.5}', 1698, 43
            return '{"overall_safe": true, "current_margin_amps": 2.5}', 1675, 43

        with HybridEvidenceGate(db_path, project_root=root) as gate:
            gate.register_local_evidence("ev:arch", arch)
            gate.register_local_evidence("ev:connector", conn)
            gate.register_local_evidence("ev:thermal", therm)
            gate.register_task("task:safety_audit", "Cross-spec charging safety audit")
            gate.bind_task("task:safety_audit", ["ev:arch", "ev:connector", "ev:thermal"])

            question = "Evaluate sub-zero charging current margin including all cable footnotes."

            # Round 1: Initial execution (cache miss -> invokes LLM)
            plan_r1 = gate.build_kv_pinned_prompt("task:safety_audit", question=question)
            r1 = gate.run_cached_step("task:safety_audit", plan_r1.rendered_prompt, simulated_llm)
            print(f"[Round 1] cache_hit={r1.cache_hit} | llm_calls={llm_invocations} | result={r1.payload_text}")

            # Round 2: Unchanged specs (ALLOW -> 100% LLM token bypass!)
            r2 = gate.run_cached_step("task:safety_audit", plan_r1.rendered_prompt, simulated_llm)
            print(
                f"[Round 2] cache_hit={r2.cache_hit}  | llm_calls={llm_invocations} | "
                f"saved={r2.saved_input_tokens + r2.saved_output_tokens} tokens | result={r2.payload_text}"
            )

            # Round 3: Upstream spec mutation (18.0A -> 24.0A) -> automatic invalidation + KV prefix pinning
            therm.write_text("Sub-zero charging current: 24.0A (cable length 2.2m).\n", encoding="utf-8")
            plan_r3 = gate.build_kv_pinned_prompt("task:safety_audit", question=question)
            print(
                f"[Round 3] KV Partition -> pinned_prefix={plan_r3.stable_prefix_ids}, "
                f"mutated_suffix={plan_r3.changed_suffix_ids}"
            )
            gate.register_local_evidence("ev:thermal", therm)
            gate.bind_task("task:safety_audit", ["ev:arch", "ev:connector", "ev:thermal"])
            r3 = gate.run_cached_step("task:safety_audit", plan_r3.rendered_prompt, simulated_llm)
            print(f"[Round 3] cache_hit={r3.cache_hit} | llm_calls={llm_invocations} | result={r3.payload_text}")

            # Round 4: Repeat post-mutation check (ALLOW -> 100% LLM token bypass again!)
            r4 = gate.run_cached_step("task:safety_audit", plan_r3.rendered_prompt, simulated_llm)
            print(
                f"[Round 4] cache_hit={r4.cache_hit}  | llm_calls={llm_invocations} | "
                f"saved={r4.saved_input_tokens + r4.saved_output_tokens} tokens"
            )

            # Bonus: Parallel subagent optimistic concurrency guard
            lease = gate.begin_work("task:safety_audit")
            therm.write_text("Sub-zero charging current: 30.0A (concurrent session edit!).\n", encoding="utf-8")
            try:
                gate.record_receipt(
                    "task:safety_audit",
                    outcome_sha256="a" * 64,
                    expected_dependency_digest=lease.dependency_digest,
                )
            except StaleWorkConflictError as exc:
                print(f"[OCC Guard] Blocked stale parallel subagent commit: {exc.code}\n")

        cli_main(["--db", str(db_path), "status"])
        cli_main(["--db", str(db_path), "verify-chain"])


if __name__ == "__main__":
    main()
