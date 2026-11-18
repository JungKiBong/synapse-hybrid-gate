"""Built-in standard-library unittest suite for synapse-hybrid-gate (also pytest-compatible)."""
from __future__ import annotations

import hashlib
from pathlib import Path
import tempfile
import unittest

from synapse_hybrid_gate import (
    CircuitBreakingAdapter,
    ExternalMemoryItem,
    HybridEvidenceGate,
    PathSecurityError,
    ReadOnlyGateError,
    StaleWorkConflictError,
    make_mem0_adapter,
    make_zep_adapter,
)


def _sha(text: str) -> str:
    return hashlib.sha256(text.encode("utf-8")).hexdigest()


class TestSynapseHybridGate(unittest.TestCase):
    def test_standalone_lifecycle_and_context_manager(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            spec = root / "spec.md"
            spec.write_text("v1\n", encoding="utf-8")
            with HybridEvidenceGate(root / "g.db", project_root=root) as gate:
                gate.register_local_evidence("ev:spec", spec)
                gate.register_task("task:1", "Verify spec")
                gate.bind_task("task:1", ["ev:spec"])
                gate.record_receipt("task:1", outcome_sha256=_sha("ok"))
                self.assertEqual(gate.check_task("task:1").decision, "ALLOW")
                spec.write_text("v2\n", encoding="utf-8")
                self.assertEqual(gate.check_task("task:1").decision, "HOLD")
            self.assertTrue(gate.closed)

    def test_multi_provider_and_circuit_breaker(self) -> None:
        mem0_data = {"m1": {"id": "m1", "memory": "rule A", "version": 1, "is_deleted": False}}
        zep_alive = True
        zep_data = {"z1": {"uuid": "z1", "fact": "fact B", "revision": 1, "invalid_at": None, "certified": True}}

        def zep_lookup(k: str) -> dict:
            if not zep_alive:
                raise ConnectionError("offline")
            return zep_data[k]

        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            with HybridEvidenceGate(
                root / "mp.db",
                providers={
                    "mem0": make_mem0_adapter(lambda k: mem0_data[k]),
                    "zep": CircuitBreakingAdapter(make_zep_adapter(zep_lookup), failure_threshold=2, cooldown_seconds=5.0),
                },
            ) as gate:
                gate.register_external_evidence("ev:m0", "m1", provider="mem0", require_certified=False)
                gate.register_external_evidence("ev:z1", "z1", provider="zep", require_certified=True)
                gate.register_task("task:both", "Both")
                gate.bind_task("task:both", ["ev:m0", "ev:z1"])
                gate.record_receipt("task:both", outcome_sha256=_sha("ok"))
                self.assertEqual(gate.check_task("task:both").decision, "ALLOW")

                zep_alive = False
                self.assertEqual(gate.check_task("task:both").decision, "HOLD")
                self.assertEqual(gate.check_task("task:both").decision, "HOLD")
                res3 = gate.check_task("task:both")
                self.assertIn("circuit_open", res3.reason)

    def test_lossless_token_cache_kv_prefix_and_optimistic_lease(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            s1 = root / "shared.md"
            s2 = root / "target.py"
            s1.write_text("Shared contract text\n", encoding="utf-8")
            s2.write_text("x = 1\n", encoding="utf-8")
            calls = 0

            def step(prompt: str) -> tuple[str, int, int]:
                nonlocal calls
                calls += 1
                return f"verified:{len(prompt)}", 500, 50

            with HybridEvidenceGate(root / "c.db", project_root=root) as gate:
                gate.register_local_evidence("ev:shared", s1)
                gate.register_local_evidence("ev:target", s2)
                gate.register_task("task:step", "Cached step")
                gate.bind_task("task:step", ["ev:shared", "ev:target"])

                plan = gate.build_kv_pinned_prompt("task:step", question="Audit x")
                self.assertIn("Shared contract text", plan.rendered_prompt)
                self.assertIn("x = 1", plan.rendered_prompt)

                out1 = gate.run_cached_step("task:step", plan.rendered_prompt, step)
                out2 = gate.run_cached_step("task:step", plan.rendered_prompt, step)
                self.assertFalse(out1.cache_hit)
                self.assertTrue(out2.cache_hit)
                self.assertEqual(calls, 1)
                self.assertEqual(gate.token_savings_summary()["saved_total_tokens"], 550)
                report = gate.token_monitoring_report()
                self.assertEqual(report["call_hit_rate_pct"], 50.0)
                self.assertEqual(report["overall_token_savings_pct"], 50.0)
                self.assertEqual(report["top_tasks"][0]["task_id"], "task:step")

                lease = gate.begin_work("task:step")
                s2.write_text("x = 2\n", encoding="utf-8")
                with self.assertRaises(StaleWorkConflictError):
                    gate.record_receipt(
                        "task:step",
                        outcome_sha256=_sha("stale"),
                        expected_dependency_digest=lease.dependency_digest,
                    )

            with HybridEvidenceGate(root / "c.db", read_only=True) as ro_gate:
                with self.assertRaises(ReadOnlyGateError):
                    ro_gate.register_task("task:nope", "Nope")

    def test_max_file_bytes_security_guard(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            huge = root / "huge.bin"
            huge.write_bytes(b"a" * 2048)
            with HybridEvidenceGate(root / "s.db", project_root=root, max_file_bytes=512) as gate:
                with self.assertRaises(PathSecurityError):
                    gate.register_local_evidence("ev:huge", huge)


if __name__ == "__main__":
    unittest.main()
