"""Optional normative action gate hook (zero eager external or scientific library imports)."""
from __future__ import annotations

from dataclasses import dataclass
from typing import Any, Protocol


@dataclass(frozen=True, slots=True)
class NormativeVerdict:
    """Normalized normative gate decision (``ALLOW``, ``HOLD``, or ``DENY``)."""

    decision: str
    reason: str
    selected_action: int | None = None


class NormativeGatePort(Protocol):
    """Abstract port for optional action-level normative/policy verification."""

    def evaluate(self, action: int, context: Any) -> NormativeVerdict:
        """Evaluates whether ``action`` is permitted under ``context``."""
        ...


class SynapseCoreGateAdapter:
    """Bridges ``SynapseCore.evaluate_normative_gate`` without importing ``synapse_core`` at load time."""

    def __init__(self, core_instance: Any) -> None:
        if not hasattr(core_instance, "evaluate_normative_gate"):
            raise TypeError("core_instance_missing_evaluate_normative_gate")
        self._core = core_instance

    def evaluate(self, action: int, context: Any) -> NormativeVerdict:
        """Maps ``SynapseCore`` decisions to ``NormativeVerdict`` (never promoting ``abstain`` to ``ALLOW``)."""
        gate_res = self._core.evaluate_normative_gate(action, context)
        raw_decision = getattr(gate_res, "decision", "abstain")
        raw_reason = getattr(gate_res, "reason", "unknown")
        selected = getattr(gate_res, "selected_action", None)
        if raw_decision == "allow":
            return NormativeVerdict("ALLOW", f"normative_allow:{raw_reason}", selected)
        if raw_decision == "deny":
            return NormativeVerdict("DENY", f"normative_deny:{raw_reason}", selected)
        return NormativeVerdict("HOLD", f"normative_abstain:{raw_reason}", selected)
