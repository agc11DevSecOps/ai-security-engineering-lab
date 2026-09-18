"""Capability selection and execution for one validated harness request."""

from __future__ import annotations

from collections.abc import Iterable

from core.capability import Capability, CapabilityRequest, CapabilityResult, ErrorCode


class Router:
    """Route a request to every registered capability that supports its task."""

    def __init__(self, capabilities: Iterable[Capability]) -> None:
        self._capabilities = tuple(capabilities)

    def select(self, request: CapabilityRequest) -> tuple[Capability, ...]:
        """Return registered capabilities that explicitly support the request task."""
        return tuple(
            capability
            for capability in self._capabilities
            if request.task_type in capability.supported_task_types
        )

    def run(self, request: CapabilityRequest) -> tuple[CapabilityResult, ...]:
        """Execute selected capabilities without interpreting their findings."""
        selected = self.select(request)
        if not selected:
            return (CapabilityResult.failed(ErrorCode.UNSUPPORTED_TASK),)
        return tuple(capability.run(request) for capability in selected)
