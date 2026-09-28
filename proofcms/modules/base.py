from __future__ import annotations

from typing import Any, Protocol, runtime_checkable

from ..core.models import Finding


@runtime_checkable
class VulnerabilityModule(Protocol):
    """
    Common Protocol that each vulnerability detection module must implement.
    Every module exposes metadata describing its parameters and a check method
    returning a unified Finding instance.
    """

    def metadata(self) -> dict[str, Any]:
        ...

    def check(
        self,
        target_url: str,
        joomla_version: str | None = None,
        run_exploit_check: bool = False,
        timeout: int = 12,
        proxy: str | None = None,
        exploit_mode: str = "safe",
        aggressive_command: str | None = None,
        plugins: dict[str, Any] | None = None,
        **kwargs: Any,
    ) -> Finding:
        ...
