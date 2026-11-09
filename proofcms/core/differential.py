"""Non-mutating differentials that prove server-side evaluation.

Reflection alone never proves evaluation: a marker echoed back verbatim may
simply have been reflected. The pattern used here submits a *registered*
shortcode whose handler renders fixed, observable output, and requires both
signals before claiming confirmation:

* the marker is reflected (proves the sink processed our input), and
* the handler's known output is present (proves it was *evaluated*, not
  merely reflected).

A public Forminator PoC for CVE-2026-9229 got this wrong: it treated a
reflected marker as exploitation, but ``esc_url()`` percent-encodes the
brackets, so the shortcode never parses. Always require handler output.
"""

from __future__ import annotations

from collections.abc import Callable
from dataclasses import dataclass
from typing import Any


@dataclass
class EvaluationResult:
    evaluated: bool
    reflection: str | None
    marker_present: bool


def confirm_shortcode_output(
    fetch: Callable[[str], str],
    extract: Callable[[str], str | None],
    marker: str,
    *,
    probe_tag: str,
    expected_output: str,
    url_template: str = "http://{marker}[{tag}]",
) -> EvaluationResult:
    """Prove a server-side shortcode evaluation without side effects.

    ``fetch`` maps a ``current_url``-style input to the raw response body and
    ``extract`` pulls the sink value (e.g. a ``data-url`` attribute) out of it.
    ``probe_tag`` must name a shortcode the target registers that renders
    ``expected_output`` with no attributes, so the probe carries no executable
    content. Returns whether both the marker and the handler output appear.
    """
    body = fetch(url_template.format(marker=marker, tag=probe_tag))
    reflection = extract(body)
    evaluated = expected_output in body and marker in body
    return EvaluationResult(
        evaluated=evaluated,
        reflection=reflection,
        marker_present=marker in body,
    )


def evidence_from(result: EvaluationResult, extra: dict[str, Any] | None = None) -> dict[str, Any]:
    """Merge an evaluation result into a finding evidence dict."""
    evidence: dict[str, Any] = {
        "reflection": result.reflection[:200] if result.reflection else None,
        "marker_reflected": result.marker_present,
        "shortcode_evaluated": result.evaluated,
    }
    if extra:
        evidence.update(extra)
    return evidence
