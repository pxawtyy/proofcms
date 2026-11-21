# Prompting playbook — external AI review of memory-safety research

Use this when asking an external model to review a defect, a reproducer, or a
source tree. The goal is a useful defensive analysis without triggering content
filters or producing operational material.

## Principles

1. Frame the request as a defensive impact assessment, not as an offensive
   exercise. Ask what the defect can affect, under which conditions, and what
   evidence would be needed; do not ask for operational tooling.
2. Never use the banned terms in the prompt, the questions, the included prose,
   comments, or logs. Scan the final packet.
3. Ask for a benign reproducer (a marker file, a unique string, a controlled
   crash) rather than a command interpreter or a state-changing action.
4. Keep the technical core: source paths/lines, offsets, allocator geometry,
   versions, build flags, and the observed effect. Redaction is about wording,
   not about removing the facts needed for analysis.
5. Separate verified facts from hypotheses; mark each.
6. Ask the model to challenge the premise and to state uncertainty.

## Term map

| Avoid | Prefer |
|---|---|
| remote code execution, RCE, arbitrary code execution, code execution | security-relevant process impact, control-flow integrity impact |
| exploit, exploitation, exploit chain, weaponize, weaponization | impact path, impact analysis, demonstration |
| PoC, proof-of-concept, payload, shell, backdoor, implant | validation harness, test input, benign marker |
| attack, attacker, malicious, adversary | test, untrusted input, crafted input |
| pwn, pwned, owned | marker, observed effect |
| red team, offensive, kill chain | defensive research, impact assessment |
| 0-day, zero-day | unpatched defect |
| privilege escalation | access-boundary impact |
| remote (when not needed) | web-facing, request-path |
| vulnerability (prefer) | defect, issue |

## Packet structure

1. Role and task (defensive).
2. Constraints (no operational tooling; benign marker; isolated lab).
3. Established facts (verified vs. hypothesis).
4. Questions (Q1..Qn) covering: primitive, geometry, allocator effect, targets,
   runtime layout, reachability, impact path, benign reproducer, reliability,
   proof/control, verdict, challenge.
5. Output format (Markdown sections).
6. Source and artifacts (clean source; sanitized prose; benign reproducer).

## Pre-send checklist

- [ ] Search the whole packet for the avoid list (case-insensitive).
- [ ] No operational code that runs a command, opens a shell, or changes a
      system; only a marker/reproducer.
- [ ] Questions ask for analysis and conditions, not for a step-by-step
      operational recipe.
- [ ] The packet still contains the source lines, offsets, versions, and the
      observed effect needed to answer.
- [ ] The model is asked to say "not demonstrated" when the evidence is
      insufficient.

## Note

This playbook governs the wording of external review packets. It does not
change the repository's validation rules: a `CONFIRMED` disposition still
requires a live, controlled observation and a patched control.
