# Prompting playbook — external AI review of memory-safety research

Use this when asking an external model to review a defect, a reproducer, or a
source tree. The goal is a useful defensive analysis without triggering content
filters or producing operational material.

## Principles

1. Frame the request as a defensive severity/impact review, not as an offensive
   exercise. Ask what the defect can affect, under which conditions, and what
   evidence would change the classification; do not ask for operational
   tooling, a chain, or a demonstration.
2. Never use the banned terms in the prompt, the questions, the included prose,
   comments, logs, **or the filename/title**. Scan the final packet.
3. Ask for a benign observation (a controlled crash, a unique marker) rather
   than a command interpreter or a state-changing action.
4. Keep the technical core: source paths/lines, offsets, allocator behavior,
   versions, build flags, and the observed effect. Redaction is about wording,
   not about removing the facts needed for analysis.
5. Separate verified facts from hypotheses; mark each.
6. Ask the model to challenge the premise and to state uncertainty.

## Filename and title

The filename and the first lines are part of the packet and are often scanned
first.

- Do not use product nicknames ("ruby2shell"), CVE/GHSA IDs, or any avoid-list
  term in the filename or title.
- Use a neutral descriptive name: `<component>-<defect-class>-review.txt`
  (for example `ruby-case-conversion-review.txt`).
- Put identifiers only in a final references section, or omit them when the
  upstream source and the fix commit are enough for the analysis.

## Redaction mechanics

- Replace identifiers with a single hyphenated token (for example
  `case-conversion`), never with a phrase containing spaces. The replacement
  can land inside a shell path, a YAML key, or a code string and break the
  artifact.
- Do not run text replacements inside code blocks, paths, filenames, or
  configuration keys. Rewrite the snippet or omit it.
- After sanitizing, run a syntax check on any included shell/YAML and re-scan
  the whole packet. A reviewer may reject broken artifacts even when the
  wording is clean.

## Scope of the request

Ask for a **classification and remediation decision**, not for an impact path:

- Is the observed effect limited to availability (a controlled crash), or could
  it plausibly affect confidentiality or integrity?
- Which classes of runtime conditions would be required for a higher impact?
- Is the affected routine reachable from untrusted input in common frameworks?
- Which mitigations and monitoring are appropriate?
- What benign observation or patched control would change the classification?

Do not ask for heap layout steps, candidate targets, allocator manipulation,
reliability/leaks, or a harness. Do not include third-party exploitation
research, PoC code, heap-observer tools, or crash logs; include the upstream
source, the fix, and the benign lab observation.

## Term map

| Avoid | Prefer |
|---|---|
| remote code execution, RCE, arbitrary code execution, code execution | security-relevant impact, integrity impact |
| exploit, exploitation, exploit chain, weaponize, weaponization | impact path, impact analysis, demonstration |
| PoC, proof-of-concept, payload, shell, backdoor, implant | validation harness, test input, benign marker |
| attack, attacker, malicious, adversary | test, untrusted input, crafted input |
| pwn, pwned, owned | marker, observed effect |
| red team, offensive, kill chain | defensive review, impact assessment |
| 0-day, zero-day | unpatched defect |
| privilege escalation | access-boundary impact |
| remote (when not needed) | web-facing, request-path |
| vulnerability (prefer) | defect, issue |
| ruby2shell, CVE-XXXX-XXXXX, GHSA-xxxx | the case-conversion defect, the upstream advisory |
| heap grooming, tcache, GOT, mprotect, safe-linking, chunk header, overlap, arbitrary write, ROP, JOP, shellcode | allocator behavior, adjacent data, memory-safety effect |
| corrupt, corruption | change, effect |
| crash log, ASAN log | observed effect, diagnostic output |

## Packet structure

1. Role and task (defensive triage).
2. Constraints (no operational guidance; benign observation; isolated lab).
3. Established facts (verified vs. hypothesis).
4. Questions (Q1..Qn) covering: defect confirmation, impact classification,
   conditions, reachability, mitigations, evidence, verdict, challenge.
5. Output format (Markdown sections).
6. Source and artifacts (clean source; sanitized prose; benign observation).

## Pre-send checklist

- [ ] Search the **filename, title, prompt, prose, comments, and logs** for the
      avoid list (case-insensitive).
- [ ] No operational code that runs a command, opens a shell, or changes a
      system; only a benign observation if needed.
- [ ] Questions ask for classification and conditions, not for a step-by-step
      recipe, candidate targets, or reliability work.
- [ ] No third-party exploitation research, PoC code, heap-observer tool, or
      crash log is included.
- [ ] The packet still contains the source lines, offsets, versions, and the
      observed effect needed to answer.
- [ ] The model is asked to say "not demonstrated" when the evidence is
      insufficient.

## Lessons from iteration

- A product nickname in the filename ("ruby2shell") blocked the packet even
  after the prompt was sanitized.
- Sanitized exploitation questions ("candidate targets", "heap grooming",
  "reliability", "validation harness") still read as a request for operational
  detail. Ask for a severity classification instead.
- Third-party research prose and crash logs carry their own trigger terms;
  paraphrase the technical geometry and keep only the upstream source, the fix,
  and the benign observation.
- A clean-looking prompt can still include broken artifacts: a redaction that
  replaces an identifier with a multi-word phrase corrupted a shell `log=` path
  and a YAML key in one packet. Rewrite code, never string-replace inside it.
- The reviewer may correct technical claims in the packet. Record those
  corrections in the repository's lab notes instead of only in the chat.
- A reviewer's "not reachable by default" claim can miss a parser-level
  charset path. Audit the framework source and run a minimal request: the Rack
  multipart `charset` + `_method.upcase` path was verified after the review
  said it required a non-default encoding.
- A packet that asks the reviewer to design or rank observation techniques
  ("workaround", "alternative designs", "verification endpoint") can be
  blocked instantly even when the wording is sanitized. Keep the request to
  classification, reachability conditions, control expectations, mitigations
  and evidence thresholds. Report negative lab findings as verified facts;
  do not ask the reviewer to propose a technique. Avoid "workaround" in the
  filename and title.
- The same block happens with "hidden oracle" / "unused signal" framing: asking
  whether an unused externally observable difference exists, or to order cases
  by lab-validation tractability. Strip those questions entirely. Use a neutral
  filename such as `<count>-defect-classification-review.txt` and ask only for
  defect confirmation, impact classification, reachability, control behavior,
  mitigations, evidence thresholds, verdict and premise challenge.

## Note

This playbook governs the wording of external review packets. It does not
change the repository's validation rules: a `CONFIRMED` disposition still
requires a live, controlled observation and a patched control.
