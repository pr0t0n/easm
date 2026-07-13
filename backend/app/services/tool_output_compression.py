"""Generic 3-layer compression for tool stdout meant for display/narrative use.

The dnsenum wildcard-flood incident (scan_intelligence.py) was fixed with a
bespoke rule for one tool's output shape. This is the same idea generalized:
any tool that floods its output with many near-identical lines (a bruteforce
section, a fuzzer hitting a soft-404, a crawler looping on a session param)
gets collapsed the same way, without needing a new hand-rolled fix each time.

NEVER apply this to text a parser still reads line-by-line for evidence
extraction — it is lossy by design. Apply it only to a display/preview copy;
the full text always stays on disk in the Kali workspace, so nothing is
actually lost, just not duplicated at full size in Postgres or an LLM prompt.
"""
from __future__ import annotations

import re

_DIGIT_RUN_RE = re.compile(r"\d+")
_LONGTOKEN_RE = re.compile(r"[A-Za-z0-9_.-]{20,}")


def _line_signature(line: str) -> str:
    """Collapse the variable parts of a line (numbers, long tokens) so
    structurally-identical lines (different subdomain, same catch-all IP;
    different session id, same crawl loop) share a signature."""
    sig = _DIGIT_RUN_RE.sub("#", line.strip())
    sig = _LONGTOKEN_RE.sub("*", sig)
    return sig


def compress_tool_output(text: str, *, max_chars: int = 3000, min_group_size: int = 4) -> str:
    """Collapse repeated-shape lines, then truncate with a placeholder.

    1. Drop blank lines.
    2. Group lines by signature; once a signature repeats >= min_group_size
       times, keep the first occurrence, add one "+N more like this" note,
       and silently drop the rest wherever they appear (contiguous or not).
       Order is otherwise preserved.
    3. If still over max_chars, truncate with a placeholder noting how many
       characters were cut.
    """
    if not text:
        return ""
    lines = [ln for ln in text.splitlines() if ln.strip()]
    if not lines:
        return ""

    counts: dict[str, int] = {}
    for line in lines:
        sig = _line_signature(line)
        counts[sig] = counts.get(sig, 0) + 1

    compacted: list[str] = []
    flood_noted: set[str] = set()
    for line in lines:
        sig = _line_signature(line)
        if counts[sig] < min_group_size:
            compacted.append(line)
            continue
        if sig not in flood_noted:
            compacted.append(line)
            compacted.append(f"  ... (+{counts[sig] - 1} linhas parecidas com essa, omitidas)")
            flood_noted.add(sig)

    result = "\n".join(compacted)
    if len(result) > max_chars:
        cut = len(result) - max_chars
        result = result[:max_chars].rstrip() + f"\n... [{cut} caracteres cortados; saida completa em disco]"
    return result
