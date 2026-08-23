#!/usr/bin/env python3
"""Validate repository-local targets in Markdown links.

The checker intentionally does not make network requests or validate anchors.
It verifies that relative file and directory targets exist inside the repository,
while ignoring external URLs, absolute paths, fenced code, inline code, and HTML
comments.
"""

from __future__ import annotations

import argparse
from dataclasses import dataclass
import html
from pathlib import Path
import re
import subprocess
from typing import Iterable, Sequence
from urllib.parse import unquote, urlsplit

_REPO_ROOT = Path(__file__).resolve().parents[2]
_FENCE = re.compile(r"^\s*(`{3,}|~{3,})")
_HTML_COMMENT = re.compile(r"<!--.*?-->", re.DOTALL)
_INLINE_CODE = re.compile(r"(`+)(?:.|\n)*?\1")
_INLINE_LINK = re.compile(
    r"!?\[[^\]]*\]\(\s*(?P<target><[^>]+>|[^\s)]+)",
    re.MULTILINE,
)
_REFERENCE_LINK = re.compile(
    r"^\s*\[[^\]]+\]:\s*(?P<target><[^>]+>|\S+)",
    re.MULTILINE,
)


@dataclass(frozen=True, slots=True)
class BrokenLink:
    source: Path
    line: int
    target: str
    reason: str


def _without_fenced_code(text: str) -> str:
    output: list[str] = []
    active_marker: str | None = None
    for line in text.splitlines(keepends=True):
        match = _FENCE.match(line)
        if match:
            marker = match.group(1)
            marker_char = marker[0]
            if active_marker is None:
                active_marker = marker_char
            elif active_marker == marker_char:
                active_marker = None
            output.append("\n" if line.endswith("\n") else "")
            continue
        output.append(
            line if active_marker is None else ("\n" if line.endswith("\n") else "")
        )
    return "".join(output)


def _extract_targets(text: str) -> list[tuple[int, str]]:
    scrubbed = _without_fenced_code(text)
    scrubbed = _HTML_COMMENT.sub(
        lambda match: "\n" * match.group(0).count("\n"), scrubbed
    )
    scrubbed = _INLINE_CODE.sub(
        lambda match: "\n" * match.group(0).count("\n"), scrubbed
    )
    matches = [*_INLINE_LINK.finditer(scrubbed), *_REFERENCE_LINK.finditer(scrubbed)]
    return sorted(
        (
            scrubbed.count("\n", 0, match.start("target")) + 1,
            match.group("target"),
        )
        for match in matches
    )


def _relative_target(raw_target: str) -> str | None:
    target = html.unescape(raw_target.strip())
    if target.startswith("<") and target.endswith(">"):
        target = target[1:-1].strip()
    if not target or target.startswith(("#", "//", "/")):
        return None
    parsed = urlsplit(target)
    if parsed.scheme or parsed.netloc:
        return None
    path = unquote(parsed.path)
    if not path or any(token in path for token in ("${", "{{", "}}")):
        return None
    return path


def check_markdown_paths(
    paths: Iterable[Path], *, repo_root: Path = _REPO_ROOT
) -> list[BrokenLink]:
    root = repo_root.resolve()
    broken: list[BrokenLink] = []
    for source in sorted({path.resolve() for path in paths}):
        if not source.is_file() or source.suffix.lower() != ".md":
            continue
        text = source.read_text(encoding="utf-8")
        for line, raw_target in _extract_targets(text):
            relative = _relative_target(raw_target)
            if relative is None:
                continue
            resolved = (source.parent / relative).resolve()
            try:
                resolved.relative_to(root)
            except ValueError:
                broken.append(
                    BrokenLink(source, line, raw_target, "target escapes repository")
                )
                continue
            if not resolved.exists():
                broken.append(BrokenLink(source, line, raw_target, "target is missing"))
    return broken


def _decode_git_paths(payload: bytes, repo_root: Path) -> set[Path]:
    return {
        repo_root / raw.decode("utf-8", errors="surrogateescape")
        for raw in payload.split(b"\0")
        if raw and raw.lower().endswith(b".md")
    }


def _run_git(repo_root: Path, *arguments: str) -> bytes:
    completed = subprocess.run(
        ["git", *arguments],
        cwd=repo_root,
        check=False,
        capture_output=True,
    )
    if completed.returncode != 0:
        detail = completed.stderr.decode("utf-8", errors="replace").strip()
        raise RuntimeError(detail or f"git {' '.join(arguments)} failed")
    return completed.stdout


def _git_markdown_paths(repo_root: Path, base_ref: str | None) -> set[Path]:
    if base_ref is None:
        return _decode_git_paths(
            _run_git(
                repo_root,
                "ls-files",
                "--cached",
                "--others",
                "--exclude-standard",
                "-z",
                "--",
                "*.md",
            ),
            repo_root,
        )

    paths = _decode_git_paths(
        _run_git(
            repo_root,
            "diff",
            "--name-only",
            "--diff-filter=ACMRT",
            "-z",
            f"{base_ref}...HEAD",
            "--",
            "*.md",
        ),
        repo_root,
    )
    paths.update(
        _decode_git_paths(
            _run_git(
                repo_root,
                "diff",
                "--name-only",
                "--diff-filter=ACMRT",
                "-z",
                "--",
                "*.md",
            ),
            repo_root,
        )
    )
    paths.update(
        _decode_git_paths(
            _run_git(
                repo_root,
                "ls-files",
                "--others",
                "--exclude-standard",
                "-z",
                "--",
                "*.md",
            ),
            repo_root,
        )
    )
    return paths


def _explicit_paths(raw_paths: Sequence[str], repo_root: Path) -> set[Path]:
    paths: set[Path] = set()
    for raw_path in raw_paths:
        candidate = (repo_root / raw_path).resolve()
        if candidate.is_dir():
            paths.update(candidate.rglob("*.md"))
        else:
            paths.add(candidate)
    return paths


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "paths",
        nargs="*",
        help="Markdown files or directories; defaults to Git-tracked and unignored files",
    )
    parser.add_argument(
        "--base-ref",
        help="check Markdown changed since BASE...HEAD plus local working-tree additions",
    )
    parser.add_argument("--repo-root", type=Path, default=_REPO_ROOT)
    return parser


def main(argv: Sequence[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    repo_root = args.repo_root.resolve()
    try:
        paths = (
            _explicit_paths(args.paths, repo_root)
            if args.paths
            else _git_markdown_paths(repo_root, args.base_ref)
        )
        broken = check_markdown_paths(paths, repo_root=repo_root)
    except (OSError, RuntimeError, UnicodeError) as exc:
        print(f"markdown link check failed: {exc}")
        return 2

    for issue in broken:
        source = issue.source.relative_to(repo_root)
        print(f"{source}:{issue.line}: {issue.reason}: {issue.target}")
    if broken:
        print(f"markdown link check failed: {len(broken)} broken target(s)")
        return 1
    print(f"markdown link check passed: {len(paths)} file(s)")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
