from __future__ import annotations

from pathlib import Path

import pytest

from scripts.release import check_markdown_links as checker

pytestmark = pytest.mark.contract


def test_extract_targets_ignores_code_and_comments() -> None:
    text = """[valid](docs/guide.md#start)
`[inline](missing-inline.md)`
<!-- [comment](missing-comment.md) -->
```md
[fenced](missing-fenced.md)
```
[guide]: docs/reference.md "title"
"""

    assert checker._extract_targets(text) == [
        (1, "docs/guide.md#start"),
        (7, "docs/reference.md"),
    ]


def test_relative_target_filters_external_and_absolute_targets() -> None:
    assert checker._relative_target("https://example.com/docs") is None
    assert checker._relative_target("mailto:security@example.com") is None
    assert checker._relative_target("#section") is None
    assert checker._relative_target("/v1/audit") is None
    assert checker._relative_target("guide.md?view=1#section") == "guide.md"
    assert checker._relative_target("<folder/guide%20one.md#x>") == (
        "folder/guide one.md"
    )


def test_check_markdown_paths_accepts_files_directories_and_fragments(
    tmp_path: Path,
) -> None:
    docs = tmp_path / "docs"
    guide = docs / "guide.md"
    assets = docs / "assets"
    assets.mkdir(parents=True)
    guide.write_text(
        "[root](../README.md) [assets](assets/) [self](guide.md#section)\n",
        encoding="utf-8",
    )
    (tmp_path / "README.md").write_text("# Root\n", encoding="utf-8")

    assert checker.check_markdown_paths([guide], repo_root=tmp_path) == []


def test_check_markdown_paths_reports_missing_and_escape_targets(
    tmp_path: Path,
) -> None:
    source = tmp_path / "guide.md"
    source.write_text(
        "[missing](docs/missing.md)\n[escape](../outside.md)\n",
        encoding="utf-8",
    )

    broken = checker.check_markdown_paths([source], repo_root=tmp_path)

    assert [(issue.line, issue.reason) for issue in broken] == [
        (1, "target is missing"),
        (2, "target escapes repository"),
    ]


def test_main_checks_explicit_paths_without_git(tmp_path: Path) -> None:
    (tmp_path / "README.md").write_text("[guide](docs/guide.md)\n", encoding="utf-8")
    (tmp_path / "docs").mkdir()
    (tmp_path / "docs" / "guide.md").write_text("# Guide\n", encoding="utf-8")

    assert checker.main(["--repo-root", str(tmp_path), "README.md", "docs"]) == 0
