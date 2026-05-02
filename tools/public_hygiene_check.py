from __future__ import annotations

from pathlib import Path

BLOCKED_PATTERNS = (
    "pos.kbeam",
    "api.kbeam",
    "kbeam.de",
    "/Volumes/",
    "/Users/",
    "htpasswd",
)

SKIP_DIRS = {
    ".git",
    ".venv",
    ".pytest_cache",
    ".ruff_cache",
    "__pycache__",
}


def iter_text_files(root: Path):
    for path in root.rglob("*"):
        if any(part in SKIP_DIRS for part in path.parts):
            continue
        if path == Path(__file__).resolve():
            continue
        if not path.is_file():
            continue
        try:
            text = path.read_text(encoding="utf-8")
        except UnicodeDecodeError:
            continue
        yield path, text


def main() -> int:
    root = Path(__file__).resolve().parents[1]
    findings: list[str] = []
    for path, text in iter_text_files(root):
        for pattern in BLOCKED_PATTERNS:
            if pattern in text:
                findings.append(f"{path.relative_to(root)} contains blocked pattern: {pattern}")

    if findings:
        print("\n".join(findings))
        return 1
    print("Public hygiene check passed.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
