#!/usr/bin/env python3
from __future__ import annotations

import argparse
import json
import re
import subprocess
from dataclasses import asdict, dataclass
from pathlib import Path


KEYWORDS = (
    "password",
    "passwd",
    "pwd",
    "passphrase",
    "secret",
    "token",
    "access_token",
    "refresh_token",
    "auth_token",
    "client_secret",
    "api_key",
    "apikey",
    "access_key",
    "private_key",
    "db_password",
)

KEYWORD_PATTERN = (
    r"(?:password|passwd|pwd|passphrase|secret|token|access[_-]?token|refresh[_-]?token|auth[_-]?token|"
    r"client[_-]?secret|api[_-]?key|access[_-]?key|private[_-]?key|db[_-]?password)"
)
ASSIGNMENT_PATTERN = re.compile(
    rf"(?i)\b(?P<key>{KEYWORD_PATTERN})\b\s*[:=]\s*(?P<value>\"[^\"]{{4,}}\"|'[^']{{4,}}'|[^\s,#]{{4,}})"
)
ENV_EXPORT_PATTERN = re.compile(
    rf"(?i)^\s*(?:export\s+)?(?P<key>{KEYWORD_PATTERN})\s*=\s*(?P<value>\"[^\"]{{4,}}\"|'[^']{{4,}}'|[^\s,#]{{4,}})"
)
CLI_FLAG_PATTERN = re.compile(
    rf"(?i)(?:--(?P<key>{KEYWORD_PATTERN})\s*[= ]\s*(?P<value>\"[^\"]{{4,}}\"|'[^']{{4,}}'|[^\s,#]{{4,}}))"
)
URL_CREDENTIAL_PATTERN = re.compile(
    r"(?i)\b(?P<scheme>[a-z][a-z0-9+\-.]{1,12})://(?P<user>[^:@/\s]{1,64}):(?P<value>[^@/\s]{4,})@"
)
CONN_PASSWORD_PATTERN = re.compile(
    r"(?i)\b(?:password|pwd)\s*=\s*(?P<value>[^;,\s'\"`]{4,}|\"[^\"]{4,}\"|'[^']{4,}')"
)
BEARER_PATTERN = re.compile(
    r"(?i)\bBearer\s+(?P<value>[A-Za-z0-9\-._~+/]{12,}={0,2})"
)
PLACEHOLDER_VALUES = {
    "changeme",
    "change_me",
    "example",
    "password",
    "secret",
    "your_password",
    "<password>",
    "********",
    "removed",
    "redacted",
    "masked",
    "dummy",
    "null",
    "none",
}

TEXT_EXTENSIONS_SKIP = {
    ".png",
    ".jpg",
    ".jpeg",
    ".gif",
    ".pdf",
    ".zip",
    ".gz",
    ".tar",
    ".jar",
    ".war",
    ".so",
    ".dylib",
    ".class",
    ".pyc",
}


@dataclass
class Finding:
    source: str
    location: str
    line: int
    key: str
    value_preview: str
    risk: str
    matched_text: str


def sanitize_value(raw: str) -> str:
    value = raw.strip().strip('"').strip("'")
    return value.strip()


def mask_value(value: str) -> str:
    if len(value) <= 4:
        return "*" * len(value)
    return f"{value[:2]}{'*' * (len(value) - 4)}{value[-2:]}"


def classify_risk(value: str) -> str:
    lower = value.lower()
    if lower in PLACEHOLDER_VALUES:
        return "LOW"
    if len(value) >= 12 and re.search(r"[A-Z]", value) and re.search(r"[a-z]", value) and re.search(r"\d", value):
        return "HIGH"
    if len(value) >= 8:
        return "MEDIUM"
    return "LOW"


def is_likely_literal(value_raw: str, value_clean: str) -> bool:
    raw = value_raw.strip()
    quoted = (raw.startswith('"') and raw.endswith('"')) or (raw.startswith("'") and raw.endswith("'"))

    if quoted:
        # Quoted value still might be env interpolation instead of literal secret.
        if "$(" in value_clean or "${" in value_clean:
            return False
        return True

    if any(ch in value_clean for ch in ("$(", "${", "`", "(", ")", "{", "}", "[", "]", "<", ">", "|", ";")):
        return False
    if re.fullmatch(r"[A-Za-z_][A-Za-z0-9_]*", value_clean) and not re.search(r"\d", value_clean):
        return False
    return True


def is_placeholder_value(value: str) -> bool:
    return value.strip().lower() in PLACEHOLDER_VALUES


def detect_secret_in_line(line: str) -> tuple[str, str] | None:
    for pattern in (ASSIGNMENT_PATTERN, ENV_EXPORT_PATTERN):
        match = pattern.search(line)
        if not match:
            continue
        key = match.group("key")
        value_raw = match.group("value")
        value = sanitize_value(value_raw)
        if not value:
            return None
        if is_placeholder_value(value):
            return None
        if not is_likely_literal(value_raw, value):
            return None
        return key, value

    cli_match = CLI_FLAG_PATTERN.search(line)
    if cli_match:
        key = cli_match.group("key")
        value_raw = cli_match.group("value")
        value = sanitize_value(value_raw)
        if value and not is_placeholder_value(value) and is_likely_literal(value_raw, value):
            return key, value

    url_match = URL_CREDENTIAL_PATTERN.search(line)
    if url_match:
        value = sanitize_value(url_match.group("value"))
        if value and not is_placeholder_value(value):
            return "url_password", value

    conn_match = CONN_PASSWORD_PATTERN.search(line)
    if conn_match:
        value_raw = conn_match.group("value")
        value = sanitize_value(value_raw)
        if value and not is_placeholder_value(value) and is_likely_literal(value_raw, value):
            return "connection_password", value

    if re.search(r"(?i)\b(authorization|auth)\b", line):
        bearer_match = BEARER_PATTERN.search(line)
        if bearer_match:
            value = sanitize_value(bearer_match.group("value"))
            if value and not is_placeholder_value(value):
                return "bearer_token", value

    return None


def should_skip_file(path: Path, exclude_dirs: set[str]) -> bool:
    if any(part in exclude_dirs for part in path.parts):
        return True
    return path.suffix.lower() in TEXT_EXTENSIONS_SKIP


def scan_worktree(root: Path, exclude_dirs: set[str]) -> list[Finding]:
    findings: list[Finding] = []
    for path in root.rglob("*"):
        if not path.is_file() or should_skip_file(path, exclude_dirs):
            continue
        try:
            lines = path.read_text(encoding="utf-8", errors="ignore").splitlines()
        except OSError:
            continue
        for line_no, line in enumerate(lines, start=1):
            found = detect_secret_in_line(line)
            if not found:
                continue
            key, value = found
            findings.append(
                Finding(
                    source="worktree",
                    location=str(path),
                    line=line_no,
                    key=key,
                    value_preview=mask_value(value),
                    risk=classify_risk(value),
                    matched_text=line.strip(),
                )
            )
    return findings


def run_git_history_scan(root: Path) -> list[Finding]:
    findings: list[Finding] = []
    cmd = [
        "git",
        "log",
        "--all",
        "--date=short",
        "--pretty=format:@@@%H|%ad|%s",
        "-p",
        "--",
        ".",
    ]

    try:
        result = subprocess.run(
            cmd,
            cwd=root,
            capture_output=True,
            text=True,
            check=False,
        )
    except OSError:
        return findings

    if result.returncode != 0 or not result.stdout:
        return findings

    commit = ""
    date = ""
    subject = ""
    current_file = ""
    current_line = 0

    for raw_line in result.stdout.splitlines():
        if raw_line.startswith("@@@"):
            commit_info = raw_line[3:].split("|", 2)
            if len(commit_info) == 3:
                commit, date, subject = commit_info
            continue

        if raw_line.startswith("+++ b/"):
            current_file = raw_line[6:]
            continue
        if raw_line.startswith("@@"):
            line_match = re.search(r"\+(\d+)", raw_line)
            current_line = int(line_match.group(1)) if line_match else 0
            continue

        if not raw_line.startswith(("+", "-")):
            continue
        if raw_line.startswith(("+++", "---")):
            continue

        sign = raw_line[0]
        if sign != "+":
            continue
        content = raw_line[1:]
        found = detect_secret_in_line(content)
        if not found:
            current_line += 1
            continue

        key, value = found
        findings.append(
            Finding(
                source="history",
                location=f"{current_file}@{commit[:10]} ({date})",
                line=current_line if current_line > 0 else 1,
                key=key,
                value_preview=mask_value(value),
                risk=classify_risk(value),
                matched_text=f"{subject} | {content.strip()}",
            )
        )
        current_line += 1

    return findings


def summarize(findings: list[Finding]) -> dict[str, int]:
    summary = {"HIGH": 0, "MEDIUM": 0, "LOW": 0}
    for finding in findings:
        summary[finding.risk] = summary.get(finding.risk, 0) + 1
    return summary


def print_human(findings: list[Finding], max_findings: int) -> None:
    if not findings:
        print("Hardcoded secret bulunamadi.")
        return

    print(f"Toplam bulgu: {len(findings)}")
    print("Risk dagilimi:", summarize(findings))
    print("")

    for finding in findings[:max_findings]:
        print(
            f"[{finding.risk}] {finding.source} | {finding.location}:{finding.line} | "
            f"key={finding.key} | value={finding.value_preview}"
        )
        print(f"  ornek: {finding.matched_text[:180]}")

    if len(findings) > max_findings:
        hidden = len(findings) - max_findings
        print(f"\n... {hidden} bulgu daha var. --max-findings ile arttirabilirsiniz.")


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Hardcoded password/secret tarayici (worktree + git history)."
    )
    parser.add_argument("--path", default=".", help="Taranacak kok dizin. Varsayilan: .")
    parser.add_argument(
        "--history",
        action="store_true",
        help="Git history taramasini etkinlestirir.",
    )
    parser.add_argument(
        "--exclude-dir",
        action="append",
        default=[".git", "node_modules", ".venv", "__pycache__", "dist", "build"],
        help="Haric tutulacak dizin (birden fazla verilebilir).",
    )
    parser.add_argument("--json", action="store_true", help="Ciktiyi JSON olarak verir.")
    parser.add_argument("--max-findings", type=int, default=200, help="Maksimum cikti adedi.")
    return parser.parse_args()


def main() -> int:
    args = parse_args()
    root = Path(args.path).resolve()
    exclude_dirs = set(args.exclude_dir)

    findings = scan_worktree(root, exclude_dirs)

    if args.history:
        findings.extend(run_git_history_scan(root))

    risk_rank = {"HIGH": 3, "MEDIUM": 2, "LOW": 1}
    findings.sort(
        key=lambda item: (risk_rank.get(item.risk, 0), item.source, item.location, item.line),
        reverse=True,
    )

    if args.json:
        payload = {
            "path": str(root),
            "history_enabled": args.history,
            "keyword_set": KEYWORDS,
            "summary": summarize(findings),
            "findings": [asdict(item) for item in findings[: args.max_findings]],
        }
        print(json.dumps(payload, ensure_ascii=False, indent=2))
    else:
        print_human(findings, args.max_findings)

    return 0


if __name__ == "__main__":
    raise SystemExit(main())
