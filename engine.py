import ast
import os
import re
import zipfile
from collections import Counter

try:
    from app.utils import _decode_bytes, _find_readme_name, _find_skill_md_name, _format_size
except ImportError:
    try:
        from .securityskills_utils import _decode_bytes, _find_readme_name, _find_skill_md_name, _format_size
    except ImportError:
        from securityskills_utils import _decode_bytes, _find_readme_name, _find_skill_md_name, _format_size

_REVIEW_EXECUTABLE_EXTENSIONS = {
    ".sh",
    ".bash",
    ".zsh",
    ".ps1",
    ".psm1",
    ".psd1",
    ".bat",
    ".cmd",
    ".py",
    ".js",
    ".mjs",
    ".cjs",
    ".ts",
    ".tsx",
    ".rb",
    ".php",
    ".pl",
}
_REVIEW_TEXT_EXTENSIONS = _REVIEW_EXECUTABLE_EXTENSIONS | {
    ".md",
    ".txt",
    ".json",
    ".yaml",
    ".yml",
    ".toml",
    ".ini",
    ".cfg",
    ".conf",
    ".env",
    ".properties",
    ".xml",
    ".html",
    ".css",
    ".sql",
}
_REVIEW_EXECUTABLE_NAMES = {
    "dockerfile",
    "makefile",
    "justfile",
}
_REVIEW_MANIFEST_NAMES = {
    "package.json",
    "package-lock.json",
    "pnpm-lock.yaml",
    "yarn.lock",
    "requirements.txt",
    "pyproject.toml",
    "poetry.lock",
    "pipfile",
    "pipfile.lock",
    "dockerfile",
    "docker-compose.yml",
    "docker-compose.yaml",
    "makefile",
    "cargo.toml",
    "go.mod",
}
_REVIEW_SUSPICIOUS_PATTERNS = [
    {
        "severity": "high",
        "type": "network",
        "title": "Detected remote script execution command",
        "detail": "The archive contains commands that download remote content and execute it immediately.",
        "pattern": re.compile(r"(curl|wget)[^\n|]{0,200}\|\s*(bash|sh|zsh|pwsh|powershell)", re.IGNORECASE),
    },
    {
        "severity": "high",
        "type": "obfuscation",
        "title": "Detected encoded or obfuscated command",
        "detail": "The archive references encoded commands that may hide real behavior and make review harder.",
        "pattern": re.compile(r"(encodedcommand|-enc\b|frombase64string|base64\s+-d)", re.IGNORECASE),
    },
    {
        "severity": "high",
        "type": "execution",
        "title": "Detected runtime code execution",
        "detail": "The archive contains patterns for dynamically executing code or shell commands.",
        "pattern": re.compile(r"(invoke-expression|\biex\b|eval\s*\(|exec\s*\(|os\.system\s*\(|subprocess\.(run|popen|call)\s*\()", re.IGNORECASE),
    },
    {
        "severity": "high",
        "type": "persistence",
        "title": "Detected persistence or auto-start behavior",
        "detail": "The archive includes scheduled tasks, startup entries, or other persistence-related content.",
        "pattern": re.compile(r"(crontab|schtasks|launchctl|systemctl\s+enable|currentversion\\run)", re.IGNORECASE),
    },
    {
        "severity": "medium",
        "type": "credential",
        "title": "Detected sensitive credential prompt",
        "detail": "The archive may ask for a token, key, cookie, or other secret during installation or use.",
        "pattern": re.compile(r"(provide|enter|paste|fill|set|export|input)[^\n]{0,80}(api[_ -]?key|token|secret|cookie|ssh key|private key)", re.IGNORECASE),
    },
    {
        "severity": "medium",
        "type": "network",
        "title": "Detected external network access or download behavior",
        "detail": "The archive contains commands or code that fetch remote content or call external APIs.",
        "pattern": re.compile(r"(invoke-webrequest|\biwr\b|requests\.(get|post)|urllib\.request|fetch\s*\(|axios\.|curl\s+https?://|wget\s+https?://)", re.IGNORECASE),
    },
    {
        "severity": "low",
        "type": "dependency",
        "title": "Detected external dependency installation",
        "detail": "The archive may install packages or build external dependencies during setup.",
        "pattern": re.compile(r"(pip\s+install|npm\s+(install|i)\b|pnpm\s+add|yarn\s+add|cargo\s+install|go\s+install|docker\s+build)", re.IGNORECASE),
    },
]


def _review_code_context(text: str, lineno: int, max_len: int = 180) -> str:
    if lineno <= 0:
        return ""
    lines = (text or "").splitlines()
    if lineno > len(lines):
        return ""

    pieces = []
    start = max(1, int(lineno) - 1)
    end = min(len(lines), int(lineno) + 1)
    for idx in range(start, end + 1):
        raw_line = str(lines[idx - 1] or "").rstrip()
        snippet = raw_line[:max_len]
        prefix = ">" if idx == int(lineno) else " "
        pieces.append(f"{prefix}L{idx}: {snippet}")
    return "\n".join(pieces)


def _review_loc(path: str, lineno: int = 0) -> str:
    base = (path or "").strip()
    if lineno > 0:
        return f"{base}:L{int(lineno)}"
    return base


def _review_detail_with_snippet(detail: str, text: str, lineno: int = 0) -> str:
    snippet = _review_code_context(text, lineno)
    if snippet:
        return f"{detail}\nCode context:\n{snippet}"
    return detail


def _review_match_lineno(text: str, match) -> int:
    if not text or match is None:
        return 0
    try:
        start = int(match.start())
    except Exception:
        return 0
    return int((text or "").count("\n", 0, max(0, start)) + 1)


def _review_locate_pattern_hit(path: str, text: str, match, detail: str):
    lineno = _review_match_lineno(text, match)
    return _review_loc(path, lineno), _review_detail_with_snippet(detail, text, lineno)


def _ast_call_name(node) -> str:
    if isinstance(node, ast.Name):
        return str(node.id or "")
    if isinstance(node, ast.Attribute):
        left = _ast_call_name(node.value)
        right = str(node.attr or "")
        if left and right:
            return f"{left}.{right}"
        return right
    if isinstance(node, ast.Call):
        return _ast_call_name(node.func)
    return ""


def _python_open_mode_is_write(node) -> bool:
    if not isinstance(node, ast.Call):
        return False
    mode_value = ""
    if len(node.args) >= 2 and isinstance(node.args[1], ast.Constant):
        mode_value = str(node.args[1].value or "")
    for kw in node.keywords or []:
        if kw.arg == "mode" and isinstance(kw.value, ast.Constant):
            mode_value = str(kw.value.value or "")
            break
    mode_value = mode_value.lower()
    return any(flag in mode_value for flag in ("w", "a", "x", "+"))


def _python_open_target(node) -> str:
    if not isinstance(node, ast.Call) or not node.args:
        return ""
    arg0 = node.args[0]
    if isinstance(arg0, ast.Constant):
        return str(arg0.value or "")
    return ""


def _review_python_code(path: str, text: str, add_issue, add_observation, is_truncated: bool = False) -> None:
    if is_truncated:
        return
    try:
        tree = ast.parse(text or "", filename=path or "<archive>")
    except SyntaxError:
        return

    for node in ast.walk(tree):
        if not isinstance(node, ast.Call):
            continue
        call_name = _ast_call_name(node.func).strip()
        lineno = int(getattr(node, "lineno", 0) or 0)
        loc = _review_loc(path, lineno)

        if call_name in {"eval", "builtins.eval", "exec", "builtins.exec"}:
            add_issue(
                "high",
                "execution",
                "Detected Python dynamic execution",
                _review_detail_with_snippet("The Python script calls dynamic execution functions and may run code not explicitly shown.", text, lineno),
                loc,
            )
        elif call_name in {
            "os.system",
            "subprocess.run",
            "subprocess.call",
            "subprocess.Popen",
            "subprocess.check_call",
            "subprocess.check_output",
            "asyncio.create_subprocess_exec",
            "asyncio.create_subprocess_shell",
        }:
            add_issue(
                "high",
                "execution",
                "Detected Python subprocess execution",
                _review_detail_with_snippet("The Python script starts external commands or subprocesses. Review the executed content carefully.", text, lineno),
                loc,
            )
        elif call_name in {"requests.get", "requests.post", "requests.request", "urllib.request.urlopen", "urllib.request.urlretrieve"}:
            add_observation(
                "network",
                "Detected Python external request",
                _review_detail_with_snippet("The Python script requests external network resources. Verify the destination and purpose.", text, lineno),
                loc,
            )
        elif call_name in {"base64.b64decode", "marshal.loads"}:
            add_issue(
                "medium",
                "obfuscation",
                "Detected Python deserialization or decoding behavior",
                _review_detail_with_snippet("The script performs decoding or deserialization. Confirm whether it is used to hide actual execution.", text, lineno),
                loc,
            )
        elif call_name == "open" and _python_open_mode_is_write(node):
            target = _python_open_target(node).lower()
            if any(mark in target for mark in (".bashrc", ".zshrc", ".profile", "currentversion\\run", "startup")):
                add_issue(
                    "high",
                    "persistence",
                    "Detected Python startup configuration write",
                    _review_detail_with_snippet("The Python script may modify startup configuration or autorun locations, which creates persistence risk.", text, lineno),
                    loc,
                )


def _review_shell_code(path: str, text: str, add_issue, add_observation) -> None:
    for idx, raw in enumerate((text or "").splitlines(), start=1):
        line = str(raw or "").strip()
        if not line or line.startswith("#"):
            continue
        loc = _review_loc(path, idx)

        if re.search(r"(curl|wget)[^\n|]{0,200}\|\s*(bash|sh|zsh)", line, re.IGNORECASE):
            add_issue(
                "high",
                "network",
                "Detected Shell remote script execution",
                _review_detail_with_snippet("The Shell script downloads remote content and pipes it directly to an interpreter.", text, idx),
                loc,
            )
        if re.search(r"\b(eval|bash\s+-c|sh\s+-c|zsh\s+-c)\b", line, re.IGNORECASE):
            add_issue(
                "high",
                "execution",
                "Detected Shell dynamic command execution",
                _review_detail_with_snippet("The Shell script dynamically constructs and executes commands.", text, idx),
                loc,
            )
        if re.search(r"\b(crontab|systemctl\s+enable|launchctl|schtasks)\b", line, re.IGNORECASE) or re.search(r">>\s*(~\/\.(bashrc|zshrc|profile)|\/etc\/profile)", line, re.IGNORECASE):
            add_issue(
                "high",
                "persistence",
                "Detected Shell persistence configuration",
                _review_detail_with_snippet("The Shell script modifies scheduled tasks, services, or startup configuration.", text, idx),
                loc,
            )
        if re.search(r"\b(curl|wget)\s+https?://", line, re.IGNORECASE) and not re.search(r"(curl|wget)[^\n|]{0,200}\|\s*(bash|sh|zsh)", line, re.IGNORECASE):
            add_observation(
                "network",
                "Detected Shell external download",
                _review_detail_with_snippet("The Shell script downloads content from an external location.", text, idx),
                loc,
            )
        if re.search(r"\b(export|read)\b[^\n]{0,80}(api[_ -]?key|token|secret|cookie|password)", line, re.IGNORECASE):
            add_issue(
                "medium",
                "credential",
                "Detected Shell credential handling",
                _review_detail_with_snippet("The Shell script handles sensitive credential input or configuration.", text, idx),
                loc,
            )


def _review_powershell_code(path: str, text: str, add_issue, add_observation) -> None:
    for idx, raw in enumerate((text or "").splitlines(), start=1):
        line = str(raw or "").strip()
        if not line or line.startswith("#"):
            continue
        loc = _review_loc(path, idx)

        if re.search(r"\b(Invoke-Expression|iex)\b", line, re.IGNORECASE):
            add_issue(
                "high",
                "execution",
                "Detected PowerShell dynamic execution",
                _review_detail_with_snippet("The PowerShell script calls dynamic execution commands.", text, idx),
                loc,
            )
        if re.search(r"\b(Start-Process|powershell(\.exe)?\s+-enc|pwsh\s+-enc)\b", line, re.IGNORECASE):
            add_issue(
                "high",
                "execution",
                "Detected PowerShell process launch or encoded execution",
                _review_detail_with_snippet("The PowerShell script launches extra processes or uses encoded parameters to run commands.", text, idx),
                loc,
            )
        if re.search(r"\b(Register-ScheduledTask|New-ScheduledTask|schtasks|Set-ItemProperty[^\n]{0,80}Run)\b", line, re.IGNORECASE):
            add_issue(
                "high",
                "persistence",
                "Detected PowerShell persistence behavior",
                _review_detail_with_snippet("The PowerShell script creates scheduled tasks or writes autorun entries.", text, idx),
                loc,
            )
        if re.search(r"\b(Invoke-WebRequest|Invoke-RestMethod|Start-BitsTransfer|iwr|irm)\b", line, re.IGNORECASE):
            add_observation(
                "network",
                "Detected PowerShell external request",
                _review_detail_with_snippet("The PowerShell script accesses external network resources.", text, idx),
                loc,
            )
        if re.search(r"\$env:[A-Z0-9_]*(KEY|TOKEN|SECRET|COOKIE|PASSWORD)", line, re.IGNORECASE):
            add_issue(
                "medium",
                "credential",
                "Detected PowerShell credential handling",
                _review_detail_with_snippet("The PowerShell script handles sensitive environment variables or credential content.", text, idx),
                loc,
            )


def _review_code_content_by_type(path: str, text: str, add_issue, add_observation, is_truncated: bool = False) -> None:
    ext = os.path.splitext(os.path.basename(path or "").lower())[1]
    basename = os.path.basename(path or "").lower()
    if ext == ".py":
        _review_python_code(path, text, add_issue, add_observation, is_truncated=is_truncated)
        return
    if ext in {".sh", ".bash", ".zsh"}:
        _review_shell_code(path, text, add_issue, add_observation)
        return
    if ext == ".ps1" or basename.endswith(".ps1"):
        _review_powershell_code(path, text, add_issue, add_observation)


def build_skill_security_review(zip_path: str, max_files_to_scan: int = 80, max_file_bytes: int = 65536) -> dict:
    issues = []
    observations = []
    issue_seen = set()
    observation_seen = set()
    files = []
    executable_files = []
    hidden_files = []
    manifest_files = []
    top_compression_ratio = 0.0
    total_uncompressed = 0

    def add_issue(severity: str, risk_type: str, title: str, detail: str, file_path: str = "") -> None:
        key = (severity, risk_type, title, file_path.strip().lower())
        if key in issue_seen:
            return
        issue_seen.add(key)
        issues.append(
            {
                "severity": severity,
                "type": risk_type,
                "title": title,
                "detail": detail,
                "file": file_path,
            }
        )

    def add_observation(obs_type: str, title: str, detail: str, file_path: str = "") -> None:
        key = (obs_type, title, file_path.strip().lower())
        if key in observation_seen:
            return
        observation_seen.add(key)
        observations.append(
            {
                "type": obs_type,
                "title": title,
                "detail": detail,
                "file": file_path,
            }
        )

    def review_level_weight(level: str) -> int:
        return {"high": 40, "medium": 16, "low": 6}.get((level or "").strip().lower(), 0)

    def combine_levels(levels) -> str:
        cleaned = [(lvl or "").strip().lower() for lvl in levels if (lvl or "").strip()]
        if "high" in cleaned:
            return "high"
        if "medium" in cleaned:
            return "medium"
        return "low"

    def is_probably_text_file(path: str) -> bool:
        basename = os.path.basename(path).lower()
        if basename.startswith("readme"):
            return False
        if basename in _REVIEW_EXECUTABLE_NAMES or basename in _REVIEW_MANIFEST_NAMES:
            return True
        ext = os.path.splitext(basename)[1].lower()
        return ext in _REVIEW_TEXT_EXTENSIONS

    def scan_priority(path: str):
        basename = os.path.basename(path).lower()
        if basename == "skill.md":
            return (0, path.count("/"), len(path))
        if basename in _REVIEW_MANIFEST_NAMES:
            return (1, path.count("/"), len(path))
        if os.path.splitext(basename)[1].lower() in _REVIEW_EXECUTABLE_EXTENSIONS:
            return (2, path.count("/"), len(path))
        return (3, path.count("/"), len(path))

    try:
        with zipfile.ZipFile(zip_path, "r") as zipped:
            infos = [info for info in zipped.infolist() if not str(info.filename or "").replace("\\", "/").endswith("/")]
            names = []
            for info in infos:
                normalized = (info.filename or "").replace("\\", "/").strip("/")
                if not normalized:
                    continue
                names.append(normalized)
                files.append(normalized)
                total_uncompressed += max(0, int(info.file_size or 0))
                compressed = max(1, int(info.compress_size or 0))
                top_compression_ratio = max(top_compression_ratio, float(info.file_size or 0) / float(compressed))

                basename = os.path.basename(normalized).lower()
                ext = os.path.splitext(basename)[1].lower()
                if any(part.startswith(".") for part in normalized.split("/") if part not in {".", ".."}):
                    hidden_files.append(normalized)
                if basename in _REVIEW_EXECUTABLE_NAMES or ext in _REVIEW_EXECUTABLE_EXTENSIONS:
                    executable_files.append(normalized)
                if basename in _REVIEW_MANIFEST_NAMES:
                    manifest_files.append(normalized)

            _find_skill_md_name(names)
            _find_readme_name(names)

            if len(files) >= 180:
                add_observation("structure", "Large archive structure", f"The archive contains {len(files)} files, which increases manual review cost.")
            if hidden_files:
                add_observation("structure", "Detected hidden files", "The archive contains hidden files or directories. Confirm their purpose.", hidden_files[0])
            if top_compression_ratio >= 30:
                add_observation("structure", "Detected high compression ratio file", "One or more files have an unusually high compression ratio. Verify their purpose.")

            scan_candidates = [path for path in files if is_probably_text_file(path)]
            scan_candidates.sort(key=scan_priority)
            for path in scan_candidates[: max(1, int(max_files_to_scan))]:
                try:
                    with zipped.open(path) as handle:
                        raw = handle.read(max(256, int(max_file_bytes)) + 1)
                except Exception:
                    continue
                is_truncated = len(raw) > int(max_file_bytes)
                sample = raw[: max(256, int(max_file_bytes))]
                if b"\x00" in sample:
                    continue
                text = _decode_bytes(sample)
                compact = text if len(text) <= int(max_file_bytes) else text[: int(max_file_bytes)]
                for rule in _REVIEW_SUSPICIOUS_PATTERNS:
                    matched = rule["pattern"].search(compact)
                    if matched:
                        loc, detail_text = _review_locate_pattern_hit(path, compact, matched, rule["detail"])
                        if rule["type"] in {"dependency"}:
                            add_observation(rule["type"], rule["title"], detail_text, loc)
                        elif rule["type"] == "network" and "remote script execution" not in str(rule["title"]):
                            add_observation(rule["type"], rule["title"], detail_text, loc)
                        else:
                            add_issue(rule["severity"], rule["type"], rule["title"], detail_text, loc)
                _review_code_content_by_type(path, compact, add_issue, add_observation, is_truncated=is_truncated)
    except (zipfile.BadZipFile, OSError, RuntimeError) as exc:
        add_issue(
            "high",
            "structure",
            "Archive could not be reviewed",
            f"The archive could not be safely opened or scanned: {exc}",
        )

    severity_counts = Counter((r.get("severity") or "low").strip().lower() for r in issues)
    risk_score = min(100, sum(review_level_weight(r.get("severity") or "") for r in issues[:12]))
    overall_level = "low"
    if severity_counts.get("high"):
        overall_level = "high"
    elif severity_counts.get("medium") or risk_score >= 18:
        overall_level = "medium"

    structure_facts = [
        f"{len(files)} files",
        f"About {_format_size(total_uncompressed)}",
    ]
    if hidden_files:
        structure_facts.append(f"{len(hidden_files)} hidden paths")
    structure_issue_count = sum(1 for r in issues if r.get("type") == "structure")
    structure_observation_count = sum(1 for item in observations if item.get("type") == "structure")
    if structure_issue_count:
        structure_summary = "The archive structure contains issues that need close review."
    elif structure_observation_count:
        structure_summary = "The archive structure includes behaviors or traits worth confirming."
    else:
        structure_summary = "No obvious structural issues were found."

    execution_related = [r for r in issues if r.get("type") in {"execution", "persistence", "obfuscation"}]
    execution_level = combine_levels([r.get("severity") for r in execution_related])
    if execution_level == "low":
        execution_summary = "No obvious high-risk runtime execution signals were found."
    elif execution_level == "medium":
        execution_summary = "Executable script paths are present. Review them carefully before use."
    else:
        execution_summary = "High-risk execution behavior was detected."

    credential_related = [r for r in issues if r.get("type") == "credential"]
    credential_level = combine_levels([r.get("severity") for r in credential_related])
    credential_summary = "No clear sensitive credential prompts were found." if credential_level == "low" else "The archive contains sensitive credential or token-related prompts."

    network_issue_count = sum(1 for r in issues if r.get("type") == "network")
    network_observation_count = sum(1 for item in observations if item.get("type") in {"network", "dependency"})
    network_related = [r for r in issues if r.get("type") in {"network", "dependency"}]
    network_level = combine_levels([r.get("severity") for r in network_related])
    if network_issue_count:
        network_summary = "Detected network or download issues that need close review."
    elif network_observation_count:
        network_summary = "External network access or dependency installation was found. Verify the source and purpose."
    else:
        network_summary = "No obvious remote access issues were found."

    return {
        "overall_level": overall_level,
        "risk_score": int(risk_score),
        "risk_counts": {
            "high": int(severity_counts.get("high") or 0),
            "medium": int(severity_counts.get("medium") or 0),
            "low": int(severity_counts.get("low") or 0),
        },
        "issue_count": int(len(issues)),
        "observation_count": int(len(observations)),
        "archive": {
            "file_count": int(len(files)),
            "uncompressed_bytes": int(total_uncompressed),
            "uncompressed_size_text": _format_size(total_uncompressed),
            "top_compression_ratio": round(float(top_compression_ratio or 0.0), 1),
        },
        "checks": [
            {
                "id": "structure",
                "level": "medium" if structure_issue_count else "low",
                "summary": structure_summary,
                "facts": structure_facts + ([f"{structure_observation_count} structural observations"] if structure_observation_count else []),
            },
            {
                "id": "execution",
                "level": execution_level,
                "summary": execution_summary,
                "facts": [f"{len(execution_related)} execution-related signals"] if execution_related else ["No execution risk signals detected"],
            },
            {
                "id": "credential",
                "level": credential_level,
                "summary": credential_summary,
                "facts": [f"{len(credential_related)} sensitive credential signals"] if credential_related else ["No credential prompts detected"],
            },
            {
                "id": "network",
                "level": network_level if network_issue_count else "low",
                "summary": network_summary,
                "facts": ([f"{network_issue_count} network issues"] if network_issue_count else []) + ([f"{network_observation_count} network/dependency observations"] if network_observation_count else ["No remote download signals detected"]),
            },
        ],
        "highlights": {
            "executable_files": executable_files[:8],
            "hidden_files": hidden_files[:8],
            "manifest_files": manifest_files[:8],
        },
        "issues": issues[:14],
        "observations": observations[:14],
        "risks": issues[:14],
    }



