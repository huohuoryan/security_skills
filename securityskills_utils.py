import os


def _decode_bytes(data: bytes) -> str:
    for encoding in ("utf-8", "utf-8-sig", "gb18030", "gbk", "big5"):
        try:
            return data.decode(encoding)
        except UnicodeDecodeError:
            continue
    return data.decode("latin-1", errors="replace")


def _find_skill_md_name(names) -> str:
    for name in names or []:
        if os.path.basename(str(name or "")).lower() == "skill.md":
            return str(name)
    return ""


def _find_readme_name(names) -> str:
    for name in names or []:
        basename = os.path.basename(str(name or "")).lower()
        if basename.startswith("readme"):
            return str(name)
    return ""


def _format_size(num_bytes: int) -> str:
    size = float(max(0, int(num_bytes or 0)))
    units = ["B", "KB", "MB", "GB", "TB"]
    for unit in units:
        if size < 1024.0 or unit == units[-1]:
            if unit == "B":
                return f"{int(size)} {unit}"
            return f"{size:.1f} {unit}"
        size /= 1024.0
