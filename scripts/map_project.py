import os
import re
import fnmatch
from pathlib import Path

# ================= sagy 项目配置 =================
PROJECT_ROOT = Path(".").resolve()
OUTPUT_FILE = ".project_map"

# 1. 强力去噪 (完全忽略)
IGNORE_PATTERNS = [
    ".git", ".idea", ".vscode", ".DS_Store", "target",
    "__pycache__", "*.pyc",
    "*.png", "*.jpg", "*.jpeg", "*.gif", "*.svg", "*.ico",
    "*.woff", "*.woff2", "*.ttf",
    "*.sqlite", "*.log",
    "*.bak", "*.bak.*",
    ".project_map",
]

# 2. 定点强制折叠 (构建产物 / 大型生成目录)
FORCE_COLLAPSE_PATHS = [
    ".gemini",              # Gemini 配置
    ".sagy",                # Sagy 本地配置
]

# 3. 智能折叠 (精确目录名匹配)
COLLAPSE_EXACT_NAMES = set()

# 4. 核心业务展开 (白名单)
EXPAND_KEYWORDS = [
    "src",          # Rust 源码
    "scripts",      # 脚本
    ".github",      # CI/CD
    "adapters",     # 适配器层
    "core",         # 核心逻辑层
    "antigravity",  # antigravity 适配器
    "workflows",    # GitHub Actions
]

# 5. 探针：如果折叠目录里藏着核心逻辑，强制展开
UNCOLLAPSE_IF_CONTAINS = [
    "src", "scripts", "config"
]

# ================= 核心逻辑 (通用) =================

def load_extra_ignores():
    patterns = []
    for fname in [".gitignore", ".mapignore"]:
        if os.path.exists(fname):
            try:
                with open(fname, 'r', encoding='utf-8') as f:
                    patterns.extend([l.strip() for l in f if l.strip() and not l.startswith('#')])
            except: pass
    return patterns

def is_ignored(path, extra_patterns):
    name = path.name
    for pattern in IGNORE_PATTERNS:
        if fnmatch.fnmatch(name, pattern): return True
    rel_path = str(path.relative_to(PROJECT_ROOT)).replace('\\', '/')
    for pattern in IGNORE_PATTERNS:
        if pattern in rel_path.split('/'): return True
    for pattern in extra_patterns:
        if fnmatch.fnmatch(rel_path, pattern) or fnmatch.fnmatch(name, pattern): return True
    return False

def should_collapse(path):
    """判断是否折叠"""
    name = path.name.lower()
    rel_path = str(path.relative_to(PROJECT_ROOT)).replace('\\', '/').lower()

    # 0. 探针逻辑
    try:
        children = [x.name.lower() for x in path.iterdir() if x.is_dir()]
        for vip in UNCOLLAPSE_IF_CONTAINS:
            if vip in children: return False
    except: pass

    # 1. 强制折叠
    for blocked in FORCE_COLLAPSE_PATHS:
        if blocked in rel_path: return True

    # 2. 白名单 (核心业务)
    for key in EXPAND_KEYWORDS:
        if key in name: return False

    # 3. 黑名单 (精确匹配)
    if name in COLLAPSE_EXACT_NAMES: return True

    return False

# 项目关注的文件类型
TRACKED_EXTENSIONS = {
    '.rs',                                  # Rust 源码
    '.toml',                                # Cargo 配置
    '.lock',                                # 锁文件 (Cargo.lock)
    '.py',                                  # 脚本
    '.sh', '.bash', '.zsh',                 # Shell 脚本
    '.ps1',                                 # PowerShell
    '.yml', '.yaml',                        # CI/CD 配置
    '.md',                                  # 文档
    '.patch',                               # 补丁文件
    '.json',                                # 配置
    '.txt',                                 # 文本
}

def generate_tree(dir_path, prefix="", extra_patterns=None):
    lines = []
    try:
        items = sorted(list(dir_path.iterdir()), key=lambda x: (not x.is_dir(), x.name.lower()))
    except PermissionError: return lines

    visible_items = [i for i in items if not is_ignored(i, extra_patterns)]

    valid_children = []
    for item in visible_items:
        if item.is_dir():
            is_collapsed = should_collapse(item)
            sub_count = 0
            if is_collapsed:
                sub_count = sum(1 for _ in item.glob('**/*') if _.is_file())
                if sub_count > 0:
                    valid_children.append((item, item.name, True, sub_count, []))
            else:
                child_lines = generate_tree(item, prefix + "    ", extra_patterns)
                if child_lines or any(x.is_file() for x in item.iterdir()):
                     valid_children.append((item, item.name, False, 0, child_lines))
        else:
             if item.suffix in TRACKED_EXTENSIONS:
                valid_children.append((item, item.name, False, 0, []))

    count = len(valid_children)
    for i, (original_item, display_name, is_collapsed, sub_count, child_lines) in enumerate(valid_children):
        is_last = (i == count - 1)
        connector = "-- " if is_last else "|-- "

        if original_item.is_dir():
            if is_collapsed:
                lines.append(f"{prefix}{connector}[D] {display_name}/  [collapsed: {sub_count} files]")
            else:
                lines.append(f"{prefix}{connector}[D] {display_name}/")
                extension = "    " if is_last else "|   "
                lines.extend(generate_tree(original_item, prefix + extension, extra_patterns))
        else:
             lines.append(f"{prefix}{connector}[F] {display_name}")

    return lines


def extract_cargo_summary():
    """从 Cargo.toml 提取项目摘要"""
    cargo_path = PROJECT_ROOT / "Cargo.toml"
    if not cargo_path.exists():
        return ["(Cargo.toml not found)"]

    try:
        text = cargo_path.read_text(encoding='utf-8')
    except Exception:
        return ["(Cargo.toml read error)"]

    lines = []

    # 解析 [package]
    pkg_match = re.search(r'\[package\](.*?)(?=\n\[|\Z)', text, re.DOTALL)
    if pkg_match:
        pkg_block = pkg_match.group(1)
        for key in ["name", "version", "edition", "description"]:
            m = re.search(rf'^{key}\s*=\s*"(.+?)"', pkg_block, re.MULTILINE)
            if m:
                lines.append(f"- {key}: {m.group(1)}")

    # 解析 [dependencies]
    dep_match = re.search(r'\[dependencies\](.*?)(?=\n\[|\Z)', text, re.DOTALL)
    if dep_match:
        dep_block = dep_match.group(1)
        deps = []
        for dep_line in dep_block.strip().split('\n'):
            dep_line = dep_line.strip()
            if not dep_line:
                continue
            dep_name = dep_line.split('=')[0].strip()
            if dep_name:
                deps.append(dep_name)
        if deps:
            lines.append(f"- dependencies ({len(deps)}): {', '.join(deps)}")

    return lines


def extract_module_summary():
    """扫描 src/ 提取 Rust 模块结构摘要"""
    src_dir = PROJECT_ROOT / "src"
    if not src_dir.is_dir():
        return ["(src/ not found)"]

    lines = []
    rs_files = sorted(src_dir.rglob("*.rs"))

    modules = {}
    for f in rs_files:
        rel = f.relative_to(src_dir)
        parts = list(rel.parts)

        if len(parts) == 1:
            name = parts[0].replace('.rs', '')
            modules.setdefault("(root)", []).append(name)
        else:
            mod_path = "::".join(parts[:-1])
            file_name = parts[-1].replace('.rs', '')
            modules.setdefault(mod_path, []).append(file_name)

    for mod_path in sorted(modules.keys()):
        files = modules[mod_path]
        if mod_path == "(root)":
            lines.append(f"- crate root: {', '.join(files)}")
        else:
            lines.append(f"- {mod_path}: {', '.join(files)}")

    return lines


def main():
    print("[map] Generating sagy project structure map...")
    extra_patterns = load_extra_ignores()
    tree_lines = generate_tree(PROJECT_ROOT, extra_patterns=extra_patterns)

    cargo_lines = extract_cargo_summary()
    module_lines = extract_module_summary()

    content = [
        "# sagy Project Map",
        f"> Generated: {os.popen('date').read().strip()}",
        "> Strategy: Source Focused (src expanded, build outputs omitted)",
        "",
        "## Package",
        "",
    ] + cargo_lines + [
        "",
        "## Rust Modules",
        "",
    ] + module_lines + [
        "",
        "## Directory Structure",
        "```text"
    ] + tree_lines + ["```"]

    with open(OUTPUT_FILE, "w", encoding="utf-8") as f:
        f.write("\n".join(content))
    print(f"[map] Done: {OUTPUT_FILE} ({len(content)} lines)")

if __name__ == "__main__":
    main()
