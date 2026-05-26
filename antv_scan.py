"""AntV npm 投毒事件 (Mini Shai-Hulud, 2026-05-19) 本地中招检测脚本.

用法:
    python antv_scan.py                       # 扫描当前目录
    python antv_scan.py D:\\projects          # 扫描指定目录
    python antv_scan.py D:\\projects --deep   # 同时对受影响包做 C2 字符串扫描 (慢)
    python antv_scan.py . --include-global    # 顺带扫描全局 npm 安装目录
    python antv_scan.py . --json out.json     # 输出 JSON 报告

只读操作, 不会修改或删除任何文件.
"""

from __future__ import annotations

import argparse
import json
import os
import re
import sys
from datetime import datetime, timezone
from pathlib import Path

# 攻击窗口起点 (UTC, 2026-05-19)
ATTACK_START_TS = datetime(2026, 5, 19, tzinfo=timezone.utc).timestamp()

# 已确认受影响的 npm 包 (来源: Snyk / Socket / Microsoft / StepSecurity 联合披露)
AFFECTED_PACKAGES = {
    # @antv 命名空间
    "@antv/g", "@antv/g2", "@antv/g6", "@antv/x6", "@antv/l7",
    "@antv/s2", "@antv/f2", "@antv/g2plot", "@antv/graphin", "@antv/data-set",
    # 同维护者账号下其他被波及的包
    "echarts-for-react", "timeago.js", "size-sensor", "canvas-nest.js",
}

# 强 IoC: 攻击者 C2 域名
C2_PATTERN = re.compile(rb"t\.m-kosche\.com", re.IGNORECASE)

# 弱 IoC: 异常 postinstall 脚本特征
SUSPICIOUS_SCRIPT_PATTERNS = [
    re.compile(r"curl\s+.+\|\s*(sh|bash|node|python)", re.IGNORECASE),
    re.compile(r"eval\s*\(\s*Buffer\.from\s*\(", re.IGNORECASE),
    re.compile(r"child_process.*exec.*https?://", re.IGNORECASE),
    re.compile(r"require\(['\"]https?://", re.IGNORECASE),
]

SEVERITY_RANK = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3, "INFO": 4}

# 跳过的大文件阈值: 50 MB
MAX_SCAN_BYTES = 50 * 1024 * 1024


def find_node_modules(root: Path):
    """递归查找所有 node_modules 目录, 不进入 node_modules 内部继续搜."""
    for dirpath, dirnames, _ in os.walk(root, onerror=lambda e: None):
        if "node_modules" in dirnames:
            yield Path(dirpath) / "node_modules"
            dirnames[:] = [d for d in dirnames if d != "node_modules"]


def iter_packages(node_modules: Path):
    """枚举 node_modules 下的顶层包, yield (包名, 路径)."""
    if not node_modules.is_dir():
        return
    try:
        entries = list(node_modules.iterdir())
    except (OSError, PermissionError):
        return
    for entry in entries:
        if entry.name.startswith(".") or not entry.is_dir():
            continue
        if entry.name.startswith("@"):
            try:
                for sub in entry.iterdir():
                    if sub.is_dir():
                        yield f"{entry.name}/{sub.name}", sub
            except (OSError, PermissionError):
                continue
        else:
            yield entry.name, entry


def scan_lockfile_for_affected(lockfile: Path):
    """从 lockfile 中提取受影响包及其版本; yield (包名, 版本, 行号)."""
    try:
        content = lockfile.read_text(encoding="utf-8", errors="ignore")
    except (OSError, PermissionError):
        return

    name = lockfile.name
    if name == "package-lock.json":
        try:
            data = json.loads(content)
        except json.JSONDecodeError:
            return
        # npm v7+ 用 packages, v6 用 dependencies
        packages = data.get("packages") or {}
        for key, meta in packages.items():
            # key 形如 "node_modules/@antv/g2"
            for affected in AFFECTED_PACKAGES:
                if key.endswith(f"node_modules/{affected}"):
                    yield affected, meta.get("version", "?"), None
        deps = data.get("dependencies") or {}
        for pkg_name, meta in deps.items():
            if pkg_name in AFFECTED_PACKAGES:
                yield pkg_name, meta.get("version", "?"), None
    else:
        # pnpm-lock.yaml / yarn.lock - 走文本匹配
        for affected in AFFECTED_PACKAGES:
            # 转义 @ 和 / 用于正则
            escaped = re.escape(affected)
            pat = re.compile(rf"(?:^|[\s/'\"]){escaped}[@:]([\d.\w\-+]+)", re.MULTILINE)
            for m in pat.finditer(content):
                yield affected, m.group(1), None


def check_package(name: str, path: Path, deep: bool):
    """返回 [(severity, message), ...] 列表."""
    issues = []
    is_affected = name in AFFECTED_PACKAGES

    pkg_json = path / "package.json"
    version = "?"
    scripts = {}
    if pkg_json.is_file():
        try:
            data = json.loads(pkg_json.read_text(encoding="utf-8", errors="ignore"))
            version = data.get("version", "?")
            scripts = data.get("scripts", {}) or {}
        except (json.JSONDecodeError, OSError):
            pass

    # 1. 受影响包名匹配
    if is_affected:
        issues.append(("HIGH", f"包名命中 AntV 投毒受影响列表 (version={version})"))

    # 2. 安装时间检查 (只对受影响包检查, 否则噪音太大)
    if is_affected:
        try:
            mtime = pkg_json.stat().st_mtime if pkg_json.exists() else path.stat().st_mtime
            if mtime >= ATTACK_START_TS:
                ts = datetime.fromtimestamp(mtime, tz=timezone.utc).isoformat()
                issues.append(("CRITICAL", f"package.json 修改时间在攻击窗口之后: {ts} UTC"))
            else:
                ts = datetime.fromtimestamp(mtime, tz=timezone.utc).isoformat()
                issues.append(("INFO", f"安装时间早于攻击窗口 ({ts} UTC), 大概率干净"))
        except OSError:
            pass

    # 3. 可疑生命周期脚本 (所有包都检查)
    for hook in ("preinstall", "install", "postinstall"):
        script = scripts.get(hook, "")
        if not isinstance(script, str):
            continue
        for pat in SUSPICIOUS_SCRIPT_PATTERNS:
            if pat.search(script):
                snippet = script[:120].replace("\n", " ")
                issues.append(("MEDIUM", f"{hook} 钩子可疑: {snippet}"))
                break

    # 4. C2 域名扫描 (只对受影响包做, 或 --deep 模式全扫)
    if is_affected or deep:
        for js_file in path.rglob("*.js"):
            try:
                size = js_file.stat().st_size
                if size > MAX_SCAN_BYTES:
                    continue
                with js_file.open("rb") as f:
                    content = f.read()
                if C2_PATTERN.search(content):
                    rel = js_file.relative_to(path)
                    issues.append(("CRITICAL", f"在 {rel} 中发现 C2 域名 t.m-kosche.com"))
            except (OSError, PermissionError):
                continue

    return issues


def top_severity(issues):
    return min((s for s, _ in issues), key=lambda s: SEVERITY_RANK.get(s, 9))


def main():
    parser = argparse.ArgumentParser(
        description="AntV npm 投毒事件 (Mini Shai-Hulud, 2026-05-19) 本地检测",
    )
    parser.add_argument("path", nargs="?", default=".", help="扫描根目录, 默认当前目录")
    parser.add_argument("--deep", action="store_true", help="对所有包做 C2 字符串扫描 (慢)")
    parser.add_argument("--include-global", action="store_true", help="同时扫描全局 npm 安装目录")
    parser.add_argument("--json", metavar="FILE", help="将结果写入 JSON 文件")
    args = parser.parse_args()

    root = Path(args.path).resolve()
    if not root.exists():
        print(f"[错误] 路径不存在: {root}", file=sys.stderr)
        return 2

    scan_roots = [root]
    if args.include_global:
        candidates = []
        if sys.platform == "win32":
            appdata = os.environ.get("APPDATA")
            if appdata:
                candidates.append(Path(appdata) / "npm")
        else:
            candidates.append(Path("/usr/local/lib"))
            candidates.append(Path.home() / ".npm-global" / "lib")
        for c in candidates:
            if c.exists() and c not in scan_roots:
                scan_roots.append(c)

    print("=" * 72)
    print(" AntV npm 投毒检测  (Mini Shai-Hulud / 2026-05-19)")
    print("=" * 72)
    for r in scan_roots:
        print(f"  扫描根目录: {r}")
    print(f"  攻击窗口起点: {datetime.fromtimestamp(ATTACK_START_TS, tz=timezone.utc).isoformat()} UTC")
    print(f"  深度扫描: {'是' if args.deep else '否 (仅扫描受影响包)'}")
    print("-" * 72)

    findings = []
    lockfile_hits = []
    total_pkgs = 0
    total_nm = 0

    for scan_root in scan_roots:
        # 4.1 扫描 node_modules
        for nm in find_node_modules(scan_root):
            total_nm += 1
            for name, pkg_path in iter_packages(nm):
                total_pkgs += 1
                issues = check_package(name, pkg_path, args.deep)
                # 只记录有 MEDIUM 以上严重度的
                if any(SEVERITY_RANK.get(s, 9) <= 2 for s, _ in issues):
                    findings.append({
                        "name": name,
                        "path": str(pkg_path),
                        "issues": issues,
                    })

        # 4.2 扫描 lockfile (即使没装 node_modules 也要检查)
        for lock_name in ("package-lock.json", "pnpm-lock.yaml", "yarn.lock"):
            for lockfile in scan_root.rglob(lock_name):
                # 跳过 node_modules 内的 lockfile
                if "node_modules" in lockfile.parts:
                    continue
                for affected, version, _ in scan_lockfile_for_affected(lockfile):
                    lockfile_hits.append({
                        "lockfile": str(lockfile),
                        "package": affected,
                        "version": version,
                    })

    print(f"  已扫描 node_modules 数: {total_nm}")
    print(f"  已扫描包数: {total_pkgs}")
    print(f"  问题包数: {len(findings)}")
    print(f"  lockfile 命中数: {len(lockfile_hits)}")
    print("=" * 72)

    if not findings and not lockfile_hits:
        print("\n[OK] 未发现受影响的包或可疑特征.")
        if args.json:
            Path(args.json).write_text(
                json.dumps({"clean": True, "findings": [], "lockfile_hits": []}, ensure_ascii=False, indent=2),
                encoding="utf-8",
            )
        return 0

    # 按严重度排序
    findings.sort(key=lambda f: SEVERITY_RANK.get(top_severity(f["issues"]), 9))

    if findings:
        print("\n[!] node_modules 中发现的问题包:\n")
        for f in findings:
            sev = top_severity(f["issues"])
            print(f"  [{sev}] {f['name']}")
            print(f"        path: {f['path']}")
            for s, msg in f["issues"]:
                print(f"        - [{s}] {msg}")
            print()

    if lockfile_hits:
        print("\n[!] lockfile 中声明的受影响包:\n")
        for h in lockfile_hits:
            print(f"  - {h['package']}@{h['version']}")
            print(f"      in: {h['lockfile']}")
        print()

    print("=" * 72)
    print(" 后续动作建议")
    print("=" * 72)
    print("""
  1. 立刻轮换以下凭据 (假设可能已泄露):
     - AWS / GCP / Azure access key
     - GitHub Personal Access Token, npm token
     - .env 中所有 API key, kubeconfig, Vault token
  2. 删除 node_modules 和所有 lockfile, 重装到 5/19 之前的已知干净版本:
     Remove-Item -Recurse -Force node_modules, package-lock.json, pnpm-lock.yaml, yarn.lock
  3. 在 package.json 加 "overrides" 锁死传递依赖, 避免再被拉回坏版本.
  4. 检查 CI/CD (尤其 GitHub Actions) 最近运行日志, 看是否有异常网络出站.
  5. 复测: 重新跑本脚本, 应输出 [OK].
""")

    # 写 JSON
    if args.json:
        Path(args.json).write_text(
            json.dumps({
                "clean": False,
                "scan_roots": [str(r) for r in scan_roots],
                "findings": findings,
                "lockfile_hits": lockfile_hits,
            }, ensure_ascii=False, indent=2),
            encoding="utf-8",
        )
        print(f"[i] JSON 报告已写入: {args.json}")

    # 退出码: 有 HIGH/CRITICAL 返回 1
    has_high = any(
        SEVERITY_RANK.get(top_severity(f["issues"]), 9) <= 1
        for f in findings
    ) or bool(lockfile_hits)
    return 1 if has_high else 0


if __name__ == "__main__":
    sys.exit(main())
