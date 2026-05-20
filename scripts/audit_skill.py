#!/usr/bin/env python3
"""
Claude Code Skill Security Auditor v1.1.0

Standardized security audit tool for Claude Code Skill repositories.
Scans 10 dimensions based on OWASP LLM Top 10, SLSA, Google SAIF, MCP-Scan.

Usage:
    python audit_skill.py /path/to/skill/           # Single skill
    python audit_skill.py /path/to/marketplace/ --all  # All skills
    python audit_skill.py /path/ --all --json out.json  # JSON output
    python audit_skill.py /path/ --all --html out.html  # HTML report
    python audit_skill.py /path/ --all --min-level C    # Filter by level

Requires: PyYAML>=6.0 (for configurable rules support)
"""

import argparse
import html as html_module
import json
import os
import re
import sys
from dataclasses import dataclass, field, asdict
from datetime import datetime, timezone
from pathlib import Path
from string import Template
from typing import List, Dict, Optional, Tuple

try:
    import yaml as _yaml
    _YAML_AVAILABLE = True
except ImportError:
    _YAML_AVAILABLE = False

# ── Configurable Rules Loader ─────────────────────────────────────────────────

_RULES_PATH = Path(__file__).parent / "rules.yaml"


def _load_configurable_rules(rules_path: Optional[Path] = None) -> Dict:
    """Load user-configurable rules from rules.yaml.

    Returns an empty dict if the file doesn't exist or PyYAML is unavailable.
    Each dimension key maps to a list of rule dicts with keys:
      id, pattern, description, severity, enabled, whitelist
    """
    path = rules_path or _RULES_PATH
    if not _YAML_AVAILABLE:
        return {}
    if not path or not path.exists():
        return {}
    try:
        with open(path, encoding="utf-8") as f:
            data = _yaml.safe_load(f)
        return data or {}
    except Exception:
        return {}

__version__ = "1.1.0"

# ── ANSI Colors ──────────────────────────────────────────────────────────────

class C:
    """ANSI color codes for terminal output."""
    RESET   = "\033[0m"
    BOLD    = "\033[1m"
    DIM     = "\033[2m"
    RED     = "\033[31m"
    GREEN   = "\033[32m"
    YELLOW  = "\033[33m"
    BLUE    = "\033[34m"
    MAGENTA = "\033[35m"
    CYAN    = "\033[36m"
    WHITE   = "\033[37m"
    GRAY    = "\033[90m"
    BG_RED  = "\033[41m"
    BG_GREEN = "\033[42m"
    BG_YELLOW = "\033[43m"

    @staticmethod
    def strip(text: str) -> str:
        return re.sub(r'\033\[[0-9;]*m', '', text)

# Disable colors if not a TTY
if not sys.stdout.isatty():
    for attr in dir(C):
        if attr.isupper() and not attr.startswith('_'):
            setattr(C, attr, '')

# ── Data Classes ─────────────────────────────────────────────────────────────

@dataclass
class Finding:
    dimension: str
    severity: str       # CRITICAL / HIGH / MEDIUM / LOW / INFO
    file_path: str
    line_number: int    # 0 = file-level
    pattern: str
    description: str
    reference: str
    remediation_zh: str = ""
    remediation_en: str = ""

@dataclass
class TokenEstimate:
    l1_skill_md: int = 0        # SKILL.md direct injection
    l2_eager: int = 0           # Mandatory/eager-loaded references
    l2_lazy: int = 0            # On-demand/lazy references
    l3_total: int = 0           # All files in skill directory
    l1_chars: int = 0
    l2_eager_chars: int = 0
    l2_lazy_chars: int = 0
    l3_chars: int = 0
    eager_files: List[str] = field(default_factory=list)
    lazy_files: List[str] = field(default_factory=list)

@dataclass
class AuditReport:
    skill_name: str
    skill_path: str
    file_inventory: Dict[str, int] = field(default_factory=dict)
    risk_score: int = 0
    risk_level: str = "A"
    findings: List[Finding] = field(default_factory=list)
    dimension_summary: Dict[str, int] = field(default_factory=dict)
    token_estimate: TokenEstimate = field(default_factory=TokenEstimate)
    cost_estimates: list = field(default_factory=list)

# ── Severity Scoring ─────────────────────────────────────────────────────────

SEVERITY_SCORES = {
    "CRITICAL": 25,
    "HIGH":     10,
    "MEDIUM":    5,
    "LOW":       2,
    "INFO":      0,
}

SEVERITY_ORDER = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3, "INFO": 4}

def compute_risk(findings: List[Finding]) -> Tuple[int, str]:
    """Compute risk score and level from findings, with deduplication.

    Deduplicates findings that match the same file+line to avoid double-counting
    similar patterns (e.g., 'rm -rf /' and 'rm -rf' on the same line).
    """
    # Deduplicate by (file_path, line_number) - keep highest severity
    deduped = {}
    for f in findings:
        key = (f.file_path, f.line_number)
        if key not in deduped:
            deduped[key] = f
        else:
            # Keep the higher severity finding
            existing = deduped[key]
            if SEVERITY_ORDER.get(f.severity, 99) < SEVERITY_ORDER.get(existing.severity, 99):
                deduped[key] = f

    unique_findings = list(deduped.values())
    score = sum(SEVERITY_SCORES.get(f.severity, 0) for f in unique_findings)
    score = min(score, 100)
    if score >= 70:
        level = "F"
    elif score >= 50:
        level = "D"
    elif score >= 30:
        level = "C"
    elif score >= 10:
        level = "B"
    else:
        level = "A"
    return score, level

LEVEL_ORDER = {"F": 0, "D": 1, "C": 2, "B": 3, "A": 4}

# ── Remediation Mappings ────────────────────────────────────────────────────

# Per-finding remediation: matched by substring in finding.description (case-insensitive)
# Each value is (zh, en) tuple
REMEDIATIONS = {
    # Prompt Injection
    "ignore previous instructions": ("移除该指令文本，使用结构化 prompt 模板避免拼接用户内容", "Remove the directive; use structured prompt templates instead of concatenating user content"),
    "role override": ("移除角色覆盖指令，使用 system prompt 中的明确角色定义", "Remove role override; use explicit role definitions in the system prompt"),
    "disregard directive": ("移除绕过指令，使用分层 prompt 架构隔离系统与用户指令", "Remove bypass directive; use layered prompt architecture to isolate system and user instructions"),
    "override system prompt": ("移除覆盖指令，确保 system prompt 不可被用户输入修改", "Remove override directive; ensure the system prompt cannot be modified by user input"),
    "jailbreak": ("移除 jailbreak 关键词，审查 prompt 是否含有越狱诱导内容", "Remove jailbreak keywords; review prompts for jailbreak-inducing content"),
    "role-play induction": ("移除角色扮演诱导语句，使用明确的角色边界定义", "Remove role-play induction phrases; use explicit role boundary definitions"),
    "dan-style jailbreak": ("移除 DAN 类越狱 prompt，加强 system prompt 的行为约束", "Remove DAN-style jailbreak prompt; strengthen behavioral constraints in system prompt"),
    "behavioral override": ("移除行为覆盖指令，使用不可变的 system prompt 约束行为", "Remove behavioral override; use immutable system prompt to constrain behavior"),
    "hidden instruction detected in html comment": ("移除 HTML 注释中的隐藏指令，审查所有注释内容", "Remove hidden instructions from HTML comments; review all comment content"),
    "zero-width character": ("移除零宽字符，使用文本净化函数过滤不可见 Unicode 字符", "Remove zero-width characters; use text sanitization to filter invisible Unicode characters"),
    "base64-like string": ("审查 base64 编码内容，解码验证是否包含注入 payload", "Review base64-encoded content; decode and verify it does not contain injected payloads"),
    # Permission Escalation
    "disables sandbox": ("移除 dangerouslyDisableSandbox，在沙箱内运行所有操作", "Remove dangerouslyDisableSandbox; run all operations inside the sandbox"),
    "skips permission checks": ("移除 --dangerously-skip-permissions，保留权限校验机制", "Remove --dangerously-skip-permissions; keep permission checks enabled"),
    "sudo usage": ("移除 sudo，改用用户态权限或 Linux capabilities (cap_net_bind_service 等)", "Remove sudo; use user-level permissions or Linux capabilities instead"),
    "chmod 777": ("改用最小权限 chmod 755 或 644，避免 world-writable", "Use minimal permissions (chmod 755 or 644); avoid world-writable"),
    "chown root": ("避免修改文件属主为 root，使用普通用户权限运行", "Avoid changing ownership to root; run with normal user privileges"),
    "modifying claude settings": ("不应直接修改 .claude/settings.json，使用 CLI 配置接口", "Do not modify .claude/settings.json directly; use the CLI configuration interface"),
    "references allowedtools": ("明确声明需要的工具列表，避免运行时动态修改 allowedTools", "Explicitly declare required tools; avoid dynamically modifying allowedTools at runtime"),
    "bypasses verification": ("移除 --no-verify，保留 pre-commit/pre-push hooks 校验", "Remove --no-verify; keep pre-commit/pre-push hook checks enabled"),
    "overly permissive chmod": ("改用最小必要权限，如 chmod 644 (文件) 或 755 (目录/脚本)", "Use least necessary permissions, e.g. chmod 644 (files) or 755 (dirs/scripts)"),
    "setuid": ("移除 setuid/setgid 位，使用 capabilities 或独立服务账户替代", "Remove setuid/setgid bits; use capabilities or dedicated service accounts instead"),
    "setgid": ("移除 setuid/setgid 位，使用 capabilities 或独立服务账户替代", "Remove setuid/setgid bits; use capabilities or dedicated service accounts instead"),
    # Data Exfiltration
    "reads .env file": ("避免在 skill 中直接读取 .env，改由宿主环境注入所需变量", "Avoid reading .env directly in skill; inject required variables from the host environment"),
    "accesses ssh directory": ("移除对 ~/.ssh/ 的访问，使用 SSH agent 或受控密钥注入", "Remove access to ~/.ssh/; use SSH agent or controlled key injection"),
    "reads /etc/passwd": ("移除对 /etc/passwd 的读取，使用 getent 或标准库 API", "Remove /etc/passwd reads; use getent or standard library APIs"),
    "reads /etc/shadow": ("移除对 /etc/shadow 的访问，这是高权限敏感文件", "Remove /etc/shadow access; this is a high-privilege sensitive file"),
    "reads aws credentials": ("使用 IAM 角色或环境变量替代直接读取 ~/.aws/credentials", "Use IAM roles or environment variables instead of reading ~/.aws/credentials"),
    "reads kubernetes config": ("使用 ServiceAccount token 或 KUBECONFIG 环境变量", "Use ServiceAccount tokens or the KUBECONFIG environment variable"),
    "reads credentials file": ("使用密钥管理服务或环境变量，不硬编码凭证路径", "Use a secrets manager or environment variables; do not hardcode credential paths"),
    "reads claude settings": ("避免读取 .claude/settings，使用官方 API 获取配置", "Avoid reading .claude/settings; use the official API to get configuration"),
    "curl post": ("审查 POST 请求目标 URL，确保数据仅发往可信端点", "Review POST request target URLs; ensure data is only sent to trusted endpoints"),
    "curl with data payload": ("审查 curl --data 请求，确认发送内容不含敏感信息", "Review curl --data requests; confirm payloads do not contain sensitive information"),
    "requests.post": ("审查 requests.post 目标 URL，添加 URL 白名单校验", "Review requests.post target URLs; add URL allowlist validation"),
    "fetch post": ("审查 fetch POST 目标，确保仅向可信域名发送数据", "Review fetch POST targets; ensure data is only sent to trusted domains"),
    "urllib outbound": ("审查 urllib 请求目标，添加 URL 白名单", "Review urllib request targets; add URL allowlist"),
    "http.client outbound": ("审查 http.client 连接目标，限制允许连接的域名", "Review http.client connection targets; restrict allowed domains"),
    "webhook url": ("审查 webhook URL 归属，确保数据不外泄到第三方", "Review webhook URL ownership; ensure data is not leaked to third parties"),
    "ngrok tunnel": ("移除 ngrok 隧道，使用受控的反向代理或 VPN", "Remove ngrok tunnel; use a controlled reverse proxy or VPN"),
    "credential exfiltration": ("隔离环境变量读取与网络请求，避免在同一上下文中操作", "Isolate environment variable reads from network requests; avoid both in the same context"),
    "data collection/analytics endpoint": ("审查数据收集端点，确认是否为必要功能并获得用户知情同意", "Review data collection endpoints; confirm necessity and obtain user consent"),
    # Destructive Operations
    "rm -rf on root": ("绝对不要使用 rm -rf /，添加路径白名单校验", "Never use rm -rf /; add path allowlist validation"),
    "rm -rf": ("添加路径白名单校验，使用 --interactive 或先 dry-run 确认", "Add path allowlist validation; use --interactive or dry-run first"),
    "git reset --hard": ("改用 git stash 保存更改，或使用 git reset --soft 保留暂存", "Use git stash to save changes, or git reset --soft to keep staging"),
    "git push --force": ("改用 git push --force-with-lease 防止覆盖他人提交", "Use git push --force-with-lease to prevent overwriting others' commits"),
    "git push -f": ("改用 git push --force-with-lease 防止覆盖他人提交", "Use git push --force-with-lease to prevent overwriting others' commits"),
    "git clean -f": ("添加确认提示，或使用 git clean -n 先预览将删除的文件", "Add confirmation prompt, or use git clean -n to preview files to be deleted"),
    "drop table": ("添加确认提示和备份机制，使用 migration 工具管理 schema 变更", "Add confirmation and backup; use migration tools to manage schema changes"),
    "delete from without where": ("添加 WHERE 条件限制删除范围，或使用事务 + 确认机制", "Add WHERE clause to limit scope, or use transactions with confirmation"),
    "truncate table": ("使用 DELETE + WHERE 替代 TRUNCATE，添加备份和确认机制", "Use DELETE + WHERE instead of TRUNCATE; add backup and confirmation"),
    "shutil.rmtree": ("添加路径白名单校验，确保目标目录在预期范围内", "Add path allowlist validation; ensure target directory is within expected scope"),
    "os.remove": ("删除前校验路径是否在预期范围内，添加确认逻辑", "Validate path is within expected scope before deletion; add confirmation"),
    "os.unlink": ("删除前校验路径是否在预期范围内，添加确认逻辑", "Validate path is within expected scope before deletion; add confirmation"),
    "disk format": ("移除磁盘格式化命令，这在 skill 中不应出现", "Remove disk format command; this should not appear in a skill"),
    "fdisk": ("移除 fdisk 命令，磁盘分区操作不应在 skill 中执行", "Remove fdisk command; disk partitioning should not be done in a skill"),
    "mkfs": ("移除 mkfs 命令，文件系统创建不应在 skill 中执行", "Remove mkfs command; filesystem creation should not be done in a skill"),
    "dd - low-level": ("添加明确的 of= 目标校验，避免误覆盖重要设备/文件", "Add explicit of= target validation; avoid overwriting critical devices/files"),
    "fork bomb": ("移除 fork bomb 代码，这是恶意或误操作", "Remove fork bomb code; this is malicious or accidental"),
    # Supply Chain
    "pipe-to-shell": ("下载脚本后先审查再执行：curl -o script.sh URL && review && bash script.sh", "Download scripts first, review, then execute: curl -o script.sh URL && review && bash script.sh"),
    "pipe-to-sudo": ("永远不要 curl | sudo，先下载审查再以最小权限执行", "Never curl | sudo; download, review, then execute with least privilege"),
    "git clone": ("锁定 clone 的 commit hash 或 tag，避免拉取未审查的代码", "Pin clone to a commit hash or tag; avoid pulling unreviewed code"),
    "pip install without version": ("使用 pip install package==x.y.z 锁定版本，或用 requirements.txt + hash", "Use pip install package==x.y.z to pin versions, or requirements.txt with hashes"),
    "npm install without version": ("使用 npm install package@x.y.z 锁定版本，或用 package-lock.json", "Use npm install package@x.y.z to pin versions, or use package-lock.json"),
    "go get": ("使用 go.sum 锁定依赖 hash，指定明确版本号", "Use go.sum to lock dependency hashes; specify explicit version numbers"),
    "dockerfile from without digest": ("改用 FROM image@sha256:... 锁定镜像摘要", "Use FROM image@sha256:... to pin image digest"),
    # Code Security
    "shell=true": ("改用 subprocess.run(cmd_list, shell=False)，参数以列表传入", "Use subprocess.run(cmd_list, shell=False); pass arguments as a list"),
    "os.system": ("改用 subprocess.run(cmd_list, shell=False)，避免 shell 注入", "Use subprocess.run(cmd_list, shell=False); avoid shell injection"),
    "os.popen": ("改用 subprocess.run(cmd_list, capture_output=True, shell=False)", "Use subprocess.run(cmd_list, capture_output=True, shell=False)"),
    "eval()": ("用 ast.literal_eval() 替代 eval()，或用 JSON/配置文件解析", "Use ast.literal_eval() instead of eval(), or parse with JSON/config files"),
    "exec()": ("避免动态执行代码，改用函数映射 (dict dispatch) 或配置驱动", "Avoid dynamic code execution; use function dispatch (dict mapping) or config-driven logic"),
    "compile()": ("避免动态编译代码字符串，使用预定义函数或模板引擎", "Avoid dynamically compiling code strings; use predefined functions or template engines"),
    "pickle.load": ("改用 json.load() 或 msgpack，避免反序列化执行任意代码", "Use json.load() or msgpack instead; avoid arbitrary code execution via deserialization"),
    "yaml.load without safeloader": ("改用 yaml.safe_load() 或 yaml.load(Loader=yaml.SafeLoader)", "Use yaml.safe_load() or yaml.load(Loader=yaml.SafeLoader)"),
    "marshal.load": ("改用 JSON 或其他安全序列化格式", "Use JSON or other safe serialization formats"),
    "sql injection": ("使用参数化查询 cursor.execute('SELECT * FROM t WHERE id=?', (id,))", "Use parameterized queries: cursor.execute('SELECT * FROM t WHERE id=?', (id,))"),
    "innerhtml": ("使用 textContent 替代 innerHTML，或用 DOMPurify 净化 HTML", "Use textContent instead of innerHTML, or sanitize with DOMPurify"),
    "dangerouslysetinnerhtml": ("使用 DOMPurify 净化 HTML 后再传入，或改用安全的渲染方式", "Sanitize HTML with DOMPurify before passing, or use safe rendering methods"),
    "path traversal": ("对路径输入进行规范化 (os.path.realpath) 并校验是否在允许的目录内", "Normalize path input (os.path.realpath) and verify it is within allowed directories"),
    # Credential Leaks
    "openai/anthropic api key": ("使用环境变量 os.environ['ANTHROPIC_API_KEY']，不硬编码密钥", "Use environment variable os.environ['ANTHROPIC_API_KEY']; do not hardcode keys"),
    "github personal access token": ("使用 GitHub App token 或环境变量，不硬编码 PAT", "Use GitHub App tokens or environment variables; do not hardcode PATs"),
    "github oauth token": ("使用 OAuth flow 动态获取 token，不在代码中存储", "Use OAuth flow to dynamically obtain tokens; do not store in code"),
    "aws access key": ("使用 IAM 角色或 AWS SSO，不硬编码 Access Key", "Use IAM roles or AWS SSO; do not hardcode Access Keys"),
    "slack bot token": ("使用环境变量存储 Slack token，不硬编码", "Store Slack tokens in environment variables; do not hardcode"),
    "slack user token": ("使用环境变量存储 Slack token，不硬编码", "Store Slack tokens in environment variables; do not hardcode"),
    "gitlab personal access token": ("使用环境变量或 CI/CD 变量注入，不硬编码", "Use environment variables or CI/CD variable injection; do not hardcode"),
    "jwt token detected": ("检查 JWT 是否为测试数据，生产 token 不应出现在代码中", "Check if JWT is test data; production tokens should not appear in code"),
    "hardcoded password": ("使用环境变量 os.environ['DB_PASSWORD'] 或密钥管理服务", "Use environment variables os.environ['DB_PASSWORD'] or a secrets manager"),
    "hardcoded secret": ("使用环境变量或密钥管理服务 (HashiCorp Vault, AWS Secrets Manager)", "Use environment variables or a secrets manager (HashiCorp Vault, AWS Secrets Manager)"),
    "private key in pem": ("使用密钥管理服务存储私钥，不在代码仓库中保存", "Store private keys in a secrets manager; do not keep them in code repositories"),
    "hardcoded email": ("使用环境变量或配置文件注入邮箱地址", "Use environment variables or config files to inject email addresses"),
    # Least Privilege
    "no allowed-tools declared": ("在 SKILL.md frontmatter 中声明 allowed-tools 列表，限制可用工具", "Declare an allowed-tools list in SKILL.md frontmatter to restrict available tools"),
    "shell access declared": ("评估是否真正需要 shell 访问，尽量使用专用工具替代", "Evaluate whether shell access is truly needed; prefer dedicated tools instead"),
    "dangerous tool combination": ("拆分为多个独立 skill，每个只申请必要的工具权限", "Split into separate skills, each requesting only the necessary tool permissions"),
    # License
    "proprietary": ("确认许可证兼容性，必要时获取商用授权", "Verify license compatibility; obtain commercial authorization if needed"),
    "all rights reserved": ("确认代码使用权限，考虑联系作者获取开源授权", "Verify usage permissions; consider contacting the author for an open-source license"),
    "copying prohibited": ("确认是否有合法使用权限，必要时寻求替代方案", "Verify legitimate usage rights; seek alternatives if necessary"),
    "non-commercial": ("确认使用场景是否符合 non-commercial 限制", "Verify the use case complies with non-commercial restrictions"),
    "kegg database": ("确认学术许可证覆盖范围，商用需单独授权", "Verify academic license scope; commercial use requires separate authorization"),
    "benchling": ("确认 Benchling API 使用条款和费用", "Review Benchling API terms of service and associated costs"),
    "bigquery": ("审查 BigQuery 数据收集范围，确认费用和数据隐私合规", "Review BigQuery data collection scope; confirm costs and data privacy compliance"),
    "snowflake": ("确认 Snowflake 使用条款和数据传输合规性", "Review Snowflake terms of service and data transfer compliance"),
    # Resource Abuse
    "while true loop": ("添加明确的退出条件和最大迭代次数限制 (如 max_iterations=1000)", "Add explicit exit conditions and max iteration limits (e.g. max_iterations=1000)"),
    "while 1 loop": ("添加明确的退出条件和最大迭代次数限制", "Add explicit exit conditions and max iteration limits"),
    "while(true) loop": ("添加 break 条件和超时机制", "Add break conditions and timeout mechanisms"),
    "for(;;) infinite loop": ("添加 break 条件和最大迭代次数", "Add break conditions and max iteration limits"),
    "very large retmax": ("降低 retmax 值，使用分页查询避免一次拉取过多数据", "Reduce retmax value; use pagination to avoid fetching too much data at once"),
    "very large limit": ("使用合理的 limit 值，配合分页逐步获取数据", "Use reasonable limit values with pagination to fetch data incrementally"),
    "sleep(0) in potential busy loop": ("增加合理的 sleep 间隔 (如 0.1s)，避免 CPU 空转", "Add reasonable sleep intervals (e.g. 0.1s); avoid CPU busy-waiting"),
    "unlimited/excessive retry": ("设置合理的 retry 上限 (如 max_retries=3) 和指数退避", "Set reasonable retry limits (e.g. max_retries=3) with exponential backoff"),
    "recursive function": ("添加递归深度限制或改用迭代实现", "Add recursion depth limits or convert to iterative implementation"),
}

# Per-dimension general remediation summary — (zh, en) tuples
DIMENSION_REMEDIATIONS = {
    "Prompt Injection": ("审查所有用户输入拼接点，使用结构化 prompt 模板，避免直接拼接用户内容到系统指令中", "Review all user input concatenation points; use structured prompt templates; avoid concatenating user content into system instructions"),
    "Permission Escalation": ("遵循最小权限原则，移除 sudo/chmod 777，使用用户态操作和 Linux capabilities", "Follow the principle of least privilege; remove sudo/chmod 777; use user-level operations and Linux capabilities"),
    "Data Exfiltration": ("审查所有外部 URL 和 API 调用，确保数据只发往可信端点，敏感操作需用户确认", "Review all external URLs and API calls; ensure data is only sent to trusted endpoints; require user confirmation for sensitive operations"),
    "Destructive Operations": ("添加路径白名单、确认提示、dry-run 模式，破坏性操作前先备份", "Add path allowlists, confirmation prompts, and dry-run mode; back up before destructive operations"),
    "Supply Chain": ("锁定依赖版本，使用 hash 校验，下载后先审查再执行，避免 pipe-to-shell", "Pin dependency versions; use hash verification; download and review before executing; avoid pipe-to-shell"),
    "Code Security": ("避免 eval/exec/shell=True，使用参数化查询，对外部输入做校验和净化", "Avoid eval/exec/shell=True; use parameterized queries; validate and sanitize external input"),
    "Credential Leaks": ("使用环境变量或密钥管理服务存储凭证，不在代码中硬编码任何密钥/密码", "Use environment variables or secrets managers to store credentials; never hardcode keys/passwords in code"),
    "Least Privilege": ("在 SKILL.md 中声明最小工具集，避免 Bash(*) 通配符权限，拆分高权限操作", "Declare minimal toolsets in SKILL.md; avoid Bash(*) wildcard permissions; split high-privilege operations"),
    "License Compliance": ("检查依赖许可证兼容性，标注商业服务使用，确保合规使用", "Check dependency license compatibility; annotate commercial service usage; ensure compliant use"),
    "Resource Abuse": ("添加循环退出条件、请求限流、合理的 retry 上限，避免无限消耗资源", "Add loop exit conditions, request throttling, and reasonable retry limits; avoid unbounded resource consumption"),
}

# ── HTML i18n Labels ────────────────────────────────────────────────────────

I18N_LABELS = {
    "report_title":     ("安全审计报告", "Security Audit Report"),
    "report_subtitle":  ("基于 10 个维度的标准化 Skill 安全分析", "Standardized skill security analysis across 10 dimensions"),
    "level_a":          ("A · 安全", "A · Safe"),
    "level_b":          ("B · 可接受", "B · Acceptable"),
    "level_c":          ("C · 警告", "C · Warning"),
    "level_d":          ("D · 不安全", "D · Unsafe"),
    "level_f":          ("F · 危险", "F · Dangerous"),
    "risk_dist":        ("风险分布", "Risk Distribution"),
    "token_title":      ("预估 Token 消耗", "Estimated Token Consumption"),
    "tok_total_l1l2":   ("L1+L2 合计", "Total L1+L2"),
    "tok_total_l3":     ("L3 合计 (最大值)", "Total L3 (max)"),
    "tok_avg":          ("平均 L1+L2 / 技能", "Avg L1+L2 / skill"),
    "tok_median":       ("中位数 L1+L2", "Median L1+L2"),
    "tok_max":          ("单技能最大值", "Max single skill"),
    "tok_top5_title":   ("Token 消耗 Top 5 (L1+L2)", "Top 5 Token Consumers (L1+L2)"),
    "cost_title":       ("预估每次调用成本 (输入 Token)", "Estimated Cost per Invocation (Input Tokens)"),
    "cost_note":        ("以上为<b>单轮输入成本</b>估算（上下文加载）。Skill 渐进加载：先注入 L1 (SKILL.md)，再通过工具调用读取 L2 文件。每次后续 API 调用会重发所有先前上下文，因此多轮实际成本高于单轮估算。不包含输出 Token 成本。",
                         "Estimates show <b>single-turn input cost</b> only (context loading). Skills load progressively: L1 (SKILL.md) is injected first, then L2 files are read via tool calls across multiple turns. Each subsequent API call re-sends all prior context, so the actual multi-turn total is higher than a single-turn estimate. Output token costs vary by usage and are not included."),
    "top10_title":      ("风险最高 Top 10", "Top 10 Highest Risk"),
    "all_skills":       ("所有技能", "All Skills"),
    "search_placeholder": ("搜索技能…", "Search skills..."),
    "tab_all":          ("全部", "All"),
    "no_findings":      ("未发现问题", "No findings detected"),
    "col_severity":     ("严重度", "Severity"),
    "col_dimension":    ("维度", "Dimension"),
    "col_description":  ("描述", "Description"),
    "col_location":     ("位置", "Location"),
    "cost_model":       ("模型", "Model"),
    "cost_min":         ("最小 (L1+Eager)", "Min (L1+Eager)"),
    "cost_typical":     ("典型 (L1+L2)", "Typical (L1+L2)"),
    "cost_max":         ("最大 (L3)", "Max (L3)"),
    "cost_avg_label":   ("平均每技能 (L1+L2)", "avg per skill (L1+L2)"),
    "cost_total_label": ("全部 {n} 技能合计", "all {n} skills total"),
    "cost_detail_note": ("仅单轮输入成本。多轮对话累积上下文——每次后续 API 调用重发所有先前消息，因此 N 轮实际总成本高于 N × 单轮成本。",
                         "Single-turn input cost only. Multi-turn conversations accumulate context — each subsequent API call re-sends all previous messages, so actual total cost across N turns is higher than N × single-turn cost."),
    "skills_label":     ("技能", "skills"),
    "tokens_label":     ("tokens", "tokens"),
}

# Dimension names: (zh_name, en_name) — used for HTML i18n
DIMENSION_NAMES_ZH = {
    "Prompt Injection": "Prompt 注入检测",
    "Permission Escalation": "权限提升分析",
    "Data Exfiltration": "数据外泄风险",
    "Destructive Operations": "破坏性操作",
    "Supply Chain": "供应链/来源验证",
    "Code Security": "代码安全(静态分析)",
    "Credential Leaks": "凭证与密钥泄露",
    "Least Privilege": "权限最小化",
    "License Compliance": "许可证合规",
    "Resource Abuse": "资源滥用/无限消耗",
}

def _match_remediation(description: str) -> Tuple[str, str]:
    """Match a finding description against REMEDIATIONS table. Returns (zh, en) or ("", "")."""
    desc_lower = description.lower()
    for key, (zh, en) in REMEDIATIONS.items():
        if key in desc_lower:
            return zh, en
    return "", ""

def _dimension_remediation(dimension: str) -> Tuple[str, str]:
    """Get dimension-level remediation by matching the English dimension name. Returns (zh, en)."""
    for key, (zh, en) in DIMENSION_REMEDIATIONS.items():
        if key.lower() in dimension.lower():
            return zh, en
    return "", ""

# ── Frontmatter Parser ──────────────────────────────────────────────────────

def parse_frontmatter(text: str) -> Dict[str, str]:
    """Parse YAML frontmatter without pyyaml. Returns flat key-value dict."""
    fm = {}
    m = re.match(r'^---\s*\n(.*?)\n---', text, re.DOTALL)
    if not m:
        return fm
    block = m.group(1)
    current_key = None
    list_values = []
    for line in block.split('\n'):
        # key: value
        kv = re.match(r'^(\w[\w\-]*):\s*(.*)', line)
        if kv:
            # flush previous list
            if current_key and list_values:
                fm[current_key] = list_values
                list_values = []
            key, val = kv.group(1), kv.group(2).strip().strip('"').strip("'")
            current_key = key
            if val:
                fm[key] = val
        elif re.match(r'^\s+-\s+(.+)', line):
            item = re.match(r'^\s+-\s+(.+)', line).group(1).strip()
            list_values.append(item)
    if current_key and list_values:
        fm[current_key] = list_values
    return fm

# ── File Utilities ───────────────────────────────────────────────────────────

SCAN_EXTENSIONS = {
    '.md', '.txt', '.py', '.js', '.ts', '.jsx', '.tsx', '.sh', '.bash',
    '.yaml', '.yml', '.json', '.toml', '.cfg', '.ini', '.conf',
    '.html', '.htm', '.xml', '.csv', '.env', '.dockerfile', '.r', '.R',
    '.go', '.rs', '.java', '.rb', '.pl', '.lua', '.swift', '.kt',
}

def collect_files(skill_dir: Path) -> List[Path]:
    """Collect scannable files from a skill directory."""
    files = []
    for p in skill_dir.rglob('*'):
        if p.is_file() and (p.suffix.lower() in SCAN_EXTENSIONS or p.name in {
            'Dockerfile', 'Makefile', 'LICENSE', 'LICENSE.txt', '.env',
            '.env.example', 'requirements.txt', 'Pipfile',
        }):
            # Skip very large files and binary-looking content
            try:
                if p.stat().st_size > 500_000:
                    continue
            except OSError:
                continue
            files.append(p)
    return files

def read_file_safe(path: Path) -> Optional[str]:
    """Read file, return None if binary/unreadable."""
    try:
        return path.read_text(encoding='utf-8', errors='replace')
    except Exception:
        return None

def file_inventory(files: List[Path]) -> Dict[str, int]:
    """Count files by extension."""
    inv = {}
    for f in files:
        ext = f.suffix.lower() or f.name
        inv[ext] = inv.get(ext, 0) + 1
    return inv

# ── Token Estimation ─────────────────────────────────────────────────────────

def _count_cjk(text: str) -> int:
    """Count CJK characters in text."""
    return sum(1 for ch in text if '\u4e00' <= ch <= '\u9fff'
               or '\u3400' <= ch <= '\u4dbf'
               or '\uf900' <= ch <= '\ufaff')

def _estimate_tokens(text: str) -> int:
    """Estimate token count for mixed CJK/Latin text.
    CJK: ~1.5 chars/token, Latin/code: ~3.5 chars/token.
    """
    if not text:
        return 0
    cjk = _count_cjk(text)
    non_cjk = len(text) - cjk
    return int(cjk / 1.5 + non_cjk / 3.5)

def _extract_references(skill_md_content: str, skill_dir: Path) -> Tuple[List[str], List[str]]:
    """Extract referenced files from SKILL.md content.
    Returns (eager_files, lazy_files):
      eager = MANDATORY READ, READ ENTIRE FILE, code block imports, direct script refs
      lazy  = normal markdown links, backtick mentions, optional references
    """
    eager = set()
    lazy = set()

    # 1. Mandatory / eager patterns — "READ ENTIRE FILE" + nearby file
    for m in re.finditer(
        r'(?:MANDATORY|READ\s+ENTIRE\s+FILE|MUST\s+(?:READ|LOAD)|REQUIRED.*?READ)'
        r'.*?[\[`\(]([a-zA-Z0-9_./-]+\.[a-zA-Z]{1,5})',
        skill_md_content, re.IGNORECASE
    ):
        candidate = m.group(1)
        if (skill_dir / candidate).exists():
            eager.add(candidate)

    # 2. Code block imports / execution — `source`, `python`, `bash`, `node` + file
    for m in re.finditer(
        r'(?:source|python3?|bash|node|ruby|perl|sh)\s+(?:\$\{[^}]*\}/)?'
        r'([a-zA-Z0-9_./-]+\.[a-zA-Z]{1,5})',
        skill_md_content
    ):
        candidate = m.group(1)
        if (skill_dir / candidate).exists():
            eager.add(candidate)

    # 3. Markdown links: [text](file.md) — lazy unless already caught as eager
    for m in re.finditer(r'\[([^\]]*)\]\(([^)]+)\)', skill_md_content):
        target = m.group(2).strip()
        if target.startswith(('http://', 'https://', '#', 'mailto:')):
            continue
        if (skill_dir / target).exists() and target not in eager:
            lazy.add(target)

    # 4. Backtick file references: `file.md` — lazy
    for m in re.finditer(r'`([a-zA-Z0-9_./-]+\.[a-zA-Z]{1,5})`', skill_md_content):
        candidate = m.group(1)
        if (skill_dir / candidate).exists() and candidate not in eager:
            lazy.add(candidate)

    # 5. "Read file.md" / "see file.md" — lazy (general read instructions)
    for m in re.finditer(
        r'(?:[Rr]ead|[Ss]ee|[Rr]efer\s+to|[Cc]heck)\s+(?:\[?[\'"])?'
        r'([a-zA-Z0-9_./-]+\.[a-zA-Z]{1,5})',
        skill_md_content
    ):
        candidate = m.group(1)
        if (skill_dir / candidate).exists() and candidate not in eager:
            lazy.add(candidate)

    # Remove any overlap
    lazy -= eager

    return sorted(eager), sorted(lazy)

def estimate_skill_tokens(skill_dir: Path, file_contents: Dict[str, str]) -> TokenEstimate:
    """Estimate token consumption for a skill."""
    est = TokenEstimate()

    # L1: SKILL.md direct content
    for name in ('SKILL.md', 'skill.md'):
        if name in file_contents:
            est.l1_chars = len(file_contents[name])
            est.l1_skill_md = _estimate_tokens(file_contents[name])
            est.eager_files, est.lazy_files = _extract_references(file_contents[name], skill_dir)
            break

    def _resolve_chars(paths):
        total = 0
        for ref_path in paths:
            if ref_path in file_contents:
                total += len(file_contents[ref_path])
            else:
                full = skill_dir / ref_path
                if full.exists():
                    content = read_file_safe(full)
                    if content:
                        total += len(content)
        return total

    # L2a: Eager (mandatory read) files
    est.l2_eager_chars = _resolve_chars(est.eager_files)
    est.l2_eager = _estimate_tokens_from_chars(est.l2_eager_chars)

    # L2b: Lazy (on-demand) files
    est.l2_lazy_chars = _resolve_chars(est.lazy_files)
    est.l2_lazy = _estimate_tokens_from_chars(est.l2_lazy_chars)

    # L3: All files (maximum context footprint)
    for content in file_contents.values():
        est.l3_chars += len(content)
    est.l3_total = _estimate_tokens_from_chars(est.l3_chars)

    return est

def _estimate_tokens_from_chars(chars: int) -> int:
    """Quick estimate from char count (assumes mixed content ~3 chars/token)."""
    return int(chars / 3.0) if chars else 0

def format_tokens(n: int) -> str:
    """Format token count: 1234 → '1.2K', 12345 → '12.3K'."""
    if n >= 1000:
        return f"{n / 1000:.1f}K"
    return str(n)

# ── Model Pricing & Cost Estimation ──────────────────────────────────────────

# ── Cost Rules ──
# Rule 1: Three session scenarios — light / typical / heavy
# Rule 2: Output per turn = 500 tokens (avg across code-gen and Q&A skills)
# Rule 3: L2 eager files loaded at turn 2, lazy files at turn 3
# Rule 4: Prompt caching: L1 (SKILL.md) is a fixed prefix, cached from turn 2 onwards
#          L2 files enter cache after the turn they are first loaded
# Rule 5: Multi-turn context accumulates — each turn re-sends all prior context
#          Cached portion = previous turn's full input; New portion = last output + new L2

COST_SCENARIOS = {
    "light":    3,    # Quick task: 3 turns
    "typical":  6,    # Normal task: 6 turns
    "heavy":   15,    # Complex task: 15 turns
}
OUTPUT_PER_TURN = 500  # Assumed output tokens per turn

@dataclass
class ModelPricing:
    name: str               # Display name
    model_id: str           # API model ID
    provider: str
    input_per_m: float      # $/1M input tokens
    output_per_m: float     # $/1M output tokens
    cache_input_per_m: float  # $/1M cached input tokens
    context_k: int          # Context window in K
    icon_svg: str = ""      # Inline SVG icon

# Icons from lobehub/lobe-icons (static-svg)
_ICON_CLAUDE = '<svg viewBox="0 0 24 24" xmlns="http://www.w3.org/2000/svg"><path d="M4.709 15.955l4.72-2.647.08-.23-.08-.128H9.2l-.79-.048-2.698-.073-2.339-.097-2.266-.122-.571-.121L0 11.784l.055-.352.48-.321.686.06 1.52.103 2.278.158 1.652.097 2.449.255h.389l.055-.157-.134-.098-.103-.097-2.358-1.596-2.552-1.688-1.336-.972-.724-.491-.364-.462-.158-1.008.656-.722.881.06.225.061.893.686 1.908 1.476 2.491 1.833.365.304.145-.103.019-.073-.164-.274-1.355-2.446-1.446-2.49-.644-1.032-.17-.619a2.97 2.97 0 01-.104-.729L6.283.134 6.696 0l.996.134.42.364.62 1.414 1.002 2.229 1.555 3.03.456.898.243.832.091.255h.158V9.01l.128-1.706.237-2.095.23-2.695.08-.76.376-.91.747-.492.584.28.48.685-.067.444-.286 1.851-.559 2.903-.364 1.942h.212l.243-.242.985-1.306 1.652-2.064.73-.82.85-.904.547-.431h1.033l.76 1.129-.34 1.166-1.064 1.347-.881 1.142-1.264 1.7-.79 1.36.073.11.188-.02 2.856-.606 1.543-.28 1.841-.315.833.388.091.395-.328.807-1.969.486-2.309.462-3.439.813-.042.03.049.061 1.549.146.662.036h1.622l3.02.225.79.522.474.638-.079.485-1.215.62-1.64-.389-3.829-.91-1.312-.329h-.182v.11l1.093 1.068 2.006 1.81 2.509 2.33.127.578-.322.455-.34-.049-2.205-1.657-.851-.747-1.926-1.62h-.128v.17l.444.649 2.345 3.521.122 1.08-.17.353-.608.213-.668-.122-1.374-1.925-1.415-2.167-1.143-1.943-.14.08-.674 7.254-.316.37-.729.28-.607-.461-.322-.747.322-1.476.389-1.924.315-1.53.286-1.9.17-.632-.012-.042-.14.018-1.434 1.967-2.18 2.945-1.726 1.845-.414.164-.717-.37.067-.662.401-.589 2.388-3.036 1.44-1.882.93-1.086-.006-.158h-.055L4.132 18.56l-1.13.146-.487-.456.061-.746.231-.243 1.908-1.312-.006.006z" fill="#D97757" fill-rule="nonzero"/></svg>'
_ICON_OPENAI = '<svg fill="currentColor" viewBox="0 0 24 24" xmlns="http://www.w3.org/2000/svg"><path d="M9.205 8.658v-2.26c0-.19.072-.333.238-.428l4.543-2.616c.619-.357 1.356-.523 2.117-.523 2.854 0 4.662 2.212 4.662 4.566 0 .167 0 .357-.024.547l-4.71-2.759a.797.797 0 00-.856 0l-5.97 3.473zm10.609 8.8V12.06c0-.333-.143-.57-.429-.737l-5.97-3.473 1.95-1.118a.433.433 0 01.476 0l4.543 2.617c1.309.76 2.189 2.378 2.189 3.948 0 1.808-1.07 3.473-2.76 4.163zM7.802 12.703l-1.95-1.142c-.167-.095-.239-.238-.239-.428V5.899c0-2.545 1.95-4.472 4.591-4.472 1 0 1.927.333 2.712.928L8.23 5.067c-.285.166-.428.404-.428.737v6.898zM12 15.128l-2.795-1.57v-3.33L12 8.658l2.795 1.57v3.33L12 15.128zm1.796 7.23c-1 0-1.927-.332-2.712-.927l4.686-2.712c.285-.166.428-.404.428-.737v-6.898l1.974 1.142c.167.095.238.238.238.428v5.233c0 2.545-1.974 4.472-4.614 4.472zm-5.637-5.303l-4.544-2.617c-1.308-.761-2.188-2.378-2.188-3.948A4.482 4.482 0 014.21 6.327v5.423c0 .333.143.571.428.738l5.947 3.449-1.95 1.118a.432.432 0 01-.476 0zm-.262 3.9c-2.688 0-4.662-2.021-4.662-4.519 0-.19.024-.38.047-.57l4.686 2.71c.286.167.571.167.856 0l5.97-3.448v2.26c0 .19-.07.333-.237.428l-4.543 2.616c-.619.357-1.356.523-2.117.523zm5.899 2.83a5.947 5.947 0 005.827-4.756C22.287 18.339 24 15.84 24 13.296c0-1.665-.713-3.282-1.998-4.448.119-.5.19-.999.19-1.498 0-3.401-2.759-5.947-5.946-5.947-.642 0-1.26.095-1.88.31A5.962 5.962 0 0010.205 0a5.947 5.947 0 00-5.827 4.757C1.713 5.447 0 7.945 0 10.49c0 1.666.713 3.283 1.998 4.448-.119.5-.19 1-.19 1.499 0 3.401 2.759 5.946 5.946 5.946.642 0 1.26-.095 1.88-.309a5.96 5.96 0 004.162 1.713z"/></svg>'
_ICON_GEMINI = '<svg viewBox="0 0 24 24" xmlns="http://www.w3.org/2000/svg"><path d="M20.616 10.835a14.147 14.147 0 01-4.45-3.001 14.111 14.111 0 01-3.678-6.452.503.503 0 00-.975 0 14.134 14.134 0 01-3.679 6.452 14.155 14.155 0 01-4.45 3.001c-.65.28-1.318.505-2.002.678a.502.502 0 000 .975c.684.172 1.35.397 2.002.677a14.147 14.147 0 014.45 3.001 14.112 14.112 0 013.679 6.453.502.502 0 00.975 0c.172-.685.397-1.351.677-2.003a14.145 14.145 0 013.001-4.45 14.113 14.113 0 016.453-3.678.503.503 0 000-.975 13.245 13.245 0 01-2.003-.678z" fill="#4285F4"/></svg>'

# Source: https://assets-cdn.pipellm.ai/api/models (pipellm.ai)
# cache_input_per_m: Anthropic ~10% of input, Google ~25%, OpenAI ~50%
MODEL_CATALOG: List[ModelPricing] = [
    ModelPricing("Claude Sonnet 4.6",       "claude-sonnet-4-6",      "Anthropic", 3,    15,   0.30,  200, _ICON_CLAUDE),
    ModelPricing("Claude Opus 4.6",         "claude-opus-4-6",        "Anthropic", 5,    25,   0.50, 1000, _ICON_CLAUDE),
    ModelPricing("Gemini 3.1 Pro Preview",  "gemini-3.1-pro-preview", "Google",    2,    12,   0.50, 1000, _ICON_GEMINI),
    ModelPricing("GPT-5.2",                 "gpt-5.2",                "OpenAI",    1.75, 14,   0.875, 400, _ICON_OPENAI),
]

@dataclass
class CostEstimate:
    model_name: str
    input_per_m: float
    output_per_m: float
    cache_input_per_m: float
    light_cost: float       # 3-turn session total
    typical_cost: float     # 6-turn session total
    heavy_cost: float       # 15-turn session total

def _compute_session_cost(te: TokenEstimate, mp: ModelPricing, n_turns: int) -> float:
    """Compute total session cost for N turns using multi-turn accumulation model.

    Turn-by-turn model:
      Turn 1: input_new=L1,                         input_cached=0
      Turn 2: input_new=O+L2_eager,                  input_cached=L1
      Turn 3: input_new=O+L2_lazy,                   input_cached=L1+O+L2_eager
      Turn k (k>3): input_new=O,                     input_cached=L1+L2e+L2l+(k-2)*O
    Each turn output = OUTPUT_PER_TURN
    """
    L1 = te.l1_skill_md
    L2e = te.l2_eager
    L2l = te.l2_lazy
    O = OUTPUT_PER_TURN

    r_full = mp.input_per_m / 1_000_000
    r_cache = mp.cache_input_per_m / 1_000_000
    r_out = mp.output_per_m / 1_000_000

    total = 0.0
    for k in range(1, n_turns + 1):
        if k == 1:
            inp_new, inp_cached = L1, 0
        elif k == 2:
            inp_new, inp_cached = O + L2e, L1
        elif k == 3:
            inp_new, inp_cached = O + L2l, L1 + O + L2e
        else:
            inp_new = O
            inp_cached = L1 + L2e + L2l + (k - 2) * O
        total += inp_new * r_full + inp_cached * r_cache + O * r_out
    return total

def estimate_costs(te: TokenEstimate) -> List[CostEstimate]:
    """Compute multi-turn session cost for each model × scenario."""
    results = []
    for mp in MODEL_CATALOG:
        results.append(CostEstimate(
            model_name=mp.name,
            input_per_m=mp.input_per_m,
            output_per_m=mp.output_per_m,
            cache_input_per_m=mp.cache_input_per_m,
            light_cost=_compute_session_cost(te, mp, COST_SCENARIOS["light"]),
            typical_cost=_compute_session_cost(te, mp, COST_SCENARIOS["typical"]),
            heavy_cost=_compute_session_cost(te, mp, COST_SCENARIOS["heavy"]),
        ))
    return results

def format_cost(v: float) -> str:
    """Format dollar amount: 0.00012 → '$0.0001', 1.23 → '$1.23'."""
    if v < 0.001:
        return f"${v:.5f}"
    if v < 0.1:
        return f"${v:.4f}"
    if v < 10:
        return f"${v:.3f}"
    return f"${v:.2f}"

# ── The Auditor ──────────────────────────────────────────────────────────────

class SkillAuditor:
    """Main auditor: runs 10 dimensions against a skill directory."""

    DIMENSIONS = [
        ("Prompt 注入检测",   "Prompt Injection",        "OWASP LLM01"),
        ("权限提升分析",     "Permission Escalation",    "OWASP LLM06"),
        ("数据外泄风险",     "Data Exfiltration",        "OWASP LLM02 / MCP-Scan TPA"),
        ("破坏性操作",       "Destructive Operations",   "Claude Code Built-in"),
        ("供应链/来源验证",  "Supply Chain",             "SLSA / OpenSSF"),
        ("代码安全(静态分析)", "Code Security",           "CWE / OWASP"),
        ("凭证与密钥泄露",   "Credential Leaks",         "OWASP LLM02"),
        ("权限最小化",       "Least Privilege",          "Google SAIF"),
        ("许可证合规",       "License Compliance",       "—"),
        ("资源滥用/无限消耗", "Resource Abuse",           "OWASP LLM10"),
    ]

    def __init__(self, rules_path: Optional[Path] = None):
        """Load user-configurable rules from rules.yaml."""
        self._configurable_rules = _load_configurable_rules(rules_path)

    def _apply_configurable_rules(self, dimension_key: str, file_contents: Dict[str, str], ref: str) -> List[Finding]:
        """Apply all enabled configurable rules for a given dimension.

        Iterates over rules in self._configurable_rules[dimension_key], skips
        disabled rules, and skips matches that hit any whitelist entry.
        """
        findings = []
        for rule in self._configurable_rules.get(dimension_key, []):
            if not rule.get("enabled", True):
                continue
            pattern = rule.get("pattern", "")
            if not pattern:
                continue
            severity = rule.get("severity", "MEDIUM")
            description = rule.get("description", "")
            whitelist = rule.get("whitelist") or []
            for rel_path, content in file_contents.items():
                try:
                    for m in re.finditer(pattern, content, re.IGNORECASE):
                        matched_text = m.group()
                        if any(w.lower() in matched_text.lower() for w in whitelist if w):
                            continue
                        line_num = content[:m.start()].count('\n') + 1
                        findings.append(Finding(
                            dimension="", severity=severity,
                            file_path=rel_path, line_number=line_num,
                            pattern=pattern, description=description,
                            reference=ref,
                        ))
                except re.error:
                    continue
        return findings

    def audit_skill(self, skill_dir: Path) -> AuditReport:
        skill_dir = skill_dir.resolve()
        report = AuditReport(
            skill_name=skill_dir.name,
            skill_path=str(skill_dir),
        )

        files = collect_files(skill_dir)
        report.file_inventory = file_inventory(files)

        # Read all file contents into a dict {relative_path: content}
        file_contents = {}
        full_text_parts = []
        for f in files:
            content = read_file_safe(f)
            if content is not None:
                rel = str(f.relative_to(skill_dir))
                file_contents[rel] = content
                full_text_parts.append(content)

        full_text = '\n'.join(full_text_parts)

        # Parse frontmatter from SKILL.md if present
        frontmatter = {}
        for name in ('SKILL.md', 'skill.md'):
            fm_path = skill_dir / name
            if fm_path.exists():
                fm_content = read_file_safe(fm_path)
                if fm_content:
                    frontmatter = parse_frontmatter(fm_content)
                break

        # Run all 10 dimensions
        checks = [
            self._check_prompt_injection,
            self._check_permission_escalation,
            self._check_data_exfiltration,
            self._check_destructive_operations,
            self._check_supply_chain,
            self._check_code_security,
            self._check_credential_leaks,
            self._check_least_privilege,
            self._check_license_compliance,
            self._check_resource_abuse,
        ]

        for i, check_fn in enumerate(checks):
            dim_name = f"{self.DIMENSIONS[i][0]} ({self.DIMENSIONS[i][1]})"
            ref = self.DIMENSIONS[i][2]
            try:
                if check_fn == self._check_supply_chain:
                    findings = check_fn(skill_dir, file_contents, ref)
                elif check_fn == self._check_least_privilege:
                    findings = check_fn(frontmatter, full_text, file_contents, ref)
                elif check_fn == self._check_license_compliance:
                    findings = check_fn(skill_dir, frontmatter, file_contents, ref)
                else:
                    findings = check_fn(full_text, file_contents, ref)
            except Exception:
                findings = []

            for f in findings:
                f.dimension = dim_name
            report.findings.extend(findings)
            report.dimension_summary[dim_name] = len(findings)

        report.risk_score, report.risk_level = compute_risk(report.findings)

        # Auto-fill remediation for each finding
        for f in report.findings:
            if not f.remediation_zh:
                zh, en = _match_remediation(f.description)
                f.remediation_zh = zh
                f.remediation_en = en
            if not f.remediation_zh:
                zh, en = _dimension_remediation(f.dimension)
                f.remediation_zh = zh
                f.remediation_en = en

        report.token_estimate = estimate_skill_tokens(skill_dir, file_contents)
        report.cost_estimates = estimate_costs(report.token_estimate)
        return report

    def audit_marketplace(self, market_dir: Path) -> List[AuditReport]:
        market_dir = market_dir.resolve()
        # Detect marketplace layout: look for skills/ subdir or direct subdirs
        skills_dir = market_dir / 'skills'
        if skills_dir.is_dir():
            base = skills_dir
        else:
            base = market_dir

        reports = []
        for entry in sorted(base.iterdir()):
            if entry.is_dir() and not entry.name.startswith('.'):
                reports.append(self.audit_skill(entry))
        return reports

    # ── Dimension 1: Prompt Injection ────────────────────────────────────

    def _check_prompt_injection(self, full_text, file_contents, ref) -> List[Finding]:
        findings = []

        # ── 内置规则：10 条核心注入短语（不可配置）──
        injection_phrases = [
            (r'ignore\s+(all\s+)?previous\s+instructions', "Prompt injection: ignore previous instructions"),
            (r'you\s+are\s+now\b', "Prompt injection: role override 'you are now'"),
            (r'disregard\s+(all\s+)?(above|previous|prior)', "Prompt injection: disregard directive"),
            (r'override\s+system\s+(prompt|instructions|message)', "Prompt injection: override system prompt"),
            (r'\bjailbreak\b', "Prompt injection keyword: jailbreak"),
            (r'pretend\s+you\s+are\b', "Role-play induction: pretend you are"),
            (r'act\s+as\s+if\s+you', "Role-play induction: act as if"),
            (r'roleplay\s+as\b', "Role-play induction: roleplay as"),
            (r'do\s+anything\s+now', "DAN-style jailbreak attempt"),
            (r'from\s+now\s+on,?\s+you\s+(will|must|should)', "Behavioral override: from now on you will"),
        ]

        for rel_path, content in file_contents.items():
            for pattern, desc in injection_phrases:
                for m in re.finditer(pattern, content, re.IGNORECASE):
                    line_num = content[:m.start()].count('\n') + 1
                    findings.append(Finding(
                        dimension="", severity="CRITICAL",
                        file_path=rel_path, line_number=line_num,
                        pattern=pattern, description=desc,
                        reference=ref,
                    ))

        # ── 可配置辅助规则（从 yaml 加载）──
        # PI-AUX-01: 零宽字符 — 特殊处理：逐字符检测，输出字符码点
        pi_aux_zwc_rule = next(
            (r for r in self._configurable_rules.get("prompt_injection_auxiliary", [])
             if r.get("id") == "PI-AUX-01"), None
        )
        if pi_aux_zwc_rule is None or pi_aux_zwc_rule.get("enabled", True):
            zwc_severity = (pi_aux_zwc_rule or {}).get("severity", "MEDIUM")
            zwc_pattern = r'[\u200b\u200c\u200d\ufeff\u2060]'
            for rel_path, content in file_contents.items():
                for m in re.finditer(zwc_pattern, content):
                    line_num = content[:m.start()].count('\n') + 1
                    findings.append(Finding(
                        dimension="", severity=zwc_severity,
                        file_path=rel_path, line_number=line_num,
                        pattern="zero-width character",
                        description=f"Zero-width character U+{ord(m.group()):04X} detected (possible steganographic injection)",
                        reference=ref,
                    ))

        # PI-AUX-02: 长 base64 串 — 特殊处理：输出匹配长度
        pi_aux_b64_rule = next(
            (r for r in self._configurable_rules.get("prompt_injection_auxiliary", [])
             if r.get("id") == "PI-AUX-02"), None
        )
        if pi_aux_b64_rule is None or pi_aux_b64_rule.get("enabled", True):
            b64_severity = (pi_aux_b64_rule or {}).get("severity", "MEDIUM")
            for rel_path, content in file_contents.items():
                for m in re.finditer(r'[A-Za-z0-9+/]{200,}={0,2}', content):
                    line_num = content[:m.start()].count('\n') + 1
                    findings.append(Finding(
                        dimension="", severity=b64_severity,
                        file_path=rel_path, line_number=line_num,
                        pattern="long base64 string",
                        description=f"Long base64-like string ({len(m.group())} chars) - may hide injected payload",
                        reference=ref,
                    ))

        # PI-AUX-03: HTML 注释隐藏指令 — 特殊处理：检查注释内容关键词
        pi_aux_html_rule = next(
            (r for r in self._configurable_rules.get("prompt_injection_auxiliary", [])
             if r.get("id") == "PI-AUX-03"), None
        )
        if pi_aux_html_rule is None or pi_aux_html_rule.get("enabled", True):
            html_severity = (pi_aux_html_rule or {}).get("severity", "HIGH")
            html_whitelist = (pi_aux_html_rule or {}).get("whitelist") or []
            kw_list = ['instruction', 'ignore', 'override', 'system prompt', 'you must', 'you are now']
            for rel_path, content in file_contents.items():
                for m in re.finditer(r'<!--(.*?)-->', content, re.DOTALL):
                    comment = m.group(1).lower()
                    if any(kw in comment for kw in kw_list):
                        if html_whitelist and any(w.lower() in comment for w in html_whitelist if w):
                            continue
                        line_num = content[:m.start()].count('\n') + 1
                        findings.append(Finding(
                            dimension="", severity=html_severity,
                            file_path=rel_path, line_number=line_num,
                            pattern="<!-- hidden instruction -->",
                            description="Hidden instruction detected in HTML comment",
                            reference=ref,
                        ))

        return findings

    # ── Dimension 2: Permission Escalation ───────────────────────────────

    def _check_permission_escalation(self, full_text, file_contents, ref) -> List[Finding]:
        findings = []

        patterns = [
            (r'dangerouslyDisableSandbox', "CRITICAL", "Disables sandbox protection"),
            (r'--dangerously-skip-permissions', "CRITICAL", "Skips permission checks"),
            (r'\bsudo\s+', "HIGH", "sudo usage - requires root privileges"),
            (r'chmod\s+777\b', "HIGH", "chmod 777 - world-writable permissions"),
            (r'chown\s+root\b', "HIGH", "chown root - changing ownership to root"),
            (r'\.claude/settings\.json', "HIGH", "Modifying Claude settings file"),
            (r'\ballowedTools\b', "MEDIUM", "References allowedTools configuration"),
            (r'--no-verify\b', "MEDIUM", "Bypasses verification hooks"),
            (r'chmod\s+[0-7]*[67][0-7]{2}\b', "MEDIUM", "Overly permissive chmod"),
            (r'setuid\b|setgid\b', "HIGH", "setuid/setgid - elevated privilege bits"),
        ]

        for rel_path, content in file_contents.items():
            for pattern, severity, desc in patterns:
                for m in re.finditer(pattern, content, re.IGNORECASE):
                    line_num = content[:m.start()].count('\n') + 1
                    findings.append(Finding(
                        dimension="", severity=severity,
                        file_path=rel_path, line_number=line_num,
                        pattern=pattern, description=desc,
                        reference=ref,
                    ))

        return findings

    # ── Dimension 3: Data Exfiltration ───────────────────────────────────

    def _check_data_exfiltration(self, full_text, file_contents, ref) -> List[Finding]:
        findings = []

        # ── 内置规则：os.environ + network send 组合检测（不可配置）──
        environ_read = re.search(r'os\.environ', full_text) is not None
        network_send = re.search(r'(requests\.post|curl.*POST|fetch.*POST|urllib)', full_text) is not None

        if environ_read and network_send:
            findings.append(Finding(
                dimension="", severity="HIGH",
                file_path="(multiple files)", line_number=0,
                pattern="os.environ + network send",
                description="Environment variables read AND outbound network requests detected - potential credential exfiltration",
                reference=ref,
            ))

        # ── 可配置规则（从 yaml 加载）──
        findings.extend(self._apply_configurable_rules("data_exfiltration", file_contents, ref))

        return findings

    # ── Dimension 4: Destructive Operations ──────────────────────────────

    def _check_destructive_operations(self, full_text, file_contents, ref) -> List[Finding]:
        findings = []

        patterns = [
            (r'rm\s+-rf\s+/', "CRITICAL", "rm -rf on root path - catastrophic deletion"),
            (r'rm\s+-rf\b', "HIGH", "rm -rf - recursive forced deletion"),
            (r'git\s+reset\s+--hard\b', "HIGH", "git reset --hard - discards all changes"),
            (r'git\s+push\s+--force\b', "HIGH", "git push --force - overwrites remote history"),
            (r'git\s+push\s+-f\b', "HIGH", "git push -f - force push"),
            (r'git\s+clean\s+-f', "HIGH", "git clean -f - deletes untracked files"),
            (r'DROP\s+TABLE\b', "CRITICAL", "DROP TABLE - database table deletion"),
            (r'DELETE\s+FROM\b(?!.*WHERE)', "HIGH", "DELETE FROM without WHERE - deletes all rows"),
            (r'TRUNCATE\s+TABLE\b', "CRITICAL", "TRUNCATE TABLE - removes all data"),
            (r'shutil\.rmtree\s*\(', "HIGH", "shutil.rmtree - recursive directory deletion"),
            (r'os\.remove\s*\(', "MEDIUM", "os.remove - file deletion"),
            (r'os\.unlink\s*\(', "MEDIUM", "os.unlink - file deletion"),
            (r'\bformat\s+[a-zA-Z]:', "CRITICAL", "Disk format command"),
            (r'\bfdisk\b', "CRITICAL", "fdisk - disk partitioning"),
            (r'\bmkfs\b', "CRITICAL", "mkfs - creates filesystem (destroys data)"),
            (r'\bdd\s+if=', "HIGH", "dd - low-level data copy/overwrite"),
            (r':(){ :\|:& };:', "CRITICAL", "Fork bomb detected"),
        ]

        for rel_path, content in file_contents.items():
            for pattern, severity, desc in patterns:
                for m in re.finditer(pattern, content, re.IGNORECASE):
                    line_num = content[:m.start()].count('\n') + 1
                    findings.append(Finding(
                        dimension="", severity=severity,
                        file_path=rel_path, line_number=line_num,
                        pattern=pattern, description=desc,
                        reference=ref,
                    ))

        return findings

    # ── Dimension 5: Supply Chain ────────────────────────────────────────

    def _check_supply_chain(self, skill_dir, file_contents, ref) -> List[Finding]:
        findings = []

        # ── 可配置规则（从 yaml 加载）──
        # SC-08 (Dockerfile FROM) 需要只扫描 Dockerfile 文件，单独处理
        dockerfile_rules = [
            r for r in self._configurable_rules.get("supply_chain", [])
            if r.get("id") == "SC-08"
        ]
        other_rules = [
            r for r in self._configurable_rules.get("supply_chain", [])
            if r.get("id") != "SC-08"
        ]

        # Apply non-Dockerfile rules to all files
        for rule in other_rules:
            if not rule.get("enabled", True):
                continue
            pattern = rule.get("pattern", "")
            if not pattern:
                continue
            severity = rule.get("severity", "MEDIUM")
            description = rule.get("description", "")
            whitelist = rule.get("whitelist") or []
            for rel_path, content in file_contents.items():
                try:
                    for m in re.finditer(pattern, content, re.IGNORECASE):
                        matched_text = m.group()
                        if any(w.lower() in matched_text.lower() for w in whitelist if w):
                            continue
                        line_num = content[:m.start()].count('\n') + 1
                        findings.append(Finding(
                            dimension="", severity=severity,
                            file_path=rel_path, line_number=line_num,
                            pattern=pattern, description=description,
                            reference=ref,
                        ))
                except re.error:
                    continue

        # Apply Dockerfile-only rules
        for rule in dockerfile_rules:
            if not rule.get("enabled", True):
                continue
            pattern = rule.get("pattern", "")
            if not pattern:
                continue
            severity = rule.get("severity", "LOW")
            description = rule.get("description", "")
            whitelist = rule.get("whitelist") or []
            for rel_path, content in file_contents.items():
                is_dockerfile = ('dockerfile' in rel_path.lower() or rel_path.endswith('Dockerfile'))
                if not is_dockerfile:
                    continue
                try:
                    for m in re.finditer(pattern, content, re.MULTILINE):
                        matched_text = m.group()
                        if any(w.lower() in matched_text.lower() for w in whitelist if w):
                            continue
                        line_num = content[:m.start()].count('\n') + 1
                        findings.append(Finding(
                            dimension="", severity=severity,
                            file_path=rel_path, line_number=line_num,
                            pattern=pattern, description=description,
                            reference=ref,
                        ))
                except re.error:
                    continue

        return findings

    # ── Dimension 6: Code Security ───────────────────────────────────────

    def _check_code_security(self, full_text, file_contents, ref) -> List[Finding]:
        findings = []

        patterns = [
            # shell injection
            (r'subprocess\.(run|call|Popen)\s*\([^)]*shell\s*=\s*True', "HIGH",
             "subprocess with shell=True - potential shell injection"),
            (r'os\.system\s*\(', "HIGH", "os.system - shell command execution"),
            (r'os\.popen\s*\(', "HIGH", "os.popen - shell command execution"),
            # code injection
            (r'\beval\s*\(', "HIGH", "eval() - arbitrary code execution"),
            (r'\bexec\s*\(', "HIGH", "exec() - arbitrary code execution"),
            (r'(?<!re\.)\bcompile\s*\([^)]*["\']', "MEDIUM", "compile() - dynamic code compilation"),
            # deserialization
            (r'pickle\.loads?\s*\(', "HIGH", "pickle.load - unsafe deserialization"),
            (r'yaml\.load\s*\((?!.*Loader\s*=\s*yaml\.SafeLoader)', "HIGH",
             "yaml.load without SafeLoader - unsafe deserialization"),
            (r'marshal\.loads?\s*\(', "HIGH", "marshal.load - unsafe deserialization"),
            # SQL injection
            (r'f["\']SELECT\b.*\{', "HIGH", "SQL injection: f-string in SELECT query"),
            (r'f["\']INSERT\b.*\{', "HIGH", "SQL injection: f-string in INSERT query"),
            (r'f["\']UPDATE\b.*\{', "HIGH", "SQL injection: f-string in UPDATE query"),
            (r'f["\']DELETE\b.*\{', "HIGH", "SQL injection: f-string in DELETE query"),
            (r'\.format\s*\(.*SELECT\b', "HIGH", "SQL injection: .format() in query"),
            (r'%\s*\(.*SELECT\b', "MEDIUM", "SQL injection: % formatting in query"),
            # XSS / template injection
            (r'\bMarkupSafe\b.*\bMarkup\s*\(', "MEDIUM", "Possible XSS via raw Markup"),
            (r'innerHTML\s*=', "MEDIUM", "innerHTML assignment - XSS risk"),
            (r'dangerouslySetInnerHTML', "MEDIUM", "React dangerouslySetInnerHTML - XSS risk"),
            # Path traversal
            (r'\.\./(\.\./)+(etc|root|home|var|usr)\b', "MEDIUM", "Deep path traversal pattern"),
        ]

        for rel_path, content in file_contents.items():
            # Only check code files for some patterns
            is_code = rel_path.endswith(('.py', '.js', '.ts', '.jsx', '.tsx', '.rb', '.go', '.rs', '.java', '.sh'))

            check_patterns = patterns if is_code else [
                p for p in patterns if p[0] in (
                    r'\beval\s*\(', r'\bexec\s*\(',
                    r'os\.system\s*\(', r'os\.popen\s*\(',
                    r'subprocess\.(run|call|Popen)\s*\([^)]*shell\s*=\s*True',
                )
            ]

            for pattern, severity, desc in check_patterns:
                for m in re.finditer(pattern, content):
                    line_num = content[:m.start()].count('\n') + 1
                    findings.append(Finding(
                        dimension="", severity=severity,
                        file_path=rel_path, line_number=line_num,
                        pattern=pattern, description=desc,
                        reference=ref,
                    ))

        return findings

    # ── Dimension 7: Credential Leaks ────────────────────────────────────

    def _check_credential_leaks(self, full_text, file_contents, ref) -> List[Finding]:
        findings = []

        key_prefixes = [
            (r'\bsk-[a-zA-Z0-9]{20,}', "CRITICAL", "OpenAI/Anthropic API key (sk-...)"),
            (r'\bghp_[a-zA-Z0-9]{36,}', "CRITICAL", "GitHub personal access token"),
            (r'\bgho_[a-zA-Z0-9]{36,}', "CRITICAL", "GitHub OAuth token"),
            (r'\bAKIA[A-Z0-9]{16}\b', "CRITICAL", "AWS Access Key ID"),
            (r'\bxoxb-[0-9-]+', "CRITICAL", "Slack bot token"),
            (r'\bxoxp-[0-9-]+', "CRITICAL", "Slack user token"),
            (r'\bglpat-[a-zA-Z0-9\-_]{20,}', "CRITICAL", "GitLab personal access token"),
            (r'\beyJ[a-zA-Z0-9_-]{50,}\.eyJ', "MEDIUM", "JWT token detected"),
        ]

        hardcoded_patterns = [
            (r'(?:password|passwd|pwd)\s*[=:]\s*["\'][^"\']{8,}["\']', "HIGH",
             "Hardcoded password"),
            (r'(?:secret|api_?key|token|auth)\s*[=:]\s*["\'][^"\']{8,}["\']', "HIGH",
             "Hardcoded secret/API key"),
        ]

        pem_pattern = (r'-----BEGIN\s+(?:RSA\s+)?PRIVATE\s+KEY-----', "CRITICAL",
                       "Private key in PEM format")

        # Files to skip for hardcoded credential checks
        skip_patterns = {'example', 'template', 'test', 'mock', 'sample', 'demo', 'fixture'}

        for rel_path, content in file_contents.items():
            rel_lower = rel_path.lower()

            # Key prefix patterns - always check
            for pattern, severity, desc in key_prefixes:
                for m in re.finditer(pattern, content):
                    line_num = content[:m.start()].count('\n') + 1
                    findings.append(Finding(
                        dimension="", severity=severity,
                        file_path=rel_path, line_number=line_num,
                        pattern=pattern, description=desc,
                        reference=ref,
                    ))

            # PEM key
            for m in re.finditer(pem_pattern[0], content):
                line_num = content[:m.start()].count('\n') + 1
                findings.append(Finding(
                    dimension="", severity=pem_pattern[1],
                    file_path=rel_path, line_number=line_num,
                    pattern=pem_pattern[0], description=pem_pattern[2],
                    reference=ref,
                ))

            # Hardcoded passwords - skip test/example files
            if not any(skip in rel_lower for skip in skip_patterns):
                for pattern, severity, desc in hardcoded_patterns:
                    for m in re.finditer(pattern, content, re.IGNORECASE):
                        matched = m.group()
                        # Skip obvious placeholders
                        if any(ph in matched.lower() for ph in [
                            'your_', 'xxx', 'placeholder', 'changeme', 'example',
                            'replace', '<', '${', 'todo', 'fixme',
                        ]):
                            continue
                        line_num = content[:m.start()].count('\n') + 1
                        findings.append(Finding(
                            dimension="", severity=severity,
                            file_path=rel_path, line_number=line_num,
                            pattern=pattern, description=desc,
                            reference=ref,
                        ))

            # Hardcoded email as identifier (lower severity)
            if not any(skip in rel_lower for skip in skip_patterns):
                for m in re.finditer(r'Entrez\.email\s*=\s*["\'][^"\']+@[^"\']+["\']', content):
                    line_num = content[:m.start()].count('\n') + 1
                    findings.append(Finding(
                        dimension="", severity="MEDIUM",
                        file_path=rel_path, line_number=line_num,
                        pattern="hardcoded email",
                        description="Hardcoded email address in API configuration",
                        reference=ref,
                    ))

        return findings

    # ── Dimension 8: Least Privilege ─────────────────────────────────────

    def _check_least_privilege(self, frontmatter, full_text, file_contents, ref) -> List[Finding]:
        findings = []

        allowed_tools = frontmatter.get('allowed-tools', [])
        if isinstance(allowed_tools, str):
            allowed_tools = [allowed_tools]

        # Resolve per-rule config from yaml
        lp_rules = {r.get("id"): r for r in self._configurable_rules.get("least_privilege", [])}

        lp01 = lp_rules.get("LP-01", {})
        lp02 = lp_rules.get("LP-02", {})
        lp03 = lp_rules.get("LP-03", {})

        if not allowed_tools:
            if lp01.get("enabled", True) if lp01 else True:
                severity = lp01.get("severity", "LOW") if lp01 else "LOW"
                findings.append(Finding(
                    dimension="", severity=severity,
                    file_path="SKILL.md", line_number=0,
                    pattern="missing allowed-tools",
                    description="No allowed-tools declared in frontmatter - implicit all-tools access",
                    reference=ref,
                ))
        else:
            tool_set = set(t.lower() for t in allowed_tools)

            has_shell = any(t in tool_set for t in ['bash', 'run_shell_command', 'shell', 'terminal'])
            has_network = any(t in tool_set for t in ['web_fetch', 'fetch', 'http', 'network', 'web_search'])
            has_write = any(t in tool_set for t in ['write', 'edit', 'file_write', 'write_file'])

            if has_shell:
                if lp02.get("enabled", True) if lp02 else True:
                    severity = lp02.get("severity", "MEDIUM") if lp02 else "MEDIUM"
                    findings.append(Finding(
                        dimension="", severity=severity,
                        file_path="SKILL.md", line_number=0,
                        pattern="allowed-tools: shell",
                        description="Shell access declared in allowed-tools",
                        reference=ref,
                    ))

            if has_shell and has_network and has_write:
                if lp03.get("enabled", True) if lp03 else True:
                    severity = lp03.get("severity", "HIGH") if lp03 else "HIGH"
                    findings.append(Finding(
                        dimension="", severity=severity,
                        file_path="SKILL.md", line_number=0,
                        pattern="shell + network + write",
                        description="Dangerous tool combination: shell + network + file write access",
                        reference=ref,
                    ))

        return findings

    # ── Dimension 9: License Compliance ──────────────────────────────────

    def _check_license_compliance(self, skill_dir, frontmatter, file_contents, ref) -> List[Finding]:
        findings = []

        # Check frontmatter license (built-in: open source detection + proprietary declaration)
        fm_license = frontmatter.get('license', '').lower() if isinstance(frontmatter.get('license'), str) else ''

        # Open source licenses (built-in informational check)
        open_licenses = ['mit', 'apache', 'bsd', 'isc', 'unlicense', 'cc0', 'wtfpl', 'mpl', 'lgpl', 'gpl']

        if fm_license:
            if any(ol in fm_license for ol in open_licenses):
                findings.append(Finding(
                    dimension="", severity="INFO",
                    file_path="SKILL.md", line_number=0,
                    pattern=f"license: {fm_license}",
                    description=f"Open source license: {fm_license}",
                    reference=ref,
                ))
            elif 'proprietary' in fm_license:
                findings.append(Finding(
                    dimension="", severity="MEDIUM",
                    file_path="SKILL.md", line_number=0,
                    pattern=f"license: {fm_license}",
                    description="Proprietary license declared",
                    reference=ref,
                ))

        # ── 可配置规则（从 yaml 加载）──
        findings.extend(self._apply_configurable_rules("license_compliance", file_contents, ref))

        return findings

    # ── Dimension 10: Resource Abuse ─────────────────────────────────────

    def _check_resource_abuse(self, full_text, file_contents, ref) -> List[Finding]:
        findings = []

        # ── 可配置规则（RA-01 ~ RA-08，从 yaml 加载）──
        findings.extend(self._apply_configurable_rules("resource_abuse", file_contents, ref))

        # ── 内置规则：递归函数检测（不可配置，需分析函数体逻辑）──
        for rel_path, content in file_contents.items():
            if rel_path.endswith('.py'):
                for m in re.finditer(r'def\s+(\w+)\s*\(', content):
                    func_name = m.group(1)
                    func_start = m.start()
                    # Find function body (rough: next def or end of file)
                    next_def = re.search(r'\ndef\s+\w+\s*\(', content[func_start + 1:])
                    if next_def:
                        func_body = content[func_start:func_start + 1 + next_def.start()]
                    else:
                        func_body = content[func_start:]

                    # Check if function calls itself
                    if re.search(rf'\b{re.escape(func_name)}\s*\(', func_body[len(m.group()):]):
                        # Check for base case indicators
                        has_base = any(kw in func_body for kw in ['return', 'if ', 'raise', 'break'])
                        if not has_base:
                            line_num = content[:func_start].count('\n') + 1
                            findings.append(Finding(
                                dimension="", severity="HIGH",
                                file_path=rel_path, line_number=line_num,
                                pattern=f"recursive: {func_name}",
                                description=f"Recursive function '{func_name}' without obvious base case",
                                reference=ref,
                            ))

        return findings


# ── Renderers ────────────────────────────────────────────────────────────────

class TerminalRenderer:
    """ANSI colored terminal output."""

    SEVERITY_COLORS = {
        "CRITICAL": f"{C.BG_RED}{C.WHITE}{C.BOLD}",
        "HIGH":     f"{C.RED}{C.BOLD}",
        "MEDIUM":   f"{C.YELLOW}",
        "LOW":      f"{C.BLUE}",
        "INFO":     f"{C.GRAY}",
    }

    LEVEL_COLORS = {
        "A": f"{C.GREEN}{C.BOLD}",
        "B": f"{C.GREEN}",
        "C": f"{C.YELLOW}{C.BOLD}",
        "D": f"{C.RED}",
        "F": f"{C.BG_RED}{C.WHITE}{C.BOLD}",
    }

    LEVEL_LABELS = {
        "A": "Safe",
        "B": "Acceptable",
        "C": "Warning",
        "D": "Unsafe",
        "F": "Dangerous",
    }

    def render_report(self, report: AuditReport, min_severity: str = "INFO"):
        min_order = SEVERITY_ORDER.get(min_severity, 4)

        level_color = self.LEVEL_COLORS.get(report.risk_level, "")
        label = self.LEVEL_LABELS.get(report.risk_level, "")
        print(f"\n{'─' * 70}")
        print(f"{C.BOLD}{report.skill_name}{C.RESET}  "
              f"{level_color}[{report.risk_level}] {label}{C.RESET}  "
              f"Score: {report.risk_score}/100")
        print(f"{C.DIM}{report.skill_path}{C.RESET}")

        # File inventory
        if report.file_inventory:
            inv_parts = [f"{ext}: {n}" for ext, n in sorted(report.file_inventory.items())]
            print(f"{C.DIM}Files: {', '.join(inv_parts)}{C.RESET}")

        # Token estimate
        te = report.token_estimate
        if te.l1_skill_md > 0:
            parts = [f"L1 SKILL.md: {C.CYAN}{format_tokens(te.l1_skill_md)}{C.RESET}"]
            if te.l2_eager > 0:
                parts.append(f"L2 eager: {C.CYAN}{format_tokens(te.l2_eager)}{C.RESET}")
            if te.l2_lazy > 0:
                parts.append(f"L2 lazy: {C.CYAN}{format_tokens(te.l2_lazy)}{C.RESET}")
            parts.append(f"L3 total: {C.CYAN}{format_tokens(te.l3_total)}{C.RESET}")
            print(f"{C.DIM}Tokens:{C.RESET} {' | '.join(parts)}")
            if te.eager_files:
                print(f"{C.DIM}  eager: {', '.join(te.eager_files)}{C.RESET}")
            if te.lazy_files:
                print(f"{C.DIM}  lazy:  {', '.join(te.lazy_files)}{C.RESET}")

        # Cost estimates (multi-turn)
        if report.cost_estimates:
            costs = report.cost_estimates
            header = "  ".join(f"{C.DIM}{c.model_name[:12]:>12}{C.RESET}" for c in costs)
            light_vals  = "  ".join(f"{C.CYAN}{format_cost(c.light_cost):>12}{C.RESET}" for c in costs)
            typical_vals = "  ".join(f"{C.CYAN}{format_cost(c.typical_cost):>12}{C.RESET}" for c in costs)
            heavy_vals  = "  ".join(f"{C.CYAN}{format_cost(c.heavy_cost):>12}{C.RESET}" for c in costs)
            print(f"Cost/sess: {header}")
            print(f"  Light    {light_vals}  {C.DIM}({COST_SCENARIOS['light']}T){C.RESET}")
            print(f"  Typical  {typical_vals}  {C.DIM}({COST_SCENARIOS['typical']}T){C.RESET}")
            print(f"  Heavy    {heavy_vals}  {C.DIM}({COST_SCENARIOS['heavy']}T){C.RESET}")

        # Findings
        filtered = [f for f in report.findings if SEVERITY_ORDER.get(f.severity, 4) <= min_order]
        if not filtered:
            print(f"  {C.GREEN}No findings at or above {min_severity} level.{C.RESET}")
            return

        # Sort by severity
        filtered.sort(key=lambda f: SEVERITY_ORDER.get(f.severity, 4))

        for f in filtered:
            sev_color = self.SEVERITY_COLORS.get(f.severity, "")
            loc = f"{f.file_path}:{f.line_number}" if f.line_number > 0 else f.file_path
            print(f"  {sev_color}{f.severity:8s}{C.RESET} "
                  f"{C.DIM}{loc}{C.RESET}")
            print(f"           {f.description}")
            if f.reference and f.reference != "—":
                print(f"           {C.DIM}[{f.reference}]{C.RESET}")
            if f.remediation_zh:
                print(f"           {C.GREEN}→ {f.remediation_zh}{C.RESET}")

    def render_summary(self, reports: List[AuditReport], min_level: str = "A"):
        min_order = LEVEL_ORDER.get(min_level, 4)

        print(f"\n{'═' * 70}")
        print(f"{C.BOLD}AUDIT SUMMARY{C.RESET}")
        print(f"{'═' * 70}")

        # Count by level
        by_level = {"A": 0, "B": 0, "C": 0, "D": 0, "F": 0}
        for r in reports:
            by_level[r.risk_level] = by_level.get(r.risk_level, 0) + 1

        print(f"Total skills scanned: {C.BOLD}{len(reports)}{C.RESET}")
        for level in ["A", "B", "C", "D", "F"]:
            lc = self.LEVEL_COLORS.get(level, "")
            label = self.LEVEL_LABELS.get(level, "")
            print(f"  {lc}{level} ({label}): {by_level[level]}{C.RESET}")

        # Show filtered reports
        filtered = [r for r in reports if LEVEL_ORDER.get(r.risk_level, 4) <= min_order]
        filtered.sort(key=lambda r: (-r.risk_score, r.skill_name))

        if filtered:
            print(f"\n{C.BOLD}Skills at level {min_level} or worse:{C.RESET}")
            for r in filtered[:50]:  # Cap at 50 for terminal
                lc = self.LEVEL_COLORS.get(r.risk_level, "")
                sev_counts = {}
                for f in r.findings:
                    sev_counts[f.severity] = sev_counts.get(f.severity, 0) + 1
                sev_str = ", ".join(f"{k}:{v}" for k, v in sorted(sev_counts.items(), key=lambda x: SEVERITY_ORDER.get(x[0], 4)))
                print(f"  {lc}[{r.risk_level}]{C.RESET} {r.risk_score:3d}/100  {r.skill_name}  {C.DIM}({sev_str}){C.RESET}")

            if len(filtered) > 50:
                print(f"  {C.DIM}... and {len(filtered) - 50} more (use --json for full list){C.RESET}")


class JsonRenderer:
    """JSON output."""

    def render(self, reports: List[AuditReport], output_path: Path, target: str = ""):
        by_level = {"A": 0, "B": 0, "C": 0, "D": 0, "F": 0}
        for r in reports:
            by_level[r.risk_level] = by_level.get(r.risk_level, 0) + 1

        data = {
            "audit_metadata": {
                "tool_version": __version__,
                "timestamp": datetime.now(timezone.utc).isoformat(),
                "target": target,
            },
            "summary": {
                "total_skills": len(reports),
                "by_level": by_level,
            },
            "dimension_remediations": {k: {"zh": v[0], "en": v[1]} for k, v in DIMENSION_REMEDIATIONS.items()},
            "reports": [],
        }

        for r in reports:
            report_dict = {
                "skill_name": r.skill_name,
                "skill_path": r.skill_path,
                "risk_score": r.risk_score,
                "risk_level": r.risk_level,
                "file_inventory": r.file_inventory,
                "token_estimate": {
                    "l1_skill_md": r.token_estimate.l1_skill_md,
                    "l2_eager": r.token_estimate.l2_eager,
                    "l2_lazy": r.token_estimate.l2_lazy,
                    "l3_total": r.token_estimate.l3_total,
                    "l1_chars": r.token_estimate.l1_chars,
                    "l2_eager_chars": r.token_estimate.l2_eager_chars,
                    "l2_lazy_chars": r.token_estimate.l2_lazy_chars,
                    "l3_chars": r.token_estimate.l3_chars,
                    "eager_files": r.token_estimate.eager_files,
                    "lazy_files": r.token_estimate.lazy_files,
                },
                "dimension_summary": r.dimension_summary,
                "cost_estimates": [
                    {
                        "model": c.model_name,
                        "input_per_m": c.input_per_m,
                        "output_per_m": c.output_per_m,
                        "cache_input_per_m": c.cache_input_per_m,
                        "light_cost": round(c.light_cost, 6),
                        "typical_cost": round(c.typical_cost, 6),
                        "heavy_cost": round(c.heavy_cost, 6),
                    }
                    for c in r.cost_estimates
                ],
                "findings": [
                    {
                        "dimension": f.dimension,
                        "severity": f.severity,
                        "file_path": f.file_path,
                        "line_number": f.line_number,
                        "pattern": f.pattern,
                        "description": f.description,
                        "reference": f.reference,
                        "remediation_zh": f.remediation_zh,
                        "remediation_en": f.remediation_en,
                    }
                    for f in r.findings
                ],
            }
            data["reports"].append(report_dict)

        output_path.write_text(json.dumps(data, indent=2, ensure_ascii=False), encoding='utf-8')
        print(f"{C.GREEN}JSON report written to: {output_path}{C.RESET}")


class HtmlRenderer:
    """Self-contained HTML report — Shadcn/ui design system."""

    TEMPLATE = r"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>Security Audit Report</title>
<script>
// Prevent FOUC: apply saved theme and language before paint
(function(){
var t=localStorage.getItem('audit-theme');
if(t==='light')document.documentElement.classList.remove('dark');
else document.documentElement.classList.add('dark');
var l=localStorage.getItem('audit-lang')||'en';
document.documentElement.lang=l;
document.documentElement.dataset.lang=l;
})();
</script>
<style>
/* ── Shadcn Design Tokens — Light (default) ──────────────────────── */
:root {
  --background: 0 0% 100%;
  --foreground: 0 0% 3.9%;
  --card: 0 0% 100%;
  --card-foreground: 0 0% 3.9%;
  --popover: 0 0% 100%;
  --popover-foreground: 0 0% 3.9%;
  --primary: 0 0% 9%;
  --primary-foreground: 0 0% 98%;
  --secondary: 0 0% 96.1%;
  --secondary-foreground: 0 0% 9%;
  --muted: 0 0% 96.1%;
  --muted-foreground: 0 0% 45.1%;
  --accent: 0 0% 96.1%;
  --accent-foreground: 0 0% 9%;
  --destructive: 0 84.2% 60.2%;
  --destructive-foreground: 0 0% 98%;
  --border: 0 0% 89.8%;
  --input: 0 0% 89.8%;
  --ring: 0 0% 3.9%;
  --radius: 0.5rem;
  /* Semantic */
  --success: 142 76% 36%;
  --success-foreground: 142 76% 90%;
  --warning: 38 92% 50%;
  --warning-foreground: 38 92% 14%;
  --info: 217 91% 60%;
  --info-foreground: 217 91% 94%;
  /* Risk levels */
  --level-a: 142 71% 45%;
  --level-b: 217 91% 60%;
  --level-c: 45 93% 47%;
  --level-d: 24 95% 53%;
  --level-f: 0 84% 60%;
  /* Severity text — darker in light mode for contrast */
  --sev-critical-bg: 0 84% 60% / 0.12;
  --sev-critical-fg: 0 72% 51%;
  --sev-critical-border: 0 84% 60% / 0.25;
  --sev-high-bg: 24 95% 53% / 0.1;
  --sev-high-fg: 21 90% 48%;
  --sev-high-border: 24 95% 53% / 0.2;
  --sev-medium-bg: 45 93% 47% / 0.1;
  --sev-medium-fg: 40 85% 38%;
  --sev-medium-border: 45 93% 47% / 0.2;
  --sev-low-bg: 217 91% 60% / 0.08;
  --sev-low-fg: 217 80% 50%;
  --sev-low-border: 217 91% 60% / 0.18;
  --sev-info-bg: 0 0% 0% / 0.04;
  --sev-info-fg: 0 0% 45%;
  --sev-info-border: 0 0% 0% / 0.1;
  /* Pill colors */
  --pill-c-bg: 0 84% 60% / 0.12; --pill-c-fg: 0 72% 51%;
  --pill-h-bg: 24 95% 53% / 0.1; --pill-h-fg: 21 90% 48%;
  --pill-m-bg: 45 93% 47% / 0.1; --pill-m-fg: 40 85% 38%;
  --pill-l-bg: 217 91% 60% / 0.08; --pill-l-fg: 217 80% 50%;
  --pill-i-bg: 0 0% 0% / 0.04; --pill-i-fg: 0 0% 45%;
  /* Cell ref */
  --cell-ref: 270 60% 55%;
  /* Accordion hover shadow */
  --card-shadow: 0 0% 0% / 0.08;
}

/* ── Shadcn Design Tokens — Dark ─────────────────────────────────── */
.dark {
  --background: 0 0% 3.9%;
  --foreground: 0 0% 98%;
  --card: 0 0% 3.9%;
  --card-foreground: 0 0% 98%;
  --popover: 0 0% 3.9%;
  --popover-foreground: 0 0% 98%;
  --primary: 0 0% 98%;
  --primary-foreground: 0 0% 9%;
  --secondary: 0 0% 14.9%;
  --secondary-foreground: 0 0% 98%;
  --muted: 0 0% 14.9%;
  --muted-foreground: 0 0% 63.9%;
  --accent: 0 0% 14.9%;
  --accent-foreground: 0 0% 98%;
  --destructive: 0 62.8% 30.6%;
  --destructive-foreground: 0 0% 98%;
  --border: 0 0% 14.9%;
  --input: 0 0% 14.9%;
  --ring: 0 0% 83.1%;
  --sev-critical-bg: 0 84% 60% / 0.15;
  --sev-critical-fg: 0 84% 65%;
  --sev-critical-border: 0 84% 60% / 0.3;
  --sev-high-bg: 24 95% 53% / 0.12;
  --sev-high-fg: 24 95% 63%;
  --sev-high-border: 24 95% 53% / 0.25;
  --sev-medium-bg: 45 93% 47% / 0.12;
  --sev-medium-fg: 45 93% 60%;
  --sev-medium-border: 45 93% 47% / 0.25;
  --sev-low-bg: 217 91% 60% / 0.1;
  --sev-low-fg: 217 91% 70%;
  --sev-low-border: 217 91% 60% / 0.2;
  --sev-info-bg: 0 0% 100% / 0.06;
  --sev-info-fg: 0 0% 64%;
  --sev-info-border: 0 0% 100% / 0.1;
  --pill-c-bg: 0 84% 60% / 0.18; --pill-c-fg: 0 84% 65%;
  --pill-h-bg: 24 95% 53% / 0.15; --pill-h-fg: 24 95% 63%;
  --pill-m-bg: 45 93% 47% / 0.15; --pill-m-fg: 45 93% 60%;
  --pill-l-bg: 217 91% 60% / 0.12; --pill-l-fg: 217 91% 70%;
  --pill-i-bg: 0 0% 100% / 0.06; --pill-i-fg: 0 0% 64%;
  --cell-ref: 270 60% 70%;
  --card-shadow: 0 0% 0% / 0.15;
}

/* ── Reset & Base ────────────────────────────────────────────────── */
*, *::before, *::after { box-sizing: border-box; margin: 0; padding: 0; }
body {
  font-family: ui-sans-serif, system-ui, -apple-system, BlinkMacSystemFont,
    "Segoe UI", Roboto, "Helvetica Neue", Arial, sans-serif;
  background: hsl(var(--background));
  color: hsl(var(--foreground));
  line-height: 1.6;
  -webkit-font-smoothing: antialiased;
  -moz-osx-font-smoothing: grayscale;
}
.container { max-width: 1200px; margin: 0 auto; padding: 2rem 1.5rem; }

/* ── Typography ──────────────────────────────────────────────────── */
h1 { font-size: 1.875rem; font-weight: 700; letter-spacing: -0.025em; line-height: 1.2; color: hsl(var(--foreground)); }
h2 { font-size: 1.25rem; font-weight: 600; letter-spacing: -0.02em; color: hsl(var(--foreground)); }
h3 { font-size: 1rem; font-weight: 600; color: hsl(var(--foreground)); }
.text-muted { color: hsl(var(--muted-foreground)); }
.text-sm { font-size: 0.875rem; line-height: 1.4; }
.text-xs { font-size: 0.75rem; line-height: 1.4; }
.font-mono { font-family: ui-monospace, SFMono-Regular, "SF Mono", Menlo, Consolas, monospace; }
.font-medium { font-weight: 500; }
.font-semibold { font-weight: 600; }
.tracking-tight { letter-spacing: -0.025em; }

/* ── Layout Utilities ────────────────────────────────────────────── */
.flex { display: flex; }
.flex-col { flex-direction: column; }
.items-center { align-items: center; }
.justify-between { justify-content: space-between; }
.gap-1 { gap: 0.25rem; } .gap-1\.5 { gap: 0.375rem; }
.gap-2 { gap: 0.5rem; } .gap-3 { gap: 0.75rem; }
.gap-4 { gap: 1rem; } .gap-6 { gap: 1.5rem; }
.grid { display: grid; }
.grid-cols-5 { grid-template-columns: repeat(5, minmax(0, 1fr)); }
@media (max-width: 768px) { .grid-cols-5 { grid-template-columns: repeat(2, minmax(0, 1fr)); } }
.space-y-1 > * + * { margin-top: 0.25rem; }
.space-y-2 > * + * { margin-top: 0.5rem; }
.space-y-3 > * + * { margin-top: 0.75rem; }
.space-y-4 > * + * { margin-top: 1rem; }
.space-y-6 > * + * { margin-top: 1.5rem; }
.hidden { display: none !important; }

/* ── Header ──────────────────────────────────────────────────────── */
.page-header { padding-bottom: 1.5rem; border-bottom: 1px solid hsl(var(--border)); margin-bottom: 2rem; }
.page-header p { color: hsl(var(--muted-foreground)); font-size: 0.875rem; margin-top: 0.375rem; }
.header-meta { display: flex; gap: 1.5rem; margin-top: 0.75rem; flex-wrap: wrap; }
.header-meta span { display: inline-flex; align-items: center; gap: 0.375rem; font-size: 0.8125rem;
  color: hsl(var(--muted-foreground)); }
.header-meta svg { width: 14px; height: 14px; opacity: 0.6; }

/* ── Card ────────────────────────────────────────────────────────── */
.card { background: hsl(var(--card)); border: 1px solid hsl(var(--border));
  border-radius: var(--radius); }
.card-header { padding: 1.25rem 1.5rem 0.75rem; }
.card-content { padding: 0 1.5rem 1.25rem; }
.card-title { font-size: 0.875rem; font-weight: 600; }
.card-description { font-size: 0.8125rem; color: hsl(var(--muted-foreground)); }

/* ── Stat Card (Dashboard) ───────────────────────────────────────── */
.stat-card { position: relative; overflow: hidden; }
.stat-card .stat-value { font-size: 2rem; font-weight: 700; letter-spacing: -0.05em; line-height: 1; }
.stat-card .stat-label { font-size: 0.75rem; font-weight: 500; color: hsl(var(--muted-foreground));
  text-transform: uppercase; letter-spacing: 0.05em; margin-top: 0.25rem; }
.stat-card .stat-bar { position: absolute; bottom: 0; left: 0; right: 0; height: 3px; }
.stat-card.level-a .stat-value { color: hsl(var(--level-a)); }
.stat-card.level-a .stat-bar { background: hsl(var(--level-a)); }
.stat-card.level-b .stat-value { color: hsl(var(--level-b)); }
.stat-card.level-b .stat-bar { background: hsl(var(--level-b)); }
.stat-card.level-c .stat-value { color: hsl(var(--level-c)); }
.stat-card.level-c .stat-bar { background: hsl(var(--level-c)); }
.stat-card.level-d .stat-value { color: hsl(var(--level-d)); }
.stat-card.level-d .stat-bar { background: hsl(var(--level-d)); }
.stat-card.level-f .stat-value { color: hsl(var(--level-f)); }
.stat-card.level-f .stat-bar { background: hsl(var(--level-f)); }

/* ── Progress / Distribution Bar ─────────────────────────────────── */
.dist-bar { display: flex; height: 10px; border-radius: 9999px; overflow: hidden;
  background: hsl(var(--muted)); }
.dist-bar > div { transition: width 0.5s ease; min-width: 0; }
.dist-bar .seg-a { background: hsl(var(--level-a)); }
.dist-bar .seg-b { background: hsl(var(--level-b)); }
.dist-bar .seg-c { background: hsl(var(--level-c)); }
.dist-bar .seg-d { background: hsl(var(--level-d)); }
.dist-bar .seg-f { background: hsl(var(--level-f)); }
.dist-legend { display: flex; gap: 1rem; flex-wrap: wrap; margin-top: 0.5rem; }
.dist-legend span { display: inline-flex; align-items: center; gap: 0.375rem; font-size: 0.75rem;
  color: hsl(var(--muted-foreground)); }
.dist-legend .dot { width: 8px; height: 8px; border-radius: 9999px; flex-shrink: 0; }

/* ── Badge ───────────────────────────────────────────────────────── */
.badge { display: inline-flex; align-items: center; justify-content: center;
  border-radius: 9999px; font-size: 0.6875rem; font-weight: 600; line-height: 1;
  padding: 0.2rem 0.55rem; white-space: nowrap; border: 1px solid transparent;
  transition: background 0.15s, color 0.15s; }
.badge-level { width: 1.5rem; height: 1.5rem; padding: 0; font-size: 0.6875rem; }
.badge-a { background: hsl(var(--level-a) / 0.15); color: hsl(var(--level-a)); border-color: hsl(var(--level-a) / 0.3); }
.badge-b { background: hsl(var(--level-b) / 0.15); color: hsl(var(--level-b)); border-color: hsl(var(--level-b) / 0.3); }
.badge-c { background: hsl(var(--level-c) / 0.15); color: hsl(var(--level-c)); border-color: hsl(var(--level-c) / 0.3); }
.badge-d { background: hsl(var(--level-d) / 0.15); color: hsl(var(--level-d)); border-color: hsl(var(--level-d) / 0.3); }
.badge-f { background: hsl(var(--level-f) / 0.15); color: hsl(var(--level-f)); border-color: hsl(var(--level-f) / 0.3); }
/* Severity badges */
.sev { display: inline-flex; align-items: center; border-radius: 9999px; font-size: 0.6875rem;
  font-weight: 600; padding: 0.15rem 0.5rem; line-height: 1.2; border: 1px solid transparent; }
.sev-CRITICAL { background: hsl(var(--sev-critical-bg)); color: hsl(var(--sev-critical-fg)); border-color: hsl(var(--sev-critical-border)); }
.sev-HIGH { background: hsl(var(--sev-high-bg)); color: hsl(var(--sev-high-fg)); border-color: hsl(var(--sev-high-border)); }
.sev-MEDIUM { background: hsl(var(--sev-medium-bg)); color: hsl(var(--sev-medium-fg)); border-color: hsl(var(--sev-medium-border)); }
.sev-LOW { background: hsl(var(--sev-low-bg)); color: hsl(var(--sev-low-fg)); border-color: hsl(var(--sev-low-border)); }
.sev-INFO { background: hsl(var(--sev-info-bg)); color: hsl(var(--sev-info-fg)); border-color: hsl(var(--sev-info-border)); }

/* ── Score Ring (CSS-only) ───────────────────────────────────────── */
.score-ring { position: relative; width: 36px; height: 36px; flex-shrink: 0; }
.score-ring svg { width: 36px; height: 36px; transform: rotate(-90deg); }
.score-ring circle { fill: none; stroke-width: 3; }
.score-ring .ring-bg { stroke: hsl(var(--muted)); }
.score-ring .ring-fg { stroke-linecap: round; transition: stroke-dashoffset 0.5s ease; }
.score-ring .ring-label { position: absolute; inset: 0; display: flex; align-items: center;
  justify-content: center; font-size: 0.625rem; font-weight: 700; }

/* ── Input ───────────────────────────────────────────────────────── */
.input { width: 100%; height: 2.5rem; padding: 0 0.75rem; font-size: 0.875rem;
  background: hsl(var(--background)); color: hsl(var(--foreground));
  border: 1px solid hsl(var(--border)); border-radius: var(--radius);
  outline: none; transition: border-color 0.15s, box-shadow 0.15s; }
.input::placeholder { color: hsl(var(--muted-foreground)); }
.input:focus { border-color: hsl(var(--ring)); box-shadow: 0 0 0 2px hsl(var(--ring) / 0.15); }
.search-wrap { position: relative; }
.search-wrap svg { position: absolute; left: 0.75rem; top: 50%; transform: translateY(-50%);
  width: 16px; height: 16px; color: hsl(var(--muted-foreground)); pointer-events: none; }
.search-wrap .input { padding-left: 2.25rem; }

/* ── Tabs ────────────────────────────────────────────────────────── */
.tabs { display: inline-flex; background: hsl(var(--muted)); border-radius: var(--radius);
  padding: 0.25rem; gap: 0.125rem; }
.tab-btn { display: inline-flex; align-items: center; justify-content: center; gap: 0.375rem;
  padding: 0.375rem 0.75rem; font-size: 0.8125rem; font-weight: 500; border: none;
  border-radius: calc(var(--radius) - 2px); cursor: pointer; white-space: nowrap;
  background: transparent; color: hsl(var(--muted-foreground));
  transition: background 0.15s, color 0.15s, box-shadow 0.15s; }
.tab-btn:hover { color: hsl(var(--foreground)); }
.tab-btn.active { background: hsl(var(--background)); color: hsl(var(--foreground));
  box-shadow: 0 1px 3px hsl(var(--card-shadow)); }
.tab-count { font-size: 0.6875rem; font-weight: 600; opacity: 0.7; }

/* ── Accordion (Skill list) ──────────────────────────────────────── */
.accordion { display: flex; flex-direction: column; }
.accordion-item { border: 1px solid hsl(var(--border)); border-radius: var(--radius);
  background: hsl(var(--card)); overflow: hidden; transition: box-shadow 0.15s; }
.accordion-item:hover { box-shadow: 0 1px 3px hsl(var(--card-shadow)); }
.accordion-trigger { width: 100%; display: flex; align-items: center; justify-content: space-between;
  padding: 0.75rem 1rem; cursor: pointer; border: none; background: none;
  color: hsl(var(--foreground)); text-align: left; font: inherit;
  transition: background 0.1s; gap: 0.75rem; }
.accordion-trigger:hover { background: hsl(var(--accent) / 0.5); }
.accordion-trigger .chevron { width: 16px; height: 16px; flex-shrink: 0;
  color: hsl(var(--muted-foreground)); transition: transform 0.2s ease; }
.accordion-item.open .accordion-trigger .chevron { transform: rotate(180deg); }
.accordion-trigger-left { display: flex; align-items: center; gap: 0.625rem; min-width: 0; }
.accordion-trigger-right { display: flex; align-items: center; gap: 0.75rem; flex-shrink: 0; }
.skill-name { font-weight: 500; font-size: 0.875rem; white-space: nowrap; overflow: hidden;
  text-overflow: ellipsis; }
.sev-pills { display: flex; gap: 0.25rem; }
.sev-pill { display: inline-flex; align-items: center; justify-content: center; font-size: 0.625rem;
  font-weight: 600; padding: 0.1rem 0.35rem; border-radius: 9999px; min-width: 1.25rem;
  line-height: 1.3; }
.pill-C { background: hsl(var(--pill-c-bg)); color: hsl(var(--pill-c-fg)); }
.pill-H { background: hsl(var(--pill-h-bg)); color: hsl(var(--pill-h-fg)); }
.pill-M { background: hsl(var(--pill-m-bg)); color: hsl(var(--pill-m-fg)); }
.pill-L { background: hsl(var(--pill-l-bg)); color: hsl(var(--pill-l-fg)); }
.pill-I { background: hsl(var(--pill-i-bg)); color: hsl(var(--pill-i-fg)); }
.accordion-content { display: none; border-top: 1px solid hsl(var(--border)); }
.accordion-item.open .accordion-content { display: block; }
.accordion-inner { padding: 1rem; }

/* ── Data Table ──────────────────────────────────────────────────── */
.data-table { width: 100%; border-collapse: collapse; font-size: 0.8125rem; }
.data-table th { text-align: left; font-weight: 500; color: hsl(var(--muted-foreground));
  padding: 0.5rem 0.75rem; border-bottom: 1px solid hsl(var(--border));
  font-size: 0.75rem; text-transform: uppercase; letter-spacing: 0.04em; }
.data-table td { padding: 0.5rem 0.75rem; border-bottom: 1px solid hsl(var(--border) / 0.5);
  vertical-align: top; color: hsl(var(--foreground)); }
.data-table tbody tr { transition: background 0.1s; }
.data-table tbody tr:hover { background: hsl(var(--muted) / 0.3); }
.data-table tbody tr:last-child td { border-bottom: none; }
.cell-loc { font-family: ui-monospace, SFMono-Regular, Menlo, monospace; font-size: 0.75rem;
  color: hsl(var(--muted-foreground)); }
.cell-ref { font-size: 0.6875rem; color: hsl(var(--cell-ref)); white-space: nowrap; }
.cell-dim { max-width: 200px; overflow: hidden; text-overflow: ellipsis; white-space: nowrap; }
.cell-remediation { font-size: 0.75rem; color: hsl(var(--success)); padding: 0.25rem 0.75rem 0.5rem 0.75rem;
  background: hsl(var(--success) / 0.06); border-bottom: 1px solid hsl(var(--border) / 0.5); }
.cell-remediation::before { content: "\2192\00a0"; font-weight: 600; }

/* ── Top 10 List ─────────────────────────────────────────────────── */
.top-list { counter-reset: topitem; }
.top-item { display: flex; align-items: center; gap: 0.75rem; padding: 0.625rem 0;
  border-bottom: 1px solid hsl(var(--border) / 0.5); }
.top-item:last-child { border-bottom: none; }
.top-rank { width: 1.5rem; height: 1.5rem; display: flex; align-items: center; justify-content: center;
  font-size: 0.6875rem; font-weight: 700; border-radius: var(--radius);
  background: hsl(var(--muted)); color: hsl(var(--muted-foreground)); flex-shrink: 0; }
.top-item:nth-child(-n+3) .top-rank { background: hsl(var(--level-f) / 0.15); color: hsl(var(--level-f)); }
.top-name { font-weight: 500; font-size: 0.875rem; min-width: 0; overflow: hidden;
  text-overflow: ellipsis; white-space: nowrap; flex: 1; }
.top-stats { display: flex; align-items: center; gap: 0.5rem; flex-shrink: 0; }

/* ── No Findings State ───────────────────────────────────────────── */
.empty-state { display: flex; flex-direction: column; align-items: center; justify-content: center;
  padding: 2rem; color: hsl(var(--muted-foreground)); gap: 0.5rem; }
.empty-state svg { width: 32px; height: 32px; opacity: 0.4; }

/* ── Token Estimate ──────────────────────────────────────────────── */
.token-bar { display: flex; flex-direction: column; gap: 0.25rem; margin-bottom: 0.75rem;
  padding: 0.625rem 0.75rem; background: hsl(var(--muted) / 0.4); border-radius: var(--radius); }
.token-chip { display: flex; align-items: baseline; gap: 0.3rem; font-size: 0.75rem;
  color: hsl(var(--muted-foreground)); }
.token-chip b { color: hsl(var(--foreground)); font-weight: 600; }
.token-dot { width: 7px; height: 7px; border-radius: 9999px; flex-shrink: 0; position: relative; top: -1px; }
.token-chip-label { display: inline-block; width: 7em; flex-shrink: 0; }
.token-chip-val { display: inline-block; width: 7em; flex-shrink: 0; }
.dot-l1 { background: hsl(var(--info)); }
.dot-eager { background: hsl(var(--warning)); }
.dot-lazy { background: hsl(var(--muted-foreground)); }
.dot-l3 { background: hsl(var(--border)); }
.token-refs { font-size: 0.6875rem; opacity: 0.7; }
.token-label { font-size: 0.6875rem; color: hsl(var(--muted-foreground)); opacity: 0.8;
  font-family: ui-monospace, SFMono-Regular, Menlo, monospace; margin-left: 0.375rem; }

/* ── Token Overview (Dashboard) ──────────────────────────────────── */
.token-overview { display: flex; flex-direction: column; gap: 1.25rem; }
.token-ov-grid { display: grid; grid-template-columns: repeat(5, 1fr); gap: 1rem; }
@media (max-width: 768px) { .token-ov-grid { grid-template-columns: repeat(2, 1fr); } }
.token-ov-stat { text-align: center; }
.token-ov-value { font-size: 1.5rem; font-weight: 700; letter-spacing: -0.03em;
  color: hsl(var(--foreground)); line-height: 1.2; }
.token-ov-label { font-size: 0.6875rem; color: hsl(var(--muted-foreground));
  margin-top: 0.125rem; }
.token-ov-breakdown { display: flex; flex-direction: column; gap: 0.5rem; }
.token-ov-bar-wrap { display: grid; grid-template-columns: 100px 1fr 70px; gap: 0.5rem;
  align-items: center; font-size: 0.75rem; }
.token-ov-bar-label { display: flex; align-items: center; gap: 0.375rem;
  color: hsl(var(--muted-foreground)); white-space: nowrap; }
.token-ov-bar-track { height: 8px; border-radius: 9999px; background: hsl(var(--muted) / 0.5);
  overflow: hidden; }
.token-ov-bar-fill { height: 100%; border-radius: 9999px; transition: width 0.5s ease; }
.bar-l1 { background: hsl(var(--info)); }
.bar-eager { background: hsl(var(--warning)); }
.bar-lazy { background: hsl(var(--muted-foreground)); }
.bar-l3 { background: hsl(var(--border)); }
.token-ov-bar-val { text-align: right; font-weight: 600; color: hsl(var(--foreground));
  font-family: ui-monospace, SFMono-Regular, Menlo, monospace; font-size: 0.75rem; }
.token-ov-top5 { }
.token-ov-top5-title { font-size: 0.75rem; font-weight: 500; color: hsl(var(--muted-foreground));
  margin-bottom: 0.375rem; }
.token-ov-top5-item { display: flex; align-items: center; gap: 0.5rem; padding: 0.3rem 0;
  font-size: 0.8125rem; border-bottom: 1px solid hsl(var(--border) / 0.3); }
.token-ov-top5-item:last-child { border-bottom: none; }
.token-ov-top5-name { flex: 1; overflow: hidden; text-overflow: ellipsis; white-space: nowrap;
  font-weight: 500; }
.token-ov-top5-val { font-family: ui-monospace, SFMono-Regular, Menlo, monospace;
  font-size: 0.75rem; font-weight: 600; color: hsl(var(--foreground)); flex-shrink: 0; }
.token-ov-top5-detail { font-size: 0.6875rem; color: hsl(var(--muted-foreground)); flex-shrink: 0; }

/* ── Cost Table ──────────────────────────────────────────────────── */
.cost-mini { margin-bottom: 0.75rem; }
.cost-table { max-width: 560px; }
.cost-table th { font-size: 0.6875rem; }
.cell-cost { font-family: ui-monospace, SFMono-Regular, Menlo, monospace; font-size: 0.8125rem;
  font-weight: 500; text-align: right; white-space: nowrap; }
.cost-ov-grid { display: grid; grid-template-columns: repeat(4, 1fr); gap: 0.75rem; margin-bottom: 1rem; }
@media (max-width: 768px) { .cost-ov-grid { grid-template-columns: repeat(2, 1fr); } }
.cost-ov-card { padding: 0.75rem; border: 1px solid hsl(var(--border)); border-radius: var(--radius);
  text-align: center; }
.cost-ov-model { font-size: 0.75rem; font-weight: 600; color: hsl(var(--foreground));
  margin-bottom: 0.125rem; display: flex; align-items: center; justify-content: center; gap: 6px; }
.cost-ov-icon { display: inline-flex; align-items: center; flex-shrink: 0; line-height: 1; }
.cost-ov-icon svg { width: 1em; height: 1em; }
.cost-model-cell { display: flex; align-items: center; gap: 6px; }
.cost-ov-provider { font-size: 0.625rem; color: hsl(var(--muted-foreground)); margin-bottom: 0.375rem; }
.cost-ov-price { font-size: 0.6875rem; color: hsl(var(--muted-foreground)); line-height: 1.5; }
.cost-ov-price b { color: hsl(var(--foreground)); }
.cost-ov-total { font-size: 1.125rem; font-weight: 700; margin-top: 0.25rem; letter-spacing: -0.02em; }
.cost-ov-total-label { font-size: 0.625rem; color: hsl(var(--muted-foreground)); }
.cost-note { font-size: 0.6875rem; color: hsl(var(--muted-foreground)); margin-top: 0.5rem;
  padding: 0.5rem 0.625rem; background: hsl(var(--muted) / 0.3); border-radius: var(--radius);
  line-height: 1.5; }

/* ── Section Divider ─────────────────────────────────────────────── */
.section { margin-bottom: 2rem; }
.section-header { display: flex; align-items: center; justify-content: space-between;
  margin-bottom: 0.75rem; flex-wrap: wrap; gap: 0.5rem; }

/* ── Responsive ──────────────────────────────────────────────────── */
@media (max-width: 640px) {
  .container { padding: 1rem; }
  .accordion-trigger { padding: 0.625rem 0.75rem; }
  .data-table { font-size: 0.75rem; }
  .cell-dim { max-width: 120px; }
  h1 { font-size: 1.5rem; }
  .sev-pills { display: none; }
}

/* ── Theme Toggle ────────────────────────────────────────────────── */
.theme-toggle { display: inline-flex; align-items: center; justify-content: center;
  width: 2.25rem; height: 2.25rem; border-radius: var(--radius); border: 1px solid hsl(var(--border));
  background: hsl(var(--card)); color: hsl(var(--muted-foreground)); cursor: pointer;
  transition: background 0.15s, color 0.15s, border-color 0.15s; flex-shrink: 0; }
.theme-toggle:hover { background: hsl(var(--accent)); color: hsl(var(--accent-foreground));
  border-color: hsl(var(--ring) / 0.3); }
.theme-toggle svg { width: 16px; height: 16px; }
.theme-toggle .icon-sun { display: none; }
.theme-toggle .icon-moon { display: block; }
.dark .theme-toggle .icon-sun { display: block; }
.dark .theme-toggle .icon-moon { display: none; }

/* ── Language Toggle ─────────────────────────────────────────────── */
.lang-toggle { display: inline-flex; align-items: center; justify-content: center;
  width: 2.25rem; height: 2.25rem; border-radius: var(--radius); border: 1px solid hsl(var(--border));
  background: hsl(var(--card)); color: hsl(var(--muted-foreground)); cursor: pointer;
  transition: background 0.15s, color 0.15s, border-color 0.15s; flex-shrink: 0;
  font-size: 0.6875rem; font-weight: 700; letter-spacing: 0.02em; }
.lang-toggle:hover { background: hsl(var(--accent)); color: hsl(var(--accent-foreground));
  border-color: hsl(var(--ring) / 0.3); }

/* ── Nav Link ────────────────────────────────────────────────────── */
.nav-link { font-size: 0.8125rem; font-weight: 500; padding: 0.375rem 0.75rem;
  border: 1px solid hsl(var(--border)); border-radius: var(--radius);
  color: hsl(var(--foreground)); text-decoration: none; display: inline-flex; align-items: center;
  transition: background 0.15s; white-space: nowrap; }
.nav-link:hover { background: hsl(var(--accent)); }

/* i18n: hide non-active language spans */
[data-lang="zh"] [data-i18n-en] { display: none !important; }
[data-lang="en"] [data-i18n-zh] { display: none !important; }
[data-lang="zh"] .i18n-en { display: none !important; }
[data-lang="en"] .i18n-zh { display: none !important; }
</style>
</head>
<body>
<div class="container">

<!-- Header -->
<div class="page-header">
  <div class="flex items-center justify-between">
    <div>
      <h1 class="tracking-tight"><span data-i18n-zh>安全审计报告</span><span data-i18n-en>Security Audit Report</span></h1>
      <p><span data-i18n-zh>基于 10 个维度的标准化 Skill 安全分析</span><span data-i18n-en>Standardized skill security analysis across 10 dimensions</span></p>
    </div>
    <div class="flex gap-2">
      <a class="nav-link" href="$methodology_filename"><span data-i18n-zh>方法论</span><span data-i18n-en>Methodology</span></a>
      <button class="lang-toggle" id="langToggle" title="Toggle language" aria-label="Toggle Chinese/English"><span data-i18n-zh>EN</span><span data-i18n-en>CN</span></button>
      <button class="theme-toggle" id="themeToggle" title="Toggle theme" aria-label="Toggle light/dark theme">
        <svg class="icon-sun" xmlns="http://www.w3.org/2000/svg" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><circle cx="12" cy="12" r="5"/><line x1="12" y1="1" x2="12" y2="3"/><line x1="12" y1="21" x2="12" y2="23"/><line x1="4.22" y1="4.22" x2="5.64" y2="5.64"/><line x1="18.36" y1="18.36" x2="19.78" y2="19.78"/><line x1="1" y1="12" x2="3" y2="12"/><line x1="21" y1="12" x2="23" y2="12"/><line x1="4.22" y1="19.78" x2="5.64" y2="18.36"/><line x1="18.36" y1="5.64" x2="19.78" y2="4.22"/></svg>
        <svg class="icon-moon" xmlns="http://www.w3.org/2000/svg" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="M21 12.79A9 9 0 1 1 11.21 3 7 7 0 0 0 21 12.79z"/></svg>
      </button>
    </div>
  </div>
  <div class="header-meta">
    <span>
      <svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><rect width="18" height="18" x="3" y="4" rx="2" ry="2"/><line x1="16" x2="16" y1="2" y2="6"/><line x1="8" x2="8" y1="2" y2="6"/><line x1="3" x2="21" y1="10" y2="10"/></svg>
      $timestamp
    </span>
    <span>
      <svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z"/></svg>
      v$version
    </span>
    <span>
      <svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="M4 20h16a2 2 0 0 0 2-2V8a2 2 0 0 0-2-2h-7.93a2 2 0 0 1-1.66-.9l-.82-1.2A2 2 0 0 0 7.93 3H4a2 2 0 0 0-2 2v13c0 1.1.9 2 2 2Z"/></svg>
      $target
    </span>
    <span>
      <svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="M16 21v-2a4 4 0 0 0-4-4H6a4 4 0 0 0-4 4v2"/><circle cx="9" cy="7" r="4"/><path d="M22 21v-2a4 4 0 0 0-3-3.87"/><path d="M16 3.13a4 4 0 0 1 0 7.75"/></svg>
      $total <span data-i18n-zh>技能</span><span data-i18n-en>skills</span>    </span>
  </div>
</div>

<!-- Dashboard Stats -->
<div class="section">
  <div class="grid grid-cols-5 gap-3">
    <div class="card stat-card level-a">
      <div class="card-header"><div class="stat-label"><span data-i18n-zh>A · 安全</span><span data-i18n-en>A &middot; Safe</span></div></div>
      <div class="card-content"><div class="stat-value">$count_a</div></div>
      <div class="stat-bar"></div>
    </div>
    <div class="card stat-card level-b">
      <div class="card-header"><div class="stat-label"><span data-i18n-zh>B · 可接受</span><span data-i18n-en>B &middot; Acceptable</span></div></div>
      <div class="card-content"><div class="stat-value">$count_b</div></div>
      <div class="stat-bar"></div>
    </div>
    <div class="card stat-card level-c">
      <div class="card-header"><div class="stat-label"><span data-i18n-zh>C · 警告</span><span data-i18n-en>C &middot; Warning</span></div></div>
      <div class="card-content"><div class="stat-value">$count_c</div></div>
      <div class="stat-bar"></div>
    </div>
    <div class="card stat-card level-d">
      <div class="card-header"><div class="stat-label"><span data-i18n-zh>D · 不安全</span><span data-i18n-en>D &middot; Unsafe</span></div></div>
      <div class="card-content"><div class="stat-value">$count_d</div></div>
      <div class="stat-bar"></div>
    </div>
    <div class="card stat-card level-f">
      <div class="card-header"><div class="stat-label"><span data-i18n-zh>F · 危险</span><span data-i18n-en>F &middot; Dangerous</span></div></div>
      <div class="card-content"><div class="stat-value">$count_f</div></div>
      <div class="stat-bar"></div>
    </div>
  </div>
</div>

<!-- Distribution Bar -->
<div class="section">
  <div class="card">
    <div class="card-header"><div class="card-title"><span data-i18n-zh>风险分布</span><span data-i18n-en>Risk Distribution</span></div></div>
    <div class="card-content">
      <div class="dist-bar">
        <div class="seg-a" style="width:${pct_a}%"></div>
        <div class="seg-b" style="width:${pct_b}%"></div>
        <div class="seg-c" style="width:${pct_c}%"></div>
        <div class="seg-d" style="width:${pct_d}%"></div>
        <div class="seg-f" style="width:${pct_f}%"></div>
      </div>
      <div class="dist-legend">
        <span><span class="dot" style="background:hsl(var(--level-a))"></span>A ${pct_a}%</span>
        <span><span class="dot" style="background:hsl(var(--level-b))"></span>B ${pct_b}%</span>
        <span><span class="dot" style="background:hsl(var(--level-c))"></span>C ${pct_c}%</span>
        <span><span class="dot" style="background:hsl(var(--level-d))"></span>D ${pct_d}%</span>
        <span><span class="dot" style="background:hsl(var(--level-f))"></span>F ${pct_f}%</span>
      </div>
    </div>
  </div>
</div>

<!-- Token Overview -->
<div class="section">
  <div class="card">
    <div class="card-header"><div class="card-title"><span data-i18n-zh>预估 Token 消耗</span><span data-i18n-en>Estimated Token Consumption</span></div></div>
    <div class="card-content">
      <div class="token-overview">
        <div class="token-ov-grid">
          <div class="token-ov-stat">
            <div class="token-ov-value">${tok_total_l1l2}</div>
            <div class="token-ov-label"><span data-i18n-zh>L1+L2 合计</span><span data-i18n-en>Total L1+L2</span></div>
          </div>
          <div class="token-ov-stat">
            <div class="token-ov-value">${tok_total_l3}</div>
            <div class="token-ov-label"><span data-i18n-zh>L3 合计 (最大值)</span><span data-i18n-en>Total L3 (max)</span></div>
          </div>
          <div class="token-ov-stat">
            <div class="token-ov-value">${tok_avg}</div>
            <div class="token-ov-label"><span data-i18n-zh>平均 L1+L2 / 技能</span><span data-i18n-en>Avg L1+L2 / skill</span></div>
          </div>
          <div class="token-ov-stat">
            <div class="token-ov-value">${tok_median}</div>
            <div class="token-ov-label"><span data-i18n-zh>中位数 L1+L2</span><span data-i18n-en>Median L1+L2</span></div>
          </div>
          <div class="token-ov-stat">
            <div class="token-ov-value">${tok_max}</div>
            <div class="token-ov-label"><span data-i18n-zh>单技能最大值</span><span data-i18n-en>Max single skill</span></div>
          </div>
        </div>
        <div class="token-ov-breakdown">
          <div class="token-ov-bar-wrap">
            <div class="token-ov-bar-label"><span class="token-dot dot-l1"></span> L1 SKILL.md</div>
            <div class="token-ov-bar-track"><div class="token-ov-bar-fill bar-l1" style="width:${tok_pct_l1}%"></div></div>
            <div class="token-ov-bar-val">${tok_sum_l1}</div>
          </div>
          <div class="token-ov-bar-wrap">
            <div class="token-ov-bar-label"><span class="token-dot dot-eager"></span> L2 Eager</div>
            <div class="token-ov-bar-track"><div class="token-ov-bar-fill bar-eager" style="width:${tok_pct_eager}%"></div></div>
            <div class="token-ov-bar-val">${tok_sum_eager}</div>
          </div>
          <div class="token-ov-bar-wrap">
            <div class="token-ov-bar-label"><span class="token-dot dot-lazy"></span> L2 Lazy</div>
            <div class="token-ov-bar-track"><div class="token-ov-bar-fill bar-lazy" style="width:${tok_pct_lazy}%"></div></div>
            <div class="token-ov-bar-val">${tok_sum_lazy}</div>
          </div>
          <div class="token-ov-bar-wrap">
            <div class="token-ov-bar-label"><span class="token-dot dot-l3"></span> L3 All files</div>
            <div class="token-ov-bar-track"><div class="token-ov-bar-fill bar-l3" style="width:${tok_pct_l3}%"></div></div>
            <div class="token-ov-bar-val">${tok_sum_l3}</div>
          </div>
        </div>
        <div class="token-ov-top5">
          <div class="token-ov-top5-title"><span data-i18n-zh>Token 消耗 Top 5 (L1+L2)</span><span data-i18n-en>Top 5 Token Consumers (L1+L2)</span></div>
          $tok_top5
        </div>
      </div>
    </div>
  </div>
</div>

<!-- Cost Overview -->
<div class="section">
  <div class="card">
    <div class="card-header"><div class="card-title"><span data-i18n-zh>预估每次调用成本 (输入 Token)</span><span data-i18n-en>Estimated Cost per Invocation (Input Tokens)</span></div></div>
    <div class="card-content">
      <div class="cost-ov-grid">$cost_ov_cards</div>
      <div class="cost-note"><span data-i18n-zh><b>多轮会话成本</b>估算（含 Prompt 缓存 + 输出 Token + 上下文累积）。轻度 = 3 轮、典型 = 6 轮、重度 = 15 轮。L1 (SKILL.md) 首轮注入后缓存，L2 文件在前 3 轮渐进加载。每轮假设输出 500 tokens。</span><span data-i18n-en><b>Multi-turn session cost</b> estimates (with prompt caching + output tokens + context accumulation). Light = 3 turns, Typical = 6 turns, Heavy = 15 turns. L1 (SKILL.md) is cached after first turn; L2 files are progressively loaded in the first 3 turns. Assumes 500 output tokens per turn.</span></div>
    </div>
  </div>
</div>

<!-- Top 10 -->
<div class="section">
  <div class="card">
    <div class="card-header"><div class="card-title"><span data-i18n-zh>风险最高 Top 10</span><span data-i18n-en>Top 10 Highest Risk</span></div></div>
    <div class="card-content">
      <div class="top-list">$top10</div>
    </div>
  </div>
</div>

<!-- Skill List -->
<div class="section">
  <div class="section-header">
    <h2 class="tracking-tight"><span data-i18n-zh>所有技能</span><span data-i18n-en>All Skills</span></h2>
    <span class="text-sm text-muted" id="visibleCount">$total <span data-i18n-zh>技能</span><span data-i18n-en>skills</span></span>
  </div>

  <div class="flex gap-3" style="margin-bottom:0.75rem; flex-wrap:wrap; align-items:center;">
    <div class="search-wrap" style="flex:1; min-width:200px;">
      <svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><circle cx="11" cy="11" r="8"/><path d="m21 21-4.3-4.3"/></svg>
      <input class="input" type="text" data-placeholder-zh="搜索技能…" data-placeholder-en="Search skills..." placeholder="Search skills..." id="searchBox">
    </div>
    <div class="tabs" id="levelTabs">
      <button class="tab-btn active" data-level="all"><span data-i18n-zh>全部</span><span data-i18n-en>All</span> <span class="tab-count">$total</span></button>
      <button class="tab-btn" data-level="F">F <span class="tab-count">$count_f</span></button>
      <button class="tab-btn" data-level="D">D <span class="tab-count">$count_d</span></button>
      <button class="tab-btn" data-level="C">C <span class="tab-count">$count_c</span></button>
      <button class="tab-btn" data-level="B">B <span class="tab-count">$count_b</span></button>
      <button class="tab-btn" data-level="A">A <span class="tab-count">$count_a</span></button>
    </div>
  </div>

  <div class="accordion space-y-2" id="skillList">
$skill_cards
  </div>
</div>

</div><!-- /container -->

<script>
(function(){
  var html=document.documentElement;
  // Theme toggle
  var toggle=document.getElementById('themeToggle');
  toggle.addEventListener('click',function(){
    var isDark=html.classList.toggle('dark');
    localStorage.setItem('audit-theme',isDark?'dark':'light');
  });
  // Language toggle
  var langBtn=document.getElementById('langToggle');
  function setLang(lang){
    html.lang=lang; html.dataset.lang=lang;
    localStorage.setItem('audit-lang',lang);
    // Update search placeholder
    var sb=document.getElementById('searchBox');
    if(sb)sb.placeholder=sb.getAttribute('data-placeholder-'+lang)||sb.placeholder;
    // Update visible count suffix
    updateVisibleCount();
  }
  langBtn.addEventListener('click',function(){
    setLang(html.dataset.lang==='zh'?'en':'zh');
  });
  // Init lang
  setLang(html.dataset.lang||'en');
  // Accordion
  document.querySelectorAll('.accordion-trigger').forEach(function(t){
    t.addEventListener('click',function(){t.closest('.accordion-item').classList.toggle('open');});
  });
  // Tabs
  var tabs=document.querySelectorAll('#levelTabs .tab-btn');
  var currentLevel='all';
  tabs.forEach(function(btn){
    btn.addEventListener('click',function(){
      tabs.forEach(function(b){b.classList.remove('active');});
      btn.classList.add('active');
      currentLevel=btn.dataset.level;
      applyFilters();
    });
  });
  // Search
  var searchBox=document.getElementById('searchBox');
  var searchQuery='';
  searchBox.addEventListener('input',function(e){searchQuery=e.target.value.toLowerCase();applyFilters();});
  function updateVisibleCount(){
    var visible=document.querySelectorAll('.accordion-item:not(.hidden)').length;
    var lang=html.dataset.lang||'en';
    var suffix=lang==='zh'?' 技能':' skills';
    document.getElementById('visibleCount').textContent=visible+suffix;
  }
  function applyFilters(){
    document.querySelectorAll('.accordion-item').forEach(function(item){
      var name=item.dataset.name.toLowerCase();
      var level=item.dataset.level;
      var matchLevel=(currentLevel==='all'||level===currentLevel);
      var matchSearch=(!searchQuery||name.includes(searchQuery));
      if(matchLevel&&matchSearch){item.classList.remove('hidden');}
      else{item.classList.add('hidden');}
    });
    updateVisibleCount();
  }
})();
</script>
</body>
</html>"""

    def render_methodology(self, output_path: Path, report_filename: str = ""):
        """Generate a standalone methodology page explaining audit dimensions, rules, and cost model."""
        esc = html_module.escape

        # ── Build dimensions table ──
        dim_rows = []
        for i, (zh_name, en_name, ref) in enumerate(SkillAuditor.DIMENSIONS, 1):
            dim_rem_zh, dim_rem_en = DIMENSION_REMEDIATIONS.get(en_name, ("", ""))
            dim_rows.append(
                f'<tr>'
                f'<td class="font-mono" style="text-align:center">{i}</td>'
                f'<td><span data-i18n-zh>{esc(zh_name)}</span><span data-i18n-en>{esc(en_name)}</span></td>'
                f'<td class="cell-ref">{esc(ref)}</td>'
                f'<td class="text-sm"><span data-i18n-zh>{esc(dim_rem_zh)}</span><span data-i18n-en>{esc(dim_rem_en)}</span></td>'
                f'</tr>'
            )
        dim_table = '\n'.join(dim_rows)

        # ── Build remediation rules table (grouped by category) ──
        import re as _re
        # Read the source to extract category comments
        try:
            src = Path(__file__).read_text(encoding='utf-8')
        except Exception:
            src = ""
        # Parse REMEDIATIONS block to get category groupings
        rem_start = src.find('\nREMEDIATIONS = {')
        rem_end = src.find('\n}', rem_start) + 2 if rem_start >= 0 else 0
        rem_block = src[rem_start:rem_end] if rem_start >= 0 else ""

        categories = []
        current_cat = "Other"
        current_items = []
        for line in rem_block.split('\n'):
            cm = _re.match(r'\s*#\s*(.+)', line)
            if cm:
                if current_items:
                    categories.append((current_cat, list(current_items)))
                    current_items = []
                current_cat = cm.group(1).strip()
                continue
            rm = _re.match(r'\s*"(.+?)"\s*:', line)
            if rm:
                key = rm.group(1)
                pair = REMEDIATIONS.get(key)
                if pair:
                    current_items.append((key, pair[0], pair[1]))
        if current_items:
            categories.append((current_cat, list(current_items)))

        rule_sections = []
        idx = 0
        for cat, items in categories:
            rows = []
            for key, zh, en in items:
                idx += 1
                rows.append(
                    f'<tr>'
                    f'<td class="font-mono text-xs" style="text-align:center">{idx}</td>'
                    f'<td class="font-mono text-xs">{esc(key)}</td>'
                    f'<td class="text-sm"><span data-i18n-zh>{esc(zh)}</span><span data-i18n-en>{esc(en)}</span></td>'
                    f'</tr>'
                )
            rule_sections.append(
                f'<div class="card" style="margin-bottom:1rem">'
                f'<div class="card-header"><div class="card-title">{esc(cat)} ({len(items)})</div></div>'
                f'<div class="card-content">'
                f'<table class="data-table"><thead><tr>'
                f'<th style="width:40px">#</th>'
                f'<th style="width:220px"><span data-i18n-zh>匹配关键词</span><span data-i18n-en>Match Keyword</span></th>'
                f'<th><span data-i18n-zh>修复建议</span><span data-i18n-en>Remediation</span></th>'
                f'</tr></thead><tbody>\n' + '\n'.join(rows) + '\n</tbody></table>'
                f'</div></div>'
            )
        rules_html = '\n'.join(rule_sections)

        # ── Build cost model section ──
        model_rows = []
        for mp in MODEL_CATALOG:
            icon_html = f'<span class="cost-ov-icon">{mp.icon_svg}</span>' if mp.icon_svg else ""
            model_rows.append(
                f'<tr>'
                f'<td><div class="cost-model-cell">{icon_html}<span class="font-medium">{esc(mp.name)}</span></div></td>'
                f'<td>{esc(mp.provider)}</td>'
                f'<td class="cell-cost">${mp.input_per_m}</td>'
                f'<td class="cell-cost">${mp.output_per_m}</td>'
                f'<td class="cell-cost">${mp.cache_input_per_m}</td>'
                f'<td class="font-mono text-xs">{mp.context_k}K</td>'
                f'</tr>'
            )
        model_table = '\n'.join(model_rows)

        # ── Risk scoring table ──
        scoring_rows = []
        for sev, score in SEVERITY_SCORES.items():
            scoring_rows.append(f'<tr><td><span class="sev sev-{sev}">{sev}</span></td><td class="cell-cost">{score}</td></tr>')
        scoring_table = '\n'.join(scoring_rows)

        level_rows = ""
        level_labels = {"A": ("安全", "Safe"), "B": ("可接受", "Acceptable"), "C": ("警告", "Warning"), "D": ("不安全", "Unsafe"), "F": ("危险", "Dangerous")}
        level_ranges = {"A": "0–9", "B": "10–29", "C": "30–49", "D": "50–69", "F": "70–100"}
        for lv in ["A", "B", "C", "D", "F"]:
            zh_label, en_label = level_labels[lv]
            level_rows += (
                f'<tr><td><span class="badge badge-level badge-{lv.lower()}">{lv}</span></td>'
                f'<td><span data-i18n-zh>{zh_label}</span><span data-i18n-en>{en_label}</span></td>'
                f'<td class="font-mono">{level_ranges[lv]}</td></tr>'
            )

        # Nav link back to report
        report_link = f'<a href="{esc(report_filename)}" style="font-size:0.8125rem;color:hsl(var(--info));text-decoration:none;">&larr; <span data-i18n-zh>返回审计报告</span><span data-i18n-en>Back to Audit Report</span></a>' if report_filename else ""

        methodology_html = Template(self.METHODOLOGY_TEMPLATE).safe_substitute(
            version=__version__,
            timestamp=datetime.now(timezone.utc).strftime('%Y-%m-%d %H:%M UTC'),
            report_link=report_link,
            dim_table=dim_table,
            rules_html=rules_html,
            model_table=model_table,
            scoring_table=scoring_table,
            level_rows=level_rows,
            total_rules=idx,
            output_per_turn=OUTPUT_PER_TURN,
            scenario_light=COST_SCENARIOS["light"],
            scenario_typical=COST_SCENARIOS["typical"],
            scenario_heavy=COST_SCENARIOS["heavy"],
        )
        output_path.write_text(methodology_html, encoding='utf-8')
        print(f"{C.GREEN}Methodology page written to: {output_path}{C.RESET}")

    METHODOLOGY_TEMPLATE = r"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>Audit Methodology</title>
<script>
(function(){
var t=localStorage.getItem('audit-theme');
if(t==='light')document.documentElement.classList.remove('dark');
else document.documentElement.classList.add('dark');
var l=localStorage.getItem('audit-lang')||'en';
document.documentElement.lang=l;
document.documentElement.dataset.lang=l;
})();
</script>
<style>
:root {
  --background: 0 0% 100%; --foreground: 0 0% 3.9%;
  --card: 0 0% 100%; --card-foreground: 0 0% 3.9%;
  --primary: 0 0% 9%; --primary-foreground: 0 0% 98%;
  --secondary: 0 0% 96.1%; --secondary-foreground: 0 0% 9%;
  --muted: 0 0% 96.1%; --muted-foreground: 0 0% 45.1%;
  --accent: 0 0% 96.1%; --accent-foreground: 0 0% 9%;
  --border: 0 0% 89.8%; --input: 0 0% 89.8%; --ring: 0 0% 3.9%;
  --radius: 0.5rem;
  --success: 142 76% 36%; --success-foreground: 142 76% 90%;
  --warning: 38 92% 50%; --info: 217 91% 60%;
  --level-a: 142 71% 45%; --level-b: 217 91% 60%; --level-c: 45 93% 47%;
  --level-d: 24 95% 53%; --level-f: 0 84% 60%;
  --sev-critical-bg: 0 84% 60%/0.12; --sev-critical-fg: 0 72% 51%; --sev-critical-border: 0 84% 60%/0.25;
  --sev-high-bg: 24 95% 53%/0.1; --sev-high-fg: 21 90% 48%; --sev-high-border: 24 95% 53%/0.2;
  --sev-medium-bg: 45 93% 47%/0.1; --sev-medium-fg: 40 85% 38%; --sev-medium-border: 45 93% 47%/0.2;
  --sev-low-bg: 217 91% 60%/0.08; --sev-low-fg: 217 80% 50%; --sev-low-border: 217 91% 60%/0.18;
  --sev-info-bg: 0 0% 0%/0.04; --sev-info-fg: 0 0% 45%; --sev-info-border: 0 0% 0%/0.1;
  --cell-ref: 270 60% 55%; --card-shadow: 0 0% 0%/0.08;
}
.dark {
  --background: 0 0% 3.9%; --foreground: 0 0% 98%;
  --card: 0 0% 3.9%; --card-foreground: 0 0% 98%;
  --primary: 0 0% 98%; --primary-foreground: 0 0% 9%;
  --secondary: 0 0% 14.9%; --secondary-foreground: 0 0% 98%;
  --muted: 0 0% 14.9%; --muted-foreground: 0 0% 63.9%;
  --accent: 0 0% 14.9%; --accent-foreground: 0 0% 98%;
  --border: 0 0% 14.9%; --input: 0 0% 14.9%; --ring: 0 0% 83.1%;
  --sev-critical-bg: 0 84% 60%/0.15; --sev-critical-fg: 0 84% 65%; --sev-critical-border: 0 84% 60%/0.3;
  --sev-high-bg: 24 95% 53%/0.12; --sev-high-fg: 24 95% 63%; --sev-high-border: 24 95% 53%/0.25;
  --sev-medium-bg: 45 93% 47%/0.12; --sev-medium-fg: 45 93% 60%; --sev-medium-border: 45 93% 47%/0.25;
  --sev-low-bg: 217 91% 60%/0.1; --sev-low-fg: 217 91% 70%; --sev-low-border: 217 91% 60%/0.2;
  --sev-info-bg: 0 0% 100%/0.06; --sev-info-fg: 0 0% 64%; --sev-info-border: 0 0% 100%/0.1;
  --cell-ref: 270 60% 70%; --card-shadow: 0 0% 0%/0.15;
}
*,*::before,*::after{box-sizing:border-box;margin:0;padding:0}
body{font-family:ui-sans-serif,system-ui,-apple-system,BlinkMacSystemFont,"Segoe UI",Roboto,"Helvetica Neue",Arial,sans-serif;background:hsl(var(--background));color:hsl(var(--foreground));line-height:1.6;-webkit-font-smoothing:antialiased;min-height:100vh;display:flex;flex-direction:column;overflow-y:scroll;overflow-x:hidden}
h1{font-size:1.875rem;font-weight:700;letter-spacing:-0.025em;line-height:1.2;color:hsl(var(--foreground))}
h2{font-size:1.25rem;font-weight:600;letter-spacing:-0.02em;color:hsl(var(--foreground));margin-top:2rem;margin-bottom:0.75rem}
h3{font-size:1rem;font-weight:600;color:hsl(var(--foreground));margin-top:1.25rem;margin-bottom:0.5rem}
p,.text-body{font-size:0.875rem;line-height:1.7;color:hsl(var(--foreground))}
.text-muted{color:hsl(var(--muted-foreground))}
.text-sm{font-size:0.875rem;line-height:1.4} .text-xs{font-size:0.75rem;line-height:1.4}
.font-mono{font-family:ui-monospace,SFMono-Regular,"SF Mono",Menlo,Consolas,monospace}
.font-medium{font-weight:500} .font-semibold{font-weight:600}
.tracking-tight{letter-spacing:-0.025em}
.flex{display:flex} .items-center{align-items:center} .justify-between{justify-content:space-between}
.gap-2{gap:0.5rem} .gap-3{gap:0.75rem}
.nav-container,.main-container,.footer-container{max-width:72rem;margin:0 auto;padding-left:1rem;padding-right:1rem}
@media(min-width:640px){.nav-container,.main-container,.footer-container{padding-left:1.5rem;padding-right:1.5rem}}
@media(min-width:1024px){.nav-container,.main-container,.footer-container{padding-left:2rem;padding-right:2rem}}
.main-container{padding-top:2rem;padding-bottom:2rem}
.card{background:hsl(var(--card));border:1px solid hsl(var(--border));border-radius:var(--radius)}
.card-header{padding:1.25rem 1.5rem 0.75rem}
.card-content{padding:0 1.5rem 1.25rem}
.card-title{font-size:0.875rem;font-weight:600}
.page-header{padding-bottom:1.5rem;border-bottom:1px solid hsl(var(--border));margin-bottom:2rem}
.page-header p{color:hsl(var(--muted-foreground));font-size:0.875rem;margin-top:0.375rem}
.data-table{width:100%;border-collapse:collapse;font-size:0.8125rem}
.data-table th{text-align:left;font-weight:500;color:hsl(var(--muted-foreground));padding:0.5rem 0.75rem;border-bottom:1px solid hsl(var(--border));font-size:0.75rem;text-transform:uppercase;letter-spacing:0.04em}
.data-table td{padding:0.5rem 0.75rem;border-bottom:1px solid hsl(var(--border)/0.5);vertical-align:top;color:hsl(var(--foreground))}
.data-table tbody tr{transition:background 0.1s}
.data-table tbody tr:hover{background:hsl(var(--muted)/0.3)}
.data-table tbody tr:last-child td{border-bottom:none}
.cell-ref{font-size:0.6875rem;color:hsl(var(--cell-ref));white-space:nowrap}
.cell-cost{font-family:ui-monospace,SFMono-Regular,Menlo,monospace;font-size:0.8125rem;font-weight:500;text-align:right;white-space:nowrap}
.cost-model-cell{display:flex;align-items:center;gap:6px}
.cost-ov-icon{display:inline-flex;align-items:center;flex-shrink:0;line-height:1}
.cost-ov-icon svg{width:1em;height:1em}
.sev{display:inline-flex;align-items:center;border-radius:9999px;font-size:0.6875rem;font-weight:600;padding:0.15rem 0.5rem;line-height:1.2;border:1px solid transparent}
.sev-CRITICAL{background:hsl(var(--sev-critical-bg));color:hsl(var(--sev-critical-fg));border-color:hsl(var(--sev-critical-border))}
.sev-HIGH{background:hsl(var(--sev-high-bg));color:hsl(var(--sev-high-fg));border-color:hsl(var(--sev-high-border))}
.sev-MEDIUM{background:hsl(var(--sev-medium-bg));color:hsl(var(--sev-medium-fg));border-color:hsl(var(--sev-medium-border))}
.sev-LOW{background:hsl(var(--sev-low-bg));color:hsl(var(--sev-low-fg));border-color:hsl(var(--sev-low-border))}
.sev-INFO{background:hsl(var(--sev-info-bg));color:hsl(var(--sev-info-fg));border-color:hsl(var(--sev-info-border))}
.badge{display:inline-flex;align-items:center;justify-content:center;border-radius:9999px;font-size:0.6875rem;font-weight:600;line-height:1;padding:0.2rem 0.55rem;white-space:nowrap;border:1px solid transparent}
.badge-level{width:1.5rem;height:1.5rem;padding:0;font-size:0.6875rem}
.badge-a{background:hsl(var(--level-a)/0.15);color:hsl(var(--level-a));border-color:hsl(var(--level-a)/0.3)}
.badge-b{background:hsl(var(--level-b)/0.15);color:hsl(var(--level-b));border-color:hsl(var(--level-b)/0.3)}
.badge-c{background:hsl(var(--level-c)/0.15);color:hsl(var(--level-c));border-color:hsl(var(--level-c)/0.3)}
.badge-d{background:hsl(var(--level-d)/0.15);color:hsl(var(--level-d));border-color:hsl(var(--level-d)/0.3)}
.badge-f{background:hsl(var(--level-f)/0.15);color:hsl(var(--level-f));border-color:hsl(var(--level-f)/0.3)}
.rule-block{background:hsl(var(--muted)/0.4);border-radius:var(--radius);padding:0.75rem 1rem;margin:0.5rem 0;font-size:0.8125rem;line-height:1.7}
.rule-block code{font-family:ui-monospace,SFMono-Regular,Menlo,monospace;font-size:0.8125rem;background:hsl(var(--muted));padding:0.1rem 0.35rem;border-radius:3px}
.section{margin-bottom:2rem}
.theme-toggle,.lang-toggle{display:inline-flex;align-items:center;justify-content:center;width:2.25rem;height:2.25rem;border-radius:var(--radius);border:1px solid hsl(var(--border));background:hsl(var(--card));color:hsl(var(--muted-foreground));cursor:pointer;transition:background 0.15s,color 0.15s,border-color 0.15s;flex-shrink:0}
.theme-toggle:hover,.lang-toggle:hover{background:hsl(var(--accent));color:hsl(var(--accent-foreground));border-color:hsl(var(--ring)/0.3)}
.lang-toggle{font-size:0.6875rem;font-weight:700;letter-spacing:0.02em}
.theme-toggle svg{width:16px;height:16px}
.theme-toggle .icon-sun{display:none} .theme-toggle .icon-moon{display:block}
.dark .theme-toggle .icon-sun{display:block} .dark .theme-toggle .icon-moon{display:none}
[data-lang="zh"] [data-i18n-en]{display:none!important}
[data-lang="en"] [data-i18n-zh]{display:none!important}
@media(max-width:640px){.container{padding:1rem} h1{font-size:1.5rem} .data-table{font-size:0.75rem}}
::-webkit-scrollbar{width:6px;height:6px}
::-webkit-scrollbar-track{background:transparent}
::-webkit-scrollbar-thumb{background-color:rgba(128,128,128,0.3);border-radius:3px}
::-webkit-scrollbar-thumb:hover{background-color:rgba(128,128,128,0.5)}
</style>
</head>
<body>
<!-- Navigation -->
<nav style="border-bottom:1px solid hsl(var(--border));background:hsl(var(--background)/0.8);backdrop-filter:blur(8px);position:sticky;top:0;z-index:50">
  <div class="nav-container">
    <div style="display:flex;align-items:center;justify-content:space-between;height:4rem">
      <div style="display:flex;align-items:center;gap:1.5rem">
        <a href="/" style="font-size:1.125rem;font-weight:700;letter-spacing:-0.025em;color:hsl(var(--foreground));text-decoration:none">Skill Guard</a>
        <a href="/" style="font-size:0.875rem;color:hsl(var(--muted-foreground));text-decoration:none;transition:color 0.2s">Home</a>
        <a href="/rules" style="font-size:0.875rem;color:hsl(var(--muted-foreground));text-decoration:none;transition:color 0.2s">Rules</a>
        <a href="/methodology" style="font-size:0.875rem;color:hsl(var(--muted-foreground));text-decoration:none;transition:color 0.2s">Methodology</a>
      </div>
      <div style="display:flex;align-items:center;gap:0.5rem">
        <button class="lang-toggle" id="langToggle" title="Toggle language"><span data-i18n-zh>EN</span><span data-i18n-en>CN</span></button>
        <button class="theme-toggle" id="themeToggle" title="Toggle theme">
          <svg class="icon-sun" xmlns="http://www.w3.org/2000/svg" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><circle cx="12" cy="12" r="5"/><line x1="12" y1="1" x2="12" y2="3"/><line x1="12" y1="21" x2="12" y2="23"/><line x1="4.22" y1="4.22" x2="5.64" y2="5.64"/><line x1="18.36" y1="18.36" x2="19.78" y2="19.78"/><line x1="1" y1="12" x2="3" y2="12"/><line x1="21" y1="12" x2="23" y2="12"/><line x1="4.22" y1="19.78" x2="5.64" y2="18.36"/><line x1="18.36" y1="5.64" x2="19.78" y2="4.22"/></svg>
          <svg class="icon-moon" xmlns="http://www.w3.org/2000/svg" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="M21 12.79A9 9 0 1 1 11.21 3 7 7 0 0 0 21 12.79z"/></svg>
        </button>
      </div>
    </div>
  </div>
</nav>

<div class="main-container" style="flex:1">

<div class="page-header">
  <div class="flex items-center justify-between">
    <div>
      <h1 class="tracking-tight"><span data-i18n-zh>审计方法论</span><span data-i18n-en>Audit Methodology</span></h1>
      <p><span data-i18n-zh>安全审计维度、检测规则与成本估算模型说明</span><span data-i18n-en>Security audit dimensions, detection rules, and cost estimation model</span></p>
      <div style="margin-top:0.5rem">$report_link</div>
    </div>
  </div>
  <div style="display:flex;gap:1.5rem;margin-top:0.75rem;flex-wrap:wrap">
    <span class="text-sm text-muted">v$version</span>
    <span class="text-sm text-muted">$timestamp</span>
  </div>
</div>

<!-- ── 1. Risk Scoring ── -->
<div class="section">
  <h2><span data-i18n-zh>一、风险评分模型</span><span data-i18n-en>1. Risk Scoring Model</span></h2>
  <p class="text-body text-muted" style="margin-bottom:0.75rem">
    <span data-i18n-zh>每条 finding 按严重度计分，累加后截断到 100 分，映射为 A–F 五级。</span>
    <span data-i18n-en>Each finding scores by severity, summed and capped at 100, mapped to A–F grades.</span>
  </p>
  <div style="display:grid;grid-template-columns:1fr 1fr;gap:1rem">
    <div class="card">
      <div class="card-header"><div class="card-title"><span data-i18n-zh>严重度分值</span><span data-i18n-en>Severity Scores</span></div></div>
      <div class="card-content">
        <table class="data-table"><thead><tr>
          <th><span data-i18n-zh>严重度</span><span data-i18n-en>Severity</span></th>
          <th style="text-align:right"><span data-i18n-zh>分值</span><span data-i18n-en>Score</span></th>
        </tr></thead><tbody>$scoring_table</tbody></table>
      </div>
    </div>
    <div class="card">
      <div class="card-header"><div class="card-title"><span data-i18n-zh>风险等级</span><span data-i18n-en>Risk Levels</span></div></div>
      <div class="card-content">
        <table class="data-table"><thead><tr>
          <th><span data-i18n-zh>等级</span><span data-i18n-en>Level</span></th>
          <th><span data-i18n-zh>标签</span><span data-i18n-en>Label</span></th>
          <th><span data-i18n-zh>分数范围</span><span data-i18n-en>Score Range</span></th>
        </tr></thead><tbody>$level_rows</tbody></table>
      </div>
    </div>
  </div>
</div>

<!-- ── 2. Audit Dimensions ── -->
<div class="section">
  <h2><span data-i18n-zh>二、10 个审计维度</span><span data-i18n-en>2. 10 Audit Dimensions</span></h2>
  <p class="text-body text-muted" style="margin-bottom:0.75rem">
    <span data-i18n-zh>基于 OWASP LLM Top 10、SLSA、Google SAIF、MCP-Scan 等框架设计。</span>
    <span data-i18n-en>Based on OWASP LLM Top 10, SLSA, Google SAIF, MCP-Scan frameworks.</span>
  </p>
  <div class="card">
    <div class="card-content" style="padding-top:1rem">
      <table class="data-table"><thead><tr>
        <th style="width:40px">#</th>
        <th><span data-i18n-zh>维度</span><span data-i18n-en>Dimension</span></th>
        <th style="width:180px"><span data-i18n-zh>参考标准</span><span data-i18n-en>Reference</span></th>
        <th><span data-i18n-zh>通用修复建议</span><span data-i18n-en>General Remediation</span></th>
      </tr></thead><tbody>
$dim_table
      </tbody></table>
    </div>
  </div>
</div>

<!-- ── 2.5. Rule Architecture ── -->
<div class="section">
  <h2><span data-i18n-zh>2.5 规则架构：内置 vs 可配置</span><span data-i18n-en>2.5 Rule Architecture: Built-in vs Configurable</span></h2>
  <p class="text-body text-muted" style="margin-bottom:0.75rem">
    <span data-i18n-zh>109 条审计规则分为两类。<b>内置规则 (67 条)</b>：权威性安全检测，硬编码不可关闭，涵盖 Prompt 注入核心短语、权限提升、破坏性操作、代码安全、凭证泄露。<b>可配置规则 (42 条)</b>：开放性检测，用户可通过 <code>rules.yaml</code> 或 <a href="/rules" style="color:hsl(var(--info))">Rules Editor</a> 调整开关、严重级别、白名单。</span>
    <span data-i18n-en>109 audit rules are split into two tiers. <b>Built-in Rules (67)</b>: authoritative security checks, hardcoded and always-on — covering Prompt Injection core phrases, Permission Escalation, Destructive Operations, Code Security, and Credential Leaks. <b>Configurable Rules (42)</b>: open checks users can toggle, re-severity, or whitelist via <code>rules.yaml</code> or the <a href="/rules" style="color:hsl(var(--info))">Rules Editor</a>.</span>
  </p>
  <div style="display:grid;grid-template-columns:1fr 1fr;gap:1rem">
    <div class="card">
      <div class="card-header"><div class="card-title"><span data-i18n-zh>内置规则 (67 条，不可配置)</span><span data-i18n-en>Built-in Rules (67, not configurable)</span></div></div>
      <div class="card-content">
        <table class="data-table"><thead><tr>
          <th><span data-i18n-zh>维度</span><span data-i18n-en>Dimension</span></th>
          <th style="text-align:right"><span data-i18n-zh>条数</span><span data-i18n-en>Count</span></th>
        </tr></thead><tbody>
          <tr><td>Prompt Injection (core)</td><td style="text-align:right">10</td></tr>
          <tr><td>Permission Escalation</td><td style="text-align:right">10</td></tr>
          <tr><td>Destructive Operations</td><td style="text-align:right">17</td></tr>
          <tr><td>Code Security</td><td style="text-align:right">17</td></tr>
          <tr><td>Credential Leaks</td><td style="text-align:right">13</td></tr>
        </tbody></table>
      </div>
    </div>
    <div class="card">
      <div class="card-header"><div class="card-title"><span data-i18n-zh>可配置规则 (42 条，rules.yaml)</span><span data-i18n-en>Configurable Rules (42, rules.yaml)</span></div></div>
      <div class="card-content">
        <table class="data-table"><thead><tr>
          <th><span data-i18n-zh>维度</span><span data-i18n-en>Dimension</span></th>
          <th style="text-align:right"><span data-i18n-zh>条数</span><span data-i18n-en>Count</span></th>
        </tr></thead><tbody>
          <tr><td>Data Exfiltration</td><td style="text-align:right">18</td></tr>
          <tr><td>Supply Chain</td><td style="text-align:right">8</td></tr>
          <tr><td>Resource Abuse</td><td style="text-align:right">9</td></tr>
          <tr><td>License Compliance</td><td style="text-align:right">7</td></tr>
          <tr><td>Least Privilege</td><td style="text-align:right">3</td></tr>
          <tr><td>Prompt Injection (aux)</td><td style="text-align:right">3</td></tr>
        </tbody></table>
      </div>
    </div>
  </div>
</div>

<!-- ── 3. Remediation Rules ── -->
<div class="section">
  <h2><span data-i18n-zh>三、修复规则清单 ($total_rules 条)</span><span data-i18n-en>3. Remediation Rules ($total_rules total)</span></h2>
  <p class="text-body text-muted" style="margin-bottom:0.75rem">
    <span data-i18n-zh>每条 finding 的 description 通过关键词匹配以下规则，自动填充修复建议。未匹配时回退到维度级通用建议。</span>
    <span data-i18n-en>Each finding's description is matched against these rules by keyword to auto-fill remediation. Falls back to dimension-level general advice when unmatched.</span>
  </p>
$rules_html
</div>

<!-- ── 4. Cost Estimation ── -->
<div class="section">
  <h2><span data-i18n-zh>四、成本估算模型</span><span data-i18n-en>4. Cost Estimation Model</span></h2>

  <h3><span data-i18n-zh>4.1 五条估算规则</span><span data-i18n-en>4.1 Five Estimation Rules</span></h3>
  <div class="rule-block">
    <strong>R1</strong> —
    <span data-i18n-zh>三档会话场景：轻度 = $scenario_light 轮, 典型 = $scenario_typical 轮, 重度 = $scenario_heavy 轮</span>
    <span data-i18n-en>Three session scenarios: Light = $scenario_light turns, Typical = $scenario_typical turns, Heavy = $scenario_heavy turns</span><br>
    <strong>R2</strong> —
    <span data-i18n-zh>每轮输出假设：$output_per_turn tokens</span>
    <span data-i18n-en>Output per turn: $output_per_turn tokens</span><br>
    <strong>R3</strong> —
    <span data-i18n-zh>渐进加载：L2 eager 文件在第 2 轮加载，L2 lazy 文件在第 3 轮</span>
    <span data-i18n-en>Progressive loading: L2 eager files loaded at turn 2, L2 lazy files at turn 3</span><br>
    <strong>R4</strong> —
    <span data-i18n-zh>Prompt 缓存：L1 (SKILL.md) 首轮后进入缓存（Anthropic 10%, Google 25%, OpenAI 50%）</span>
    <span data-i18n-en>Prompt caching: L1 (SKILL.md) cached after first turn (Anthropic 10%, Google 25%, OpenAI 50%)</span><br>
    <strong>R5</strong> —
    <span data-i18n-zh>上下文累积：每轮重发全部先前上下文。缓存部分 = 上轮完整输入；新增部分 = 上轮输出 + 新 L2 文件</span>
    <span data-i18n-en>Context accumulation: each turn re-sends all prior context. Cached = previous turn's full input; New = last output + new L2 files</span>
  </div>

  <h3><span data-i18n-zh>4.2 多轮成本公式</span><span data-i18n-en>4.2 Multi-turn Cost Formula</span></h3>
  <div class="rule-block">
    <code>Turn 1</code>: new = L1, cached = 0<br>
    <code>Turn 2</code>: new = O + L2_eager, cached = L1<br>
    <code>Turn 3</code>: new = O + L2_lazy, cached = L1 + O + L2_eager<br>
    <code>Turn k&gt;3</code>: new = O, cached = L1 + L2e + L2l + (k-2)×O<br><br>
    <span data-i18n-zh>每轮成本 = new × full_rate + cached × cache_rate + O × output_rate</span>
    <span data-i18n-en>Per-turn cost = new × full_rate + cached × cache_rate + O × output_rate</span><br>
    <span data-i18n-zh>会话总成本 = Σ (各轮成本)</span>
    <span data-i18n-en>Session total = Σ (per-turn costs)</span>
  </div>

  <h3><span data-i18n-zh>4.3 模型定价</span><span data-i18n-en>4.3 Model Pricing</span></h3>
  <div class="card">
    <div class="card-content" style="padding-top:1rem">
      <table class="data-table"><thead><tr>
        <th><span data-i18n-zh>模型</span><span data-i18n-en>Model</span></th>
        <th><span data-i18n-zh>厂商</span><span data-i18n-en>Provider</span></th>
        <th style="text-align:right"><span data-i18n-zh>输入/1M</span><span data-i18n-en>Input/1M</span></th>
        <th style="text-align:right"><span data-i18n-zh>输出/1M</span><span data-i18n-en>Output/1M</span></th>
        <th style="text-align:right"><span data-i18n-zh>缓存/1M</span><span data-i18n-en>Cache/1M</span></th>
        <th><span data-i18n-zh>上下文</span><span data-i18n-en>Context</span></th>
      </tr></thead><tbody>
$model_table
      </tbody></table>
    </div>
  </div>
</div>

</div>

<!-- Footer -->
<footer style="border-top:1px solid hsl(var(--border));margin-top:4rem;padding:2rem 0">
  <div class="footer-container" style="text-align:center;font-size:0.875rem;color:hsl(var(--muted-foreground))">
    SkillGuard &mdash; AI Agent Skill Security Auditor &middot; 10 Dimensions &middot; 109 Rules (67 Built-in + 42 Configurable)
  </div>
</footer>

<script>
(function(){
  var html=document.documentElement;
  document.getElementById('themeToggle').addEventListener('click',function(){
    var isDark=html.classList.toggle('dark');
    localStorage.setItem('audit-theme',isDark?'dark':'light');
  });
  var langBtn=document.getElementById('langToggle');
  function setLang(lang){html.lang=lang;html.dataset.lang=lang;localStorage.setItem('audit-lang',lang);}
  langBtn.addEventListener('click',function(){setLang(html.dataset.lang==='zh'?'en':'zh');});
  setLang(html.dataset.lang||'en');
})();
</script>
</body>
</html>"""

    def _score_color_hsl(self, score: int) -> str:
        if score >= 70: return "var(--level-f)"
        if score >= 50: return "var(--level-d)"
        if score >= 30: return "var(--level-c)"
        if score >= 10: return "var(--level-b)"
        return "var(--level-a)"

    def _score_ring_svg(self, score: int, level: str) -> str:
        r = 15
        circ = 2 * 3.14159 * r
        offset = circ * (1 - score / 100)
        color_hsl = self._score_color_hsl(score)
        return (
            f'<div class="score-ring">'
            f'<svg viewBox="0 0 36 36"><circle class="ring-bg" cx="18" cy="18" r="{r}"/>'
            f'<circle class="ring-fg" cx="18" cy="18" r="{r}" '
            f'stroke="hsl({color_hsl})" stroke-dasharray="{circ:.1f}" '
            f'stroke-dashoffset="{offset:.1f}"/></svg>'
            f'<div class="ring-label" style="color:hsl({color_hsl})">{score}</div></div>'
        )

    def render(self, reports: List[AuditReport], output_path: Path, target: str = "", methodology_filename: str = "methodology.html"):
        esc = html_module.escape
        total = len(reports)
        by_level = {"A": 0, "B": 0, "C": 0, "D": 0, "F": 0}
        for r in reports:
            by_level[r.risk_level] = by_level.get(r.risk_level, 0) + 1

        pcts = {}
        for lv in "ABCDF":
            pcts[lv] = (by_level[lv] / total * 100) if total > 0 else 0

        # ── Token aggregate stats ──
        sum_l1 = sum(r.token_estimate.l1_skill_md for r in reports)
        sum_eager = sum(r.token_estimate.l2_eager for r in reports)
        sum_lazy = sum(r.token_estimate.l2_lazy for r in reports)
        per_skill = sorted(
            [(r.skill_name, r.token_estimate.l1_skill_md + r.token_estimate.l2_eager + r.token_estimate.l2_lazy, r.token_estimate) for r in reports],
            key=lambda x: -x[1]
        )
        l1l2_values = [x[1] for x in per_skill]
        total_l1l2 = sum(l1l2_values)
        avg_l1l2 = total_l1l2 // total if total > 0 else 0
        median_l1l2 = sorted(l1l2_values)[len(l1l2_values) // 2] if l1l2_values else 0
        max_l1l2 = l1l2_values[0] if l1l2_values else 0
        sum_l3 = sum(r.token_estimate.l3_total for r in reports)
        tok_pct_l1 = (sum_l1 / sum_l3 * 100) if sum_l3 > 0 else 0
        tok_pct_eager = (sum_eager / sum_l3 * 100) if sum_l3 > 0 else 0
        tok_pct_lazy = (sum_lazy / sum_l3 * 100) if sum_l3 > 0 else 0
        tok_pct_l3 = 100.0
        # Top 5 token consumers
        top5_items = []
        for name, l1l2, te in per_skill[:5]:
            detail_parts = []
            if te.l1_skill_md: detail_parts.append(f"L1:{format_tokens(te.l1_skill_md)}")
            if te.l2_eager: detail_parts.append(f"eager:{format_tokens(te.l2_eager)}")
            if te.l2_lazy: detail_parts.append(f"lazy:{format_tokens(te.l2_lazy)}")
            top5_items.append(
                f'<div class="token-ov-top5-item">'
                f'<span class="token-ov-top5-name">{esc(name)}</span>'
                f'<span class="token-ov-top5-detail">{" + ".join(detail_parts)}</span>'
                f'<span class="token-ov-top5-val">{format_tokens(l1l2)} tokens</span>'
                f'</div>'
            )
        tok_top5_html = '\n'.join(top5_items)

        # ── Cost overview cards (multi-turn model) ──
        cost_ov_cards_parts = []
        for mp in MODEL_CATALOG:
            avg_typical = sum(_compute_session_cost(r.token_estimate, mp, COST_SCENARIOS["typical"]) for r in reports) / total if total > 0 else 0
            avg_light = sum(_compute_session_cost(r.token_estimate, mp, COST_SCENARIOS["light"]) for r in reports) / total if total > 0 else 0
            avg_heavy = sum(_compute_session_cost(r.token_estimate, mp, COST_SCENARIOS["heavy"]) for r in reports) / total if total > 0 else 0
            icon_html = f'<span class="cost-ov-icon">{mp.icon_svg}</span>' if mp.icon_svg else ""
            cost_ov_cards_parts.append(
                f'<div class="cost-ov-card">'
                f'<div class="cost-ov-model">{icon_html}{esc(mp.name)}</div>'
                f'<div class="cost-ov-provider">{esc(mp.provider)} &middot; ${mp.input_per_m}/${mp.output_per_m} per 1M</div>'
                f'<div class="cost-ov-price">'
                f'<span data-i18n-zh>轻度</span><span data-i18n-en>Light</span> ({COST_SCENARIOS["light"]}T): <b>{format_cost(avg_light)}</b><br>'
                f'<span data-i18n-zh>典型</span><span data-i18n-en>Typical</span> ({COST_SCENARIOS["typical"]}T): <b>{format_cost(avg_typical)}</b><br>'
                f'<span data-i18n-zh>重度</span><span data-i18n-en>Heavy</span> ({COST_SCENARIOS["heavy"]}T): <b>{format_cost(avg_heavy)}</b>'
                f'</div>'
                f'<div class="cost-ov-total-label"><span data-i18n-zh>平均每技能会话成本</span><span data-i18n-en>avg session cost per skill</span></div>'
                f'</div>'
            )
        cost_ov_html = '\n'.join(cost_ov_cards_parts)

        # Top 10
        sorted_reports = sorted(reports, key=lambda r: (-r.risk_score, r.skill_name))
        top10_items = []
        for i, r in enumerate(sorted_reports[:10]):
            crit = sum(1 for f in r.findings if f.severity == "CRITICAL")
            high = sum(1 for f in r.findings if f.severity == "HIGH")
            pills = []
            if crit: pills.append(f'<span class="sev-pill pill-C">{crit}C</span>')
            if high: pills.append(f'<span class="sev-pill pill-H">{high}H</span>')
            top10_items.append(
                f'<div class="top-item">'
                f'<span class="top-rank">{i+1}</span>'
                f'<span class="badge badge-level badge-{r.risk_level.lower()}">{r.risk_level}</span>'
                f'<span class="top-name">{esc(r.skill_name)}</span>'
                f'<div class="top-stats">'
                f'{"".join(pills)}'
                f'{self._score_ring_svg(r.risk_score, r.risk_level)}'
                f'</div></div>'
            )
        top10_html = '\n'.join(top10_items)

        # Skill cards
        cards = []
        for r in sorted_reports:
            sorted_findings = sorted(r.findings, key=lambda f: SEVERITY_ORDER.get(f.severity, 4))
            rows = []
            for f in sorted_findings:
                loc = f"{esc(f.file_path)}:{f.line_number}" if f.line_number > 0 else esc(f.file_path)
                ref_html = f'<span class="cell-ref">{esc(f.reference)}</span>' if f.reference and f.reference != "—" else ""
                dim_short = f.dimension.split('(')[0].strip() if '(' in f.dimension else f.dimension
                dim_en = ""
                if '(' in f.dimension:
                    dim_en = f.dimension.split('(')[1].rstrip(')').strip()
                dim_cell = (
                    f'<span data-i18n-zh>{esc(dim_short)}</span>'
                    f'<span data-i18n-en>{esc(dim_en) if dim_en else esc(dim_short)}</span>'
                )
                rows.append(
                    f'<tr>'
                    f'<td><span class="sev sev-{f.severity}">{f.severity}</span></td>'
                    f'<td class="cell-dim" title="{esc(f.dimension)}">{dim_cell}</td>'
                    f'<td>{esc(f.description)} {ref_html}</td>'
                    f'<td class="cell-loc">{loc}</td>'
                    f'</tr>'
                )
                if f.remediation_zh or f.remediation_en:
                    rem_zh = esc(f.remediation_zh) if f.remediation_zh else ""
                    rem_en = esc(f.remediation_en) if f.remediation_en else ""
                    rows.append(
                        f'<tr><td colspan="4" class="cell-remediation">'
                        f'<span data-i18n-zh>{rem_zh}</span>'
                        f'<span data-i18n-en>{rem_en}</span>'
                        f'</td></tr>'
                    )

            if rows:
                table_html = (
                    '<table class="data-table"><thead><tr>'
                    '<th style="width:90px"><span data-i18n-zh>严重度</span><span data-i18n-en>Severity</span></th>'
                    '<th style="width:160px"><span data-i18n-zh>维度</span><span data-i18n-en>Dimension</span></th>'
                    '<th><span data-i18n-zh>描述</span><span data-i18n-en>Description</span></th>'
                    '<th style="width:200px"><span data-i18n-zh>位置</span><span data-i18n-en>Location</span></th>'
                    '</tr></thead><tbody>\n' + '\n'.join(rows) + '\n</tbody></table>'
                )
            else:
                table_html = (
                    '<div class="empty-state">'
                    '<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 24 24" fill="none" '
                    'stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round">'
                    '<path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z"/></svg>'
                    '<span class="text-sm"><span data-i18n-zh>未发现问题</span><span data-i18n-en>No findings detected</span></span></div>'
                )

            # Severity pills
            sev_counts = {}
            for f in r.findings:
                sev_counts[f.severity] = sev_counts.get(f.severity, 0) + 1
            pills = []
            pill_map = {"CRITICAL": "C", "HIGH": "H", "MEDIUM": "M", "LOW": "L", "INFO": "I"}
            for sev_name in ["CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"]:
                cnt = sev_counts.get(sev_name, 0)
                if cnt:
                    pills.append(f'<span class="sev-pill pill-{pill_map[sev_name]}">{cnt}{pill_map[sev_name]}</span>')

            # Token estimate
            te = r.token_estimate
            token_html = ""
            if te.l1_skill_md > 0:
                token_html = f'<div class="token-bar"><span class="token-chip"><span class="token-dot dot-l1"></span><span class="token-chip-label">L1 SKILL.md</span><span class="token-chip-val"><b>{format_tokens(te.l1_skill_md)} tokens</b></span></span>'
                if te.l2_eager > 0:
                    eager_list = ", ".join(esc(f) for f in te.eager_files[:6])
                    more_e = f" +{len(te.eager_files)-6}" if len(te.eager_files) > 6 else ""
                    token_html += f'<span class="token-chip"><span class="token-dot dot-eager"></span><span class="token-chip-label">L2 Eager</span><span class="token-chip-val"><b>{format_tokens(te.l2_eager)} tokens</b></span><span class="token-refs" title="{eager_list}{more_e}">({len(te.eager_files)} files: {eager_list}{more_e})</span></span>'
                if te.l2_lazy > 0:
                    lazy_list = ", ".join(esc(f) for f in te.lazy_files[:6])
                    more_l = f" +{len(te.lazy_files)-6}" if len(te.lazy_files) > 6 else ""
                    token_html += f'<span class="token-chip"><span class="token-dot dot-lazy"></span><span class="token-chip-label">L2 Lazy</span><span class="token-chip-val"><b>{format_tokens(te.l2_lazy)} tokens</b></span><span class="token-refs" title="{lazy_list}{more_l}">({len(te.lazy_files)} files: {lazy_list}{more_l})</span></span>'
                token_html += f'<span class="token-chip"><span class="token-dot dot-l3"></span><span class="token-chip-label">L3 Total</span><span class="token-chip-val"><b>{format_tokens(te.l3_total)} tokens</b></span></span></div>'
            l1_l2 = te.l1_skill_md + te.l2_eager + te.l2_lazy
            token_label = f'<span class="token-label">~{format_tokens(l1_l2)} tokens</span>' if te.l1_skill_md > 0 else ""

            # Cost mini-table per skill (multi-turn scenarios)
            cost_html = ""
            if r.cost_estimates:
                icon_map = {mp.name: mp.icon_svg for mp in MODEL_CATALOG}
                cost_rows = []
                for c in r.cost_estimates:
                    ic = f'<span class="cost-ov-icon">{icon_map.get(c.model_name, "")}</span>' if icon_map.get(c.model_name) else ""
                    cost_rows.append(
                        f'<tr>'
                        f'<td><div class="cost-model-cell">{ic}<span class="font-medium">{esc(c.model_name)}</span></div></td>'
                        f'<td class="cell-cost">{format_cost(c.light_cost)}</td>'
                        f'<td class="cell-cost">{format_cost(c.typical_cost)}</td>'
                        f'<td class="cell-cost">{format_cost(c.heavy_cost)}</td>'
                        f'</tr>'
                    )
                cost_html = (
                    '<div class="cost-mini">'
                    '<table class="data-table cost-table"><thead><tr>'
                    f'<th><span data-i18n-zh>模型</span><span data-i18n-en>Model</span></th>'
                    f'<th><span data-i18n-zh>轻度 ({COST_SCENARIOS["light"]}T)</span><span data-i18n-en>Light ({COST_SCENARIOS["light"]}T)</span></th>'
                    f'<th><span data-i18n-zh>典型 ({COST_SCENARIOS["typical"]}T)</span><span data-i18n-en>Typical ({COST_SCENARIOS["typical"]}T)</span></th>'
                    f'<th><span data-i18n-zh>重度 ({COST_SCENARIOS["heavy"]}T)</span><span data-i18n-en>Heavy ({COST_SCENARIOS["heavy"]}T)</span></th>'
                    '</tr></thead><tbody>\n' + '\n'.join(cost_rows) + '\n</tbody></table>'
                    '<div class="cost-note">'
                    '<span data-i18n-zh>多轮会话成本估算（含 Prompt 缓存 + 输出 Token + 上下文累积）。'
                    f'假设每轮输出 {OUTPUT_PER_TURN} tokens，L2 文件在前 3 轮渐进加载。</span>'
                    '<span data-i18n-en>Multi-turn session cost estimate (with prompt caching + output tokens + context accumulation). '
                    f'Assumes {OUTPUT_PER_TURN} output tokens/turn, L2 files progressively loaded in first 3 turns.</span>'
                    '</div></div>'
                )

            card = (
                f'<div class="accordion-item" data-level="{r.risk_level}" '
                f'data-name="{esc(r.skill_name)}">'
                f'<button class="accordion-trigger">'
                f'<div class="accordion-trigger-left">'
                f'<span class="badge badge-level badge-{r.risk_level.lower()}">{r.risk_level}</span>'
                f'<span class="skill-name">{esc(r.skill_name)}</span>'
                f'{token_label}'
                f'</div>'
                f'<div class="accordion-trigger-right">'
                f'<div class="sev-pills">{"".join(pills)}</div>'
                f'{self._score_ring_svg(r.risk_score, r.risk_level)}'
                f'<svg class="chevron" xmlns="http://www.w3.org/2000/svg" viewBox="0 0 24 24" fill="none" '
                f'stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round">'
                f'<path d="m6 9 6 6 6-6"/></svg>'
                f'</div>'
                f'</button>'
                f'<div class="accordion-content"><div class="accordion-inner">{token_html}{cost_html}{table_html}</div></div>'
                f'</div>'
            )
            cards.append(card)

        html_content = Template(self.TEMPLATE).safe_substitute(
            timestamp=datetime.now(timezone.utc).strftime('%Y-%m-%d %H:%M UTC'),
            version=__version__,
            target=esc(target),
            total=total,
            count_a=by_level["A"], count_b=by_level["B"], count_c=by_level["C"],
            count_d=by_level["D"], count_f=by_level["F"],
            pct_a=f"{pcts['A']:.1f}", pct_b=f"{pcts['B']:.1f}",
            pct_c=f"{pcts['C']:.1f}", pct_d=f"{pcts['D']:.1f}",
            pct_f=f"{pcts['F']:.1f}",
            tok_total_l1l2=format_tokens(total_l1l2),
            tok_total_l3=format_tokens(sum_l3),
            tok_avg=format_tokens(avg_l1l2),
            tok_median=format_tokens(median_l1l2),
            tok_max=format_tokens(max_l1l2),
            tok_sum_l1=format_tokens(sum_l1),
            tok_sum_eager=format_tokens(sum_eager),
            tok_sum_lazy=format_tokens(sum_lazy),
            tok_sum_l3=format_tokens(sum_l3),
            tok_pct_l1=f"{tok_pct_l1:.1f}",
            tok_pct_eager=f"{tok_pct_eager:.1f}",
            tok_pct_lazy=f"{tok_pct_lazy:.1f}",
            tok_pct_l3=f"{tok_pct_l3:.1f}",
            tok_top5=tok_top5_html,
            cost_ov_cards=cost_ov_html,
            top10=top10_html,
            skill_cards='\n'.join(cards),
            methodology_filename=esc(methodology_filename),
        )

        output_path.write_text(html_content, encoding='utf-8')
        print(f"{C.GREEN}HTML report written to: {output_path}{C.RESET}")


# ── CLI ──────────────────────────────────────────────────────────────────────

def main():
    parser = argparse.ArgumentParser(
        description="Claude Code Skill Security Auditor",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="Examples:\n"
               "  python audit_skill.py /path/to/skill/\n"
               "  python audit_skill.py /path/to/marketplace/ --all\n"
               "  python audit_skill.py /path/to/marketplace/ --all --json report.json\n"
               "  python audit_skill.py /path/to/marketplace/ --all --html report.html\n"
               "  python audit_skill.py /path/to/marketplace/ --all --min-level C\n",
    )
    parser.add_argument("path", type=Path, help="Path to skill directory or marketplace")
    parser.add_argument("--all", action="store_true", help="Scan all skills in marketplace directory")
    parser.add_argument("--json", type=Path, metavar="FILE", help="Output JSON report to file")
    parser.add_argument("--html", type=Path, metavar="FILE", help="Output HTML report to file")
    parser.add_argument("--min-level", choices=["A", "B", "C", "D", "F"], default="A",
                        help="Minimum risk level to display in terminal (default: A = show all)")
    parser.add_argument("--min-severity", choices=["CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"],
                        default="INFO", help="Minimum severity to show in terminal findings")
    parser.add_argument("--version", action="version", version=f"audit_skill.py {__version__}")

    args = parser.parse_args()

    if not args.path.exists():
        print(f"{C.RED}Error: Path does not exist: {args.path}{C.RESET}", file=sys.stderr)
        sys.exit(1)

    auditor = SkillAuditor()
    terminal = TerminalRenderer()

    if args.all:
        print(f"{C.BOLD}Scanning marketplace: {args.path}{C.RESET}")
        reports = auditor.audit_marketplace(args.path)
        print(f"Scanned {len(reports)} skills.")

        # Show individual reports for filtered levels
        min_level = args.min_level
        for r in sorted(reports, key=lambda r: (-r.risk_score, r.skill_name)):
            if LEVEL_ORDER.get(r.risk_level, 4) <= LEVEL_ORDER.get(min_level, 4):
                terminal.render_report(r, min_severity=args.min_severity)

        terminal.render_summary(reports, min_level=min_level)
    else:
        print(f"{C.BOLD}Auditing skill: {args.path}{C.RESET}")
        report = auditor.audit_skill(args.path)
        reports = [report]
        terminal.render_report(report, min_severity=args.min_severity)

    # JSON output
    if args.json:
        JsonRenderer().render(reports, args.json, target=str(args.path))

    # HTML output
    if args.html:
        renderer = HtmlRenderer()
        methodology_path = args.html.parent / "methodology.html"
        renderer.render(reports, args.html, target=str(args.path), methodology_filename=methodology_path.name)
        renderer.render_methodology(methodology_path, report_filename=args.html.name)


if __name__ == "__main__":
    main()
