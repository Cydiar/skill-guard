# PRD-004: Phase 2 — 依赖审计

## 概述

在静态代码分析的基础上，扫描 Skill 引入的第三方依赖，比对已知漏洞数据库，输出 CVE 级别的风险报告。

## 支持的依赖类型

| 生态 | 文件 | 工具 |
|------|------|------|
| Python | `requirements.txt`, `Pipfile`, `pyproject.toml` | `pip-audit` |
| Node.js | `package.json`, `package-lock.json`, `yarn.lock` | `npm audit` |
| Go | `go.mod`, `go.sum` | `govulncheck` |
| Ruby | `Gemfile`, `Gemfile.lock` | `bundler-audit` |
| Dockerfile | `Dockerfile` | `trivy` (镜像层扫描) |

## 漏洞数据库

| 数据库 | 覆盖 | 更新频率 |
|--------|------|---------|
| OSV (Open Source Vulnerabilities) | Python, JS, Go, Rust | 实时 |
| NVD (National Vulnerability Database) | 全生态 | 每日 |
| GitHub Advisory Database | 全生态 | 实时 |

## 检测内容

### 2.1 已知漏洞 (CVE)

```
requests 2.28.0 → CVE-2023-32681 (MEDIUM)
  描述: 代理认证信息泄露
  修复: 升级到 2.31.0+
  参考: https://osv.dev/vulnerability/PYSEC-2023-xxx
```

### 2.2 版本锁定检查

| 问题 | 示例 | 严重度 |
|------|------|--------|
| 未锁定版本 | `requests>=2.0` | MEDIUM |
| 使用 latest 标签 | `FROM python:latest` | LOW |
| 缺少 hash 校验 | `pip install requests` | LOW |

### 2.3 许可证合规

在静态分析的许可证维度基础上增加：
- 解析实际依赖的许可证（通过 OSV/PyPI API）
- 标记 GPL/AGPL（需注意传染性）
- 标记商业限制许可证（CC-NC、proprietary）

### 2.4 供应链风险信号

| 信号 | 描述 |
|------|------|
| 包名相似度 | 检测 typosquatting（如 `reqeusts` vs `requests`） |
| 发布时间 | 包在 24h 内发布（可疑） |
| 下载量 | 极低下载量的冷门包 |
| 维护状态 | 依赖已 archived 的仓库 |

## 输出格式

### 报告新增区块

```
Dependency Audit
─────────────────────────────────
Python (requirements.txt)
  ✓ 12 dependencies scanned
  ⚠ 3 vulnerabilities found

  HIGH   requests 2.28.0
         CVE-2023-32681 · Proxy-Authorization header leak
         Fix: pip install "requests>=2.31.0"

  MEDIUM urllib3 1.26.0
         CVE-2023-45803 · Header injection
         Fix: pip install "urllib3>=2.0.7"

  LOW    certifi 2022.12.7
         CVE-2023-37920 · Outdated CA bundle
         Fix: pip install "certifi>=2023.7.22"

Node.js (package.json)
  ✓ No vulnerabilities found
```

## 性能目标

| 指标 | 目标 |
|------|------|
| 扫描耗时 | < 30s |
| 数据库查询 | 本地缓存 + 增量更新 |
| 支持离线运行 | 是（使用本地数据库快照） |
