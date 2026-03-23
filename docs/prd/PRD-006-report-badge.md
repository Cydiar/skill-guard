# PRD-006: Phase 4 — 报告系统与认证徽章

## 概述

生成综合安全报告（合并静态 + 依赖 + 沙箱），提供可分享链接和安全认证徽章。

## 综合评分模型

### 评分公式

```
最终评分 = 静态评分 × 0.4 + 依赖评分 × 0.2 + 行为评分 × 0.4
```

> **深度验证调整**：当 Deep Scan（Layer 2）完成后，静态评分会根据验证结果重算 — `mitigated` 的 Finding 移除扣分，`downgraded` 的按新 severity 计分。详见 PRD-005 §深度验证反驳机制。

### 评分细则

| 维度 | 权重 | 数据来源 |
|------|------|---------|
| 静态分析 | 40% | 10 维度 109 条规则（67 内置 + 42 可配置） |
| 依赖审计 | 20% | CVE 数量 × 严重度 |
| 行为分析 | 40% | 网络/文件/进程行为分类 |

### 等级映射（不变）

| 等级 | 分数范围 | 含义 |
|------|---------|------|
| A | 0-9 | Safe — 安全 |
| B | 10-29 | Acceptable — 可接受 |
| C | 30-49 | Warning — 警告 |
| D | 50-69 | Unsafe — 不安全 |
| F | 70-100 | Dangerous — 危险 |

## 报告页面

### 综合报告布局

```
┌─────────────────────────────────────────┐
│  SkillGuard Report                      │
│  skill-name · v1.0.0 (commit: a1b2c3d) │
│  Scanned: 2026-03-20 12:00 UTC          │
├─────────────────────────────────────────┤
│                                          │
│  Overall: C (Warning)  Score: 45/100    │
│  ┌──────┬──────┬──────┐                 │
│  │Static│ Deps │Behave│                 │
│  │  35  │  12  │  52  │                 │
│  │  B   │  B   │  D   │                 │
│  └──────┴──────┴──────┘                 │
│                                          │
│  Tab: [Static] [Dependencies] [Behavior]│
│                                          │
│  (各 Tab 下展示对应详细报告)             │
│                                          │
├─────────────────────────────────────────┤
│  Recommendations (Top 5)                │
│  1. Remove sudo from line 42            │
│  2. Upgrade requests to 2.31.0+         │
│  3. Review analytics.example.com        │
│  4. Add allowed-tools declaration       │
│  5. Pin npm dependencies                │
└─────────────────────────────────────────┘
```

### 报告功能

| 功能 | 描述 |
|------|------|
| **可分享链接** | `https://skillguard.dev/report/{scan_id}`，7 天有效 |
| **PDF 导出** | 一键导出完整报告 PDF |
| **JSON API** | `GET /api/report/{scan_id}` 返回结构化数据 |
| **历史对比** | 同一 Skill 多次扫描，展示趋势变化 |
| **中英双语** | 一键切换 CN/EN |

## 安全认证徽章

### 徽章设计

```
┌────────────────────────────┐
│  🛡️ SkillGuard │ A  Safe  │  ← 绿色徽章
└────────────────────────────┘

┌────────────────────────────┐
│  🛡️ SkillGuard │ C  Warn  │  ← 黄色徽章
└────────────────────────────┘
```

### 使用方式

**Markdown 嵌入**（README.md）：

```markdown
[![SkillGuard](https://skillguard.dev/badge/{scan_id})](https://skillguard.dev/report/{scan_id})
```

**HTML 嵌入**：

```html
<a href="https://skillguard.dev/report/{scan_id}">
  <img src="https://skillguard.dev/badge/{scan_id}" alt="SkillGuard Rating">
</a>
```

### 徽章 API

```
GET /badge/{scan_id}
→ 返回 SVG 徽章

GET /badge/{scan_id}?style=flat
GET /badge/{scan_id}?style=flat-square
GET /badge/{scan_id}?style=for-the-badge
```

### 认证有效期

| 类型 | 有效期 | 触发更新 |
|------|-------|---------|
| 免费扫描 | 7 天 | 手动重新扫描 |
| 认证徽章 (付费) | 90 天 | 自动每周重新扫描 |

## 变现模型

### 免费版

- 每天 10 次扫描
- 报告保存 7 天
- 基础徽章（含 "Free" 标记）
- 无历史对比

### Pro 版（$9.9/月）

- 无限扫描
- 报告永久保存
- 认证徽章（无 "Free" 标记）
- 历史对比趋势图
- PDF 导出
- GitHub Webhook（push 时自动重新扫描）

### Team 版（$49/月）

- 团队成员管理
- 批量扫描 API
- 自定义规则配置
- 合规报告导出（SOC2 格式）
- 优先支持
