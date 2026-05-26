# AntV npm 投毒事件 · 完整应急响应方案

> **事件代号**：Mini Shai-Hulud
> **发生时间**：2026-05-19
> **影响范围**：323 个 npm 包 / 周下载量约 1600 万次
> **攻击者**：威胁组织 TeamPCP
> **本文档版本**：v1.0

这是一份按时间序排列的完整应急响应清单（runbook），按照"**止血 → 检测 → 凭据轮换 → 清理 → 加固**"的顺序展开。对于受影响的项目，**前 4 个阶段务必在 24 小时内完成**，凭据轮换尤其紧急。

---

## 目录

- [阶段 0 · 影响面预判](#阶段-0--影响面预判2-分钟)
- [阶段 1 · 立即止血](#阶段-1--立即止血5-分钟内)
- [阶段 2 · 检测](#阶段-2--检测30-分钟)
- [阶段 3 · 凭据轮换](#阶段-3--凭据轮换最优先2-小时内完成-)
- [阶段 4 · 清理与重装](#阶段-4--清理与重装)
- [阶段 5 · CI/CD 专项处置](#阶段-5--cicd-专项处置)
- [阶段 6 · 长期加固](#阶段-6--长期加固一周内完成)
- [阶段 7 · 持续监控](#阶段-7--持续监控接下来-30-天)
- [应急联系方式](#应急联系方式)
- [团队简报模板](#最后一份给团队老板看的简报)

---

## 阶段 0 · 影响面预判（2 分钟）

如果以下任一条为真，您**必须**完整走完本方案；如果全部为否，仅需走阶段 1 + 阶段 6 做预防加固即可。

- [ ] 在 **2026-05-19 之后**对任何 Node.js 项目执行过 `npm install` / `pnpm install` / `yarn install`
- [ ] 项目依赖中**直接或间接**使用了 `@antv/*`、`echarts-for-react`、`timeago.js`、`size-sensor`、`canvas-nest.js`
- [ ] CI/CD（特别是 GitHub Actions）在攻击窗口期触发过包含上述依赖项目的构建
- [ ] 开发机或构建机上**存放过**云密钥、GitHub PAT、npm token、`.env` 文件

### 受影响包完整列表

| 命名空间 | 受影响包 |
|---------|---------|
| `@antv/*` | `g`、`g2`、`g6`、`x6`、`l7`、`s2`、`f2`、`g2plot`、`graphin`、`data-set` 等 |
| 非 @antv | `echarts-for-react`（周下载 110 万）、`timeago.js`（周下载 150 万）、`size-sensor`、`canvas-nest.js` 等 |

### 恶意载荷能力

- 读取 GitHub Actions Runner 进程内存，dump 已掩码（masked）的 CI/CD secret
- 扫描 130+ 个文件路径，收集 AWS / GCP / Azure / Kubernetes / Vault / 加密货币钱包凭据
- **双通道外发**：
  - 主通道：dead-drop 到 `antvis/G2` GitHub 仓库
  - 备用 C2：`t.m-kosche.com`（伪装成 OpenTelemetry collector）
- 用偷到的 npm token 自传播感染更多包

---

## 阶段 1 · 立即止血（5 分钟内）

目标：**阻止恶意代码继续运行 / 联网 / 二次传播**。

### 1.1 暂停所有 CI/CD 工作流

```powershell
# GitHub Actions: 在 .github/workflows/ 下临时禁用关键工作流
# 或在 GitHub 网页端: Settings → Actions → Disable Actions
```

```yaml
# GitLab CI: 在 .gitlab-ci.yml 顶部加
workflow:
  rules:
    - when: never
```

### 1.2 阻断 C2 域名（本机 + 防火墙双重）

```powershell
# Windows hosts 文件 (需管理员权限)
Add-Content -Path "$env:SystemRoot\System32\drivers\etc\hosts" -Value @"
0.0.0.0 t.m-kosche.com
0.0.0.0 m-kosche.com
"@

# Windows Defender 防火墙: 阻断出站到该域名解析的所有 IP
Resolve-DnsName t.m-kosche.com -ErrorAction SilentlyContinue | ForEach-Object {
    New-NetFirewallRule -DisplayName "Block AntV C2 $($_.IPAddress)" `
        -Direction Outbound -Action Block -RemoteAddress $_.IPAddress
}
```

### 1.3 暂停所有 `npm publish` 并撤销 token 写权限

如果您是 npm 包维护者：

```powershell
# 列出所有 token, 临时撤销 publish 权限避免被借您的身份继续投毒
npm token list
npm token revoke <token-id>   # 对每一个 publish 权限的 token 都执行
```

---

## 阶段 2 · 检测（30 分钟）

### 2.1 跑扫描脚本

```powershell
# 单个项目
python D:\环境\LLM\Claude\antv_scan.py D:\your\project --json scan.json

# 整盘 + 全局 npm
python D:\环境\LLM\Claude\antv_scan.py D: --include-global --json scan-d.json

# 深度模式 (慢, 但能发现传染到非 @antv 包的情况)
python D:\环境\LLM\Claude\antv_scan.py D:\your\project --deep
```

记录所有 `CRITICAL` 和 `HIGH` 级别的命中。

### 2.2 检查 GitHub Actions / CI 日志

重点看 **2026-05-19 ~ 2026-05-20** 期间所有 run 的：

- 出站网络请求（看是否有到 `t.m-kosche.com` 或 `api.github.com/repos/antvis/G2/issues|commits`）
- secret 使用日志（看是否有未在脚本中显式使用、却被读取的 secret）
- 异常长的 `npm install` 步骤（恶意载荷需要时间下载和执行）

```powershell
# 用 gh CLI 拉最近的 workflow runs
gh run list --limit 50 --created '>=2026-05-19' --json conclusion,createdAt,displayTitle,databaseId
gh run view <run-id> --log > run.log
Select-String -Path run.log -Pattern "kosche|antvis/G2|atob|Buffer\.from"
```

### 2.3 检查 `antvis/G2` 仓库的 dead-drop 痕迹

恶意软件会把窃取的数据**伪装成 issue 评论或 commit** 提交到合法的 `antvis/G2` 仓库。访问：

- <https://github.com/antvis/G2/issues?q=is%3Aissue+created%3A2026-05-19..2026-05-25>
- <https://github.com/antvis/G2/commits/main>

如果发现自己机器的 git config 出现在异常 issue/commit 里 → **强证据**，按完整流程处置。

### 2.4 云账户异常检查

| 云厂 | 检查项 | 命令/位置 |
|------|------|---------|
| AWS | CloudTrail `Console`/`API` 登录、`IAM CreateAccessKey` 事件、异常区域调用 | `aws cloudtrail lookup-events --start-time 2026-05-19T00:00:00Z` |
| GCP | Cloud Audit Logs，`iam.serviceAccountKeys.create` | Console → Logging |
| Azure | Activity Log，`Microsoft.Authorization/*` | Portal → Monitor → Activity log |
| GitHub | Security log，`personal_access_token` 创建/使用 | Settings → Security log |

---

## 阶段 3 · 凭据轮换（最优先，2 小时内完成）⚠️

恶意软件已确认会扫描 130+ 个文件路径，**必须假设所有出现在开发机/CI 上的凭据已泄露**。轮换顺序按"破坏力"降序：

### 3.1 高优先级（立即轮换）

| 凭据类型 | 轮换方式 |
|---------|---------|
| **AWS Access Key** | IAM → Users → Security credentials → Make inactive → Delete，重建新 key 写入新位置 |
| **GCP Service Account Key** | `gcloud iam service-accounts keys delete <KEY_ID> --iam-account=<SA>` |
| **Azure Service Principal** | `az ad sp credential reset --id <appId>` |
| **GitHub PAT** | <https://github.com/settings/tokens> → Revoke all → 重建 fine-grained PAT |
| **GitHub Actions secrets** | Repo/Org Settings → Secrets → 逐个轮换 |
| **npm Token** | `npm token revoke <id>`，重建并启用 2FA + granular access |

### 3.2 中优先级（24 小时内）

- `.env` 中所有 API key（OpenAI、Anthropic、Stripe、SendGrid 等）
- 数据库密码（Postgres、MySQL、MongoDB、Redis）
- Kubernetes `kubeconfig` token、`kubectl` certificates
- HashiCorp Vault token
- SSH 私钥（特别是 `~/.ssh/id_*`，恶意软件会读）
- Docker Registry 凭据（`~/.docker/config.json`）
- 浏览器/CLI 中保存的 Slack / Discord / Jira webhook URL

### 3.3 加密货币钱包（如有）

如果开发机上存在加密货币钱包文件（MetaMask、Phantom、Solana CLI、`*.wallet`、`keystore` 目录等）：

> **立即将资产转移到新地址**——攻击者明确扫描这些路径。

### 3.4 GitHub Actions 改造（趁机做掉）

把长期 secret 替换成 **OIDC 联邦凭据**，从根上消除"长期 token 被偷"的风险：

```yaml
# 改造前
- uses: aws-actions/configure-aws-credentials@v4
  with:
    aws-access-key-id: ${{ secrets.AWS_ACCESS_KEY_ID }}
    aws-secret-access-key: ${{ secrets.AWS_SECRET_ACCESS_KEY }}

# 改造后 (OIDC, 无长期密钥)
permissions:
  id-token: write
  contents: read
- uses: aws-actions/configure-aws-credentials@v4
  with:
    role-to-assume: arn:aws:iam::<ACCOUNT_ID>:role/<ROLE>
    aws-region: us-east-1
```

---

## 阶段 4 · 清理与重装

### 4.1 彻底清理本地痕迹

```powershell
# 进入受影响项目
cd D:\your\project

# 删除 node_modules 和所有 lockfile
Remove-Item -Recurse -Force node_modules, package-lock.json, pnpm-lock.yaml, yarn.lock -ErrorAction SilentlyContinue

# 清 npm 全局缓存
npm cache clean --force

# 清 pnpm store (如使用)
pnpm store prune

# 清用户级 npm 缓存目录
Remove-Item -Recurse -Force "$env:LOCALAPPDATA\npm-cache" -ErrorAction SilentlyContinue
Remove-Item -Recurse -Force "$env:APPDATA\npm-cache" -ErrorAction SilentlyContinue
```

### 4.2 锁版本到攻击前的已知干净版本

在 `package.json` 中**显式锁定**并加 `overrides`/`resolutions` 防止传递依赖拉回坏版本：

```jsonc
{
  "dependencies": {
    "@antv/g2": "5.2.x",          // 锁到 5/19 前发布的版本号
    "echarts-for-react": "3.0.2"  // 以发布时间在 5/19 前的为准
  },
  // npm / pnpm
  "overrides": {
    "@antv/g": "$@antv/g",
    "@antv/g2": "$@antv/g2",
    "@antv/g6": "$@antv/g6",
    "echarts-for-react": "3.0.2",
    "timeago.js": "4.0.2",
    "size-sensor": "1.0.1"
  },
  // yarn
  "resolutions": {
    "@antv/g2": "5.2.x",
    "echarts-for-react": "3.0.2"
  }
}
```

> **具体安全版本号请以 Snyk Advisory 实时数据为准**：<https://security.snyk.io/package/npm/@antv%2Fg2> （把 g2 换成对应包名）。本文示例版本号仅为占位，请勿直接复制。

### 4.3 用 `npm ci` 而不是 `npm install` 重装

```powershell
# 关闭 install 脚本 (极重要！防止万一仍然中招的包执行 postinstall)
npm config set ignore-scripts true --location=project

# 用 ci 严格按 lockfile 安装
npm ci

# 验证完毕、确认干净后再决定是否打开脚本 (建议保持关闭)
# npm config delete ignore-scripts --location=project
```

### 4.4 复跑扫描脚本验证

```powershell
python D:\环境\LLM\Claude\antv_scan.py D:\your\project --deep
# 期望输出: [OK] 未发现受影响的包或可疑特征.
```

---

## 阶段 5 · CI/CD 专项处置

GitHub Actions 是这次攻击的**主战场**，需要单独处理：

### 5.1 立即清理 GitHub 侧痕迹

```bash
# 列出所有 self-hosted runner 并下线 (避免 runner 上残留)
gh api /repos/<owner>/<repo>/actions/runners

# 删除可疑 workflow runs (可选, 用于审计后)
gh run delete <run-id>

# 重新生成所有 secrets
gh secret set AWS_ACCESS_KEY_ID --body "<new-value>"
```

### 5.2 强化 workflow 配置

```yaml
# .github/workflows/build.yml
permissions:
  contents: read         # 最小权限
  id-token: write        # OIDC 用

jobs:
  build:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
        with:
          persist-credentials: false   # 不在 runner 上留 git token

      - uses: actions/setup-node@v4
        with:
          node-version: '20'

      # 关键: 用 npm ci + 禁脚本
      - run: npm ci --ignore-scripts

      # 加 audit 阶段
      - run: npm audit signatures
      - run: npx better-npm-audit audit --level high
```

### 5.3 加装 install-time 扫描

在 `package.json` 加 `preinstall` 守门员（讽刺但有效）：

```json
{
  "scripts": {
    "preinstall": "npx --yes @socketsecurity/cli install"
  }
}
```

或者用 GitHub Action：

```yaml
- uses: socketdev/socket-security-action@v1
  with:
    api-key: ${{ secrets.SOCKET_API_KEY }}
```

---

## 阶段 6 · 长期加固（一周内完成）

### 6.1 工具链层

| 工具 | 作用 | 推荐配置 |
|------|------|---------|
| **Socket** | npm install 前实时分析包行为 | `npx @socketsecurity/cli` |
| **Snyk** | 漏洞数据库 + CI 集成 | `snyk test --severity-threshold=high` |
| **StepSecurity** | GitHub Actions 出站监控 | `step-security/harden-runner` |
| **npm-audit-resolver** | 持续追踪受影响版本 | 加入 CI |

### 6.2 npm 配置加固（机器级）

```powershell
# 全局禁 install 脚本 (最强一道防线, 但会破坏一些合法依赖如 esbuild/sharp)
npm config set ignore-scripts true

# 强制走 lockfile
npm config set save-exact true

# 启用 2FA (npm 账号)
npm profile enable-2fa auth-and-writes
```

### 6.3 流程层

- **强制 PR review 才能合并 lockfile 变更**：在 GitHub 设置 CODEOWNERS 把 `package-lock.json` 指给安全负责人。
- **定期跑 `npm audit signatures`**：验证包签名，能发现部分仿冒。
- **依赖更新走 Renovate / Dependabot 自动 PR**：人工 review 时容易看出异常版本跳跃。
- **建立 SBOM**：用 `cyclonedx-npm` 生成依赖清单，便于未来事件快速定位。

### 6.4 主机层

- 开发机上**不要常驻**云密钥；改用短时凭据（`aws-vault`、`gcloud auth application-default login`）
- `.env` 文件用 `direnv` + `pass` / `1password CLI` 动态注入，不要明文落盘
- 加密货币钱包**不要**装在日常开发机上
- 用专门的容器/VM 跑 `npm install`（Dev Container 是个低成本方案）

---

## 阶段 7 · 持续监控（接下来 30 天）

设置告警，关注以下信号：

- [ ] 云账单异常增长（被偷的密钥常被用于挖矿）
- [ ] GitHub 仓库出现非预期的 push / fork
- [ ] npm 账户出现非预期的 publish
- [ ] 个人邮箱收到任何"新设备登录"通知
- [ ] 公司 SSO 日志中出现陌生 IP / User-Agent

---

## 应急联系方式

如果发现已**确实**被攻击（CRITICAL 命中 + 凭据被滥用迹象）：

| 厂商 | 应急通道 |
|------|---------|
| AWS | <https://aws.amazon.com/security/security-bulletins/> → Contact Support → 选 Security |
| GitHub | <https://github.com/contact/report-abuse> |
| npm | <security@npmjs.com> |
| 国内云 | 阿里云/腾讯云提工单时选"账号安全" |

---

## 最后：一份给团队/老板看的简报

> **事件**：2026-05-19，AntV 生态及关联 npm 包遭"Mini Shai-Hulud"供应链投毒，323 个包被植入凭据窃取后门。
>
> **我们的暴露面**：[填写扫描结果]
>
> **已完成动作**：
>
> 1. 已暂停受影响项目的 CI/CD
> 2. 已完成 [N] 个云密钥、[M] 个 GitHub token、[K] 个 npm token 的轮换
> 3. 已删除并以 5/19 前版本重装所有受影响项目
> 4. 已在 CI 中接入 Socket + Snyk 双重扫描
>
> **风险等级**：[评估]
>
> **后续监控周期**：30 天
>
> **责任人**：[填写]

---

## 参考来源

- [Mini Shai Hulud: Compromised @antv npm packages enable CI/CD credential theft (Microsoft Security Blog)](https://www.microsoft.com/en-us/security/blog/2026/05/20/mini-shai-hulud-compromised-antv-npm-packages-enable-ci-cd-credential-theft/)
- [Mini Shai-Hulud Hits AntV: 300+ Malicious npm Packages (Snyk)](https://snyk.io/blog/mini-shai-hulud-antv-npm-supply-chain-attack/)
- [Shai-Hulud: Here We Go Again. Mass npm Supply Chain Attack Hits the AntV Ecosystem (StepSecurity)](https://www.stepsecurity.io/blog/shai-hulud-here-we-go-again-mass-npm-supply-chain-attack-hits-the-antv-ecosystem)
- [Active Supply Chain Attack Compromises @antv Packages on npm (Socket)](https://socket.dev/blog/antv-packages-compromised)
- [Mini Shai-Hulud Pushes Malicious AntV npm Packages (The Hacker News)](https://thehackernews.com/2026/05/mini-shai-hulud-pushes-malicious-antv.html)
- [Massive npm Supply Chain Attack Compromises AntV Ecosystem (Orca Security)](https://orca.security/resources/blog/antv-npm-supply-chain-attack/)
