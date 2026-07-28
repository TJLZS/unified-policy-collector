# 统一安全策略远程采集工具

本项目部署在一台 Linux 采集机上，通过统一命令行远程采集：

- Linux 主机安全策略；
- Windows 主机安全策略；
- Suricata、Snort、ModSecurity、Zeek、Nuclei；
- Docker 宿主机中的堡塔云 WAF 和南墙 uuwaf。

项目只读取配置、规则和状态，不修改或重载目标设备的安全策略。原始三套采集脚本保留不变，本项目使用独立载荷副本。

## 1. 环境要求

采集机：

- Linux；
- Python 3.10 或更高版本；
- 能够访问目标设备的 SSH 或 WinRM 管理端口。

安装：

```bash
cd 统一策略采集项目
python3 -m venv .venv
source .venv/bin/activate
python -m pip install --upgrade pip
python -m pip install -r requirements.txt
```

目标 Linux/安全设备宿主机：

- SSH 服务可用；
- 存在 `python3` 和 `tar`；
- 需要读取系统策略时，账号应具备相应权限；
- 使用 `--sudo` 时，账号应允许 sudo。

SSH 默认校验采集机的 `~/.ssh/known_hosts`，建议先人工执行一次
`ssh 用户名@目标IP` 并核对主机指纹。只有在隔离靶场且已通过其他方式确认目标身份时，
才可显式增加 `--trust-new-host-key`。

目标 Windows：

- Windows PowerShell 5.1 或更高版本；
- 启用 WinRM；
- 账号具备管理员权限；
- 存在 `Compress-Archive`。

可在 Windows 管理员 PowerShell 中检查：

```powershell
winrm quickconfig
Enable-PSRemoting -Force
Test-WSMan localhost
Get-Command Compress-Archive
```

默认使用 WinRM HTTP/NTLM 端口 5985。HTTPS 使用 5986 和 `--https`；只有靶场使用自签名证书且确认风险时才增加 `--insecure`。

## 2. Web界面（推荐演示方式）

在采集机上启动：

```bash
python web.py
```

然后使用采集机本机浏览器访问：

```text
http://127.0.0.1:8080
```

Web界面支持：

- Windows、Linux和安全设备目标切换；
- 7种内置安全设备适配器及可见的默认规则路径；
- 可在页面中临时添加自定义安全设备，填写设备名称、规则文件类型、部署方式和规则路径；
- 安全设备规则路径可逐行修改，并可一键恢复适配器默认值；
- 连接与能力检查；
- 后台执行采集并实时显示任务状态；
- 查看最近采集的原始状态、分析后有效状态和各状态数量；
- 进入独立分析页查看失败原因、返回码、脱敏证据和处理建议；
- 按模块名搜索、按状态筛选并下载 JSON 分析报告；
- sudo、HTTPS WinRM、Docker容器名称和自定义规则路径等高级选项。

密码和sudo密码只保留在任务执行期间的内存中，不会进入Web任务记录、
日志、配置文件或结果摘要。任务完成后，页面表单中的密码会被清空。
服务同一时间只执行一个远程任务，其余任务进入内存队列；服务重启会清空
页面任务列表，但已写入 `outputs/` 的采集结果仍会显示在最近结果中。

### Web 自定义安全设备

在“安全设备类型”中选择“自定义安全设备”，然后填写：

1. 设备名称，例如“自研 WAF”；
2. 规则文件类型，例如 `rules`、`.rules` 或 `*.rules`；
3. 部署方式：宿主机（本地部署）或 Docker 容器部署；
4. 至少一个绝对规则文件或目录路径，每行一个；
5. Docker 部署还必须填写准确的容器名称。

采集机会通过 SSH 连接目标宿主机。宿主机部署直接读取目标路径；Docker 部署
从指定容器读取目标路径。目录中只会下载与规则文件类型后缀一致的文件，例如
填写 `.rules` 时不会带回 `.conf` 文件。设备定义只用于当前任务，不会保存密码，
也不会写入全局适配器配置；采集摘要和分析报告会保留设备名称、文件类型和部署
方式，便于后续审计。

服务默认只监听 `127.0.0.1`。如果确实需要从其他电脑访问，必须显式运行：

```bash
python web.py --host 0.0.0.0 --allow-remote
```

远程开放前必须在采集机前方配置HTTPS、访问控制和防火墙白名单；项目首版
不自带用户登录系统，不应将该端口暴露到办公网或互联网。

## 3. CLI使用方式

### 交互采集

```bash
python main.py collect
```

工具会依次询问设备类型、IP、端口、用户名和密码。密码使用隐藏输入，不写入配置、日志或结果摘要。

### 命令行指定非敏感信息

Linux：

```bash
python main.py collect \
  --type linux \
  --host 192.168.10.10 \
  --port 22 \
  --username collector \
  --sudo
```

Windows：

```bash
python main.py collect \
  --type windows \
  --host 192.168.10.20 \
  --port 5985 \
  --username Administrator
```

ModSecurity：

```bash
python main.py collect \
  --type security \
  --security-device modsecurity \
  --host 192.168.10.30 \
  --username collector \
  --sudo
```

Docker WAF（IP 指向 Docker 宿主机）：

```bash
python main.py collect \
  --type security \
  --security-device bt_waf \
  --host 192.168.10.40 \
  --username collector \
  --sudo
```

默认按容器名称和镜像特征自动查找容器。如果存在多个匹配项：

```bash
python main.py collect \
  --type security \
  --security-device uuwaf \
  --host 192.168.10.40 \
  --username collector \
  --container-name uuwaf
```

### 仅检查连接

`check` 会验证端口、认证和必要能力，不上传采集载荷：

```bash
python main.py check \
  --type linux \
  --host 192.168.10.10 \
  --username collector
```

Linux及安全设备的检查项包括 `python3`、`tar`，启用 `--sudo` 时还会验证
本次输入的 sudo 凭据。Windows会检查 PowerShell 和 `Compress-Archive`。

### YAML 高级配置

复制 `config/targets.example.yaml` 后修改非敏感字段：

```bash
python main.py collect --config config/my-target.yaml
```

配置文件严禁出现 `password`、`token`、`secret` 或 `authorization` 等敏感字段；工具发现后会拒绝运行。

安全设备路径优先级：

1. 本次 `--path` 参数；
2. YAML 中 `security_devices.<设备>.paths`；
3. 适配器内置默认路径。

普通演示无需填写规则路径。仅当实际安装目录不同才使用：

```bash
python main.py collect \
  --type security \
  --security-device modsecurity \
  --host 192.168.10.30 \
  --username collector \
  --path /srv/modsecurity/rules
```

## 4. 支持的安全设备

| 键 | 显示名称 | 连接方式 |
|---|---|---|
| `suricata` | Suricata | SSH 文件采集 |
| `snort` | Snort | SSH 文件采集 |
| `modsecurity` | ModSecurity | SSH 文件采集 |
| `zeek` | Zeek | SSH 文件采集 |
| `nuclei` | Nuclei | SSH 文件采集 |
| `bt_waf` | 堡塔云 WAF | SSH 到 Docker 宿主机 |
| `uuwaf` | 南墙 uuwaf | SSH 到 Docker 宿主机 |
| `custom` | 自定义安全设备（Web） | SSH 文件采集或 SSH 到指定 Docker 容器 |

临时设备可直接通过 Web 表单添加，无需修改代码。需要长期固定默认路径、状态命令
或容器识别特征时，再在 `policy_collector/adapters.py` 注册内置适配器；CLI、结果
管理和传输实现无需修改。

## 5. Windows 默认采集参数

统一入口会继续执行全部脚本，即使其中某项失败：

- 密码策略：Local 和 Domain；
- ACL：`C:\`；
- 事件日志：Application、System、Security 各 100 条；
- LAPS：50 条；
- BitLocker：全部卷；
- GPO 和 Windows Update 报告：写入本次临时结果目录。

每项输出独立保存，并通过 `collection_manifest.json` 记录返回码。

## 6. 结果、分析状态和退出码

结果目录：

```text
outputs/
└── <设备类型>/
    └── <目标IP>/
        └── <采集时间>/
            ├── collection_summary.json
            ├── analysis_report.json
            ├── execution.log
            └── data/
```

`collection_summary.json` 保存采集当时的原始审计事实，分析功能不会修改它。
`analysis_report.json` 是本地离线分析结果；历史记录首次打开详情页时会自动生成。
当分析器版本变化或原始结果文件发生变化时，报告会自动重新生成。

原始采集状态：

- `success`：所有原始采集模块成功，进程退出码 0；
- `partial`：至少一项原始采集成功、至少一项失败，进程退出码 2；
- `failed`：连接、传输或全部原始采集失败，进程退出码 1。

分析项状态：

- `success`：该适用模块已采集成功；
- `failed`：该适用模块采集失败；
- `not_applicable`：确认目标未安装该条件功能、未加入域，或默认候选路径无需命中；
- `skipped`：该模块未进入本次采集范围。

分析后有效状态：

- `success`：所有适用模块成功；不适用和跳过项不影响成功；
- `partial`：至少一个适用模块成功，同时至少一个适用模块失败；
- `failed`：没有适用模块成功，或连接、上传、执行、打包、下载等整体流程失败。

远端临时目录使用随机 UUID，并只在确认目录满足本项目安全格式时删除。
如果已有采集项成功但远端清理失败，清理会作为独立失败项记录，最终状态为
`partial`，便于人工核查残留目录。

## 7. 本地结果分析

分析完全在采集机本地执行，不连接目标设备、不调用外部 AI，也不会修改安全
策略。失败原因会按权限不足、依赖或功能缺失、未加入域、规则路径不存在、
Docker 容器不存在或匹配不唯一、命令执行、传输、打包和远端清理等类型归类。
无法识别的异常保守标记为失败，并提示人工核查。

Windows 的证书、事件日志、防火墙、补丁、更新、审计、服务、ACL、本地用户、
本地密码策略和 UAC 是基线模块；BitLocker、LAPS、Defender、GPO 和域密码策略
按目标功能判断是否适用。Linux 的 Firewall、ACL、StartupItems 和
User_identity 是基线模块，其他服务按安装痕迹判断。普通安全设备的默认候选
路径命中任意一项即可；手工或 YAML 覆盖的路径全部视为必采。Docker WAF 的
固定规则路径和唯一容器匹配始终是必需项。

自定义安全设备没有默认候选路径，用户填写的每一条路径都视为必采；路径不存在、
目录内没有指定类型的规则文件或 Docker 容器不可用时，分析页会把对应项目标记为
失败并显示原因和处理建议。

详情页只展示白名单结果文件中的短证据片段，单文件读取大小和展示长度均有限制，
并沿用密码、令牌和认证头脱敏规则。完整原始日志不会直接显示在页面中。

结果接口：

- `GET /api/runs`：记录列表、双状态和状态数量；
- `GET /api/runs/{run_id}`：完整分析详情；
- `GET /api/runs/{run_id}/report`：下载 `analysis_report.json`。

`run_id` 是根据 `outputs/` 内部记录生成的不可伪造标识。接口不接受客户端文件
路径，未知标识和路径穿越输入会返回 404。旧结果缺少新清单字段时，会结合旧清单、
日志特征和已知输出目录进行兼容分析。

## 8. 测试

```bash
python -m pytest
python -m mypy policy_collector
```

实机演示建议先分别运行三次 `check`，再依次采集 Linux、Windows 和 WAF。
