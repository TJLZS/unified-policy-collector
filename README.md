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

## 2. 使用方式

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

## 3. 支持的安全设备

| 键 | 显示名称 | 连接方式 |
|---|---|---|
| `suricata` | Suricata | SSH 文件采集 |
| `snort` | Snort | SSH 文件采集 |
| `modsecurity` | ModSecurity | SSH 文件采集 |
| `zeek` | Zeek | SSH 文件采集 |
| `nuclei` | Nuclei | SSH 文件采集 |
| `bt_waf` | 堡塔云 WAF | SSH 到 Docker 宿主机 |
| `uuwaf` | 南墙 uuwaf | SSH 到 Docker 宿主机 |

新增设备时，在 `policy_collector/adapters.py` 注册默认路径、状态命令和连接特征即可；CLI、结果管理和传输实现无需修改。

## 4. Windows 默认采集参数

统一入口会继续执行全部脚本，即使其中某项失败：

- 密码策略：Local 和 Domain；
- ACL：`C:\`；
- 事件日志：Application、System、Security 各 100 条；
- LAPS：50 条；
- BitLocker：全部卷；
- GPO 和 Windows Update 报告：写入本次临时结果目录。

每项输出独立保存，并通过 `collection_manifest.json` 记录返回码。

## 5. 结果和退出码

结果目录：

```text
outputs/
└── <设备类型>/
    └── <目标IP>/
        └── <采集时间>/
            ├── collection_summary.json
            ├── execution.log
            └── data/
```

状态：

- `success`：所有采集模块成功，进程退出码 0；
- `partial`：至少一项成功、至少一项失败，进程退出码 2；
- `failed`：连接、传输或全部采集失败，进程退出码 1。

远端临时目录使用随机 UUID，并只在确认目录满足本项目安全格式时删除。

## 6. 测试

```bash
python -m pytest
python -m mypy policy_collector
```

实机演示建议先分别运行三次 `check`，再依次采集 Linux、Windows 和 WAF。
