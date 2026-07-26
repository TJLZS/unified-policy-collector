# 实施规格：统一安全策略远程采集工具

## 目标

在 Linux 采集机上提供一个 Python 3.10+ CLI。用户输入目标类型、IP、端口、用户名和隐藏密码，工具远程采集 Linux、Windows 或安全设备策略，将结果下载到本地并清理远端临时目录。

## 必须实现

- `python main.py collect` 和 `python main.py check`；
- Linux与普通安全产品使用 SSH/SFTP；
- Windows使用 WinRM/NTLM，默认5985，支持HTTPS 5986；
- 堡塔云WAF与南墙uuwaf通过SSH登录Docker宿主机；
- 密码不写入YAML、日志或结果摘要；
- 状态分为 `success`、`partial`、`failed`；
- 结果写入 `outputs/<类型>/<IP>/<时间>/`；
- 远端使用UUID临时目录，并限制清理路径；
- 原有Linux和Windows脚本作为独立载荷副本复用，原目录不修改；
- Windows统一入口执行全部脚本并记录逐项结果；
- 注册 Suricata、Snort、ModSecurity、Zeek、Nuclei、堡塔云WAF和南墙uuwaf；
- 安全设备路径优先级为运行时覆盖、YAML覆盖、内置默认值；
- Docker WAF按容器名或镜像特征发现，不使用硬编码容器ID；
- 提供依赖清单、中文README、示例配置、自动化测试和类型检查。

## Web界面增补

- 在采集机本地提供Web控制台，复用同一采集器、适配器和结果目录；
- 支持连接检查、启动采集、任务状态及最近结果查看；
- 密码只存在于任务运行内存，不进入任务记录和接口响应；
- 默认仅监听回环地址，非本机监听必须显式确认；
- Web界面不改变“只读采集、不修改目标策略”的边界。

## 首版不包含

- Web界面、数据库或凭据持久化；
- 并发批量采集；
- 所有厂商专用API/CLI协议；
- 自动修改目标网络、防火墙、WinRM或安全策略。
