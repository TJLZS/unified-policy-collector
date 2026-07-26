# Linux 安全策略收集脚本

Linux 安全策略统一采集工具，用于收集系统各类安全配置、策略文件、运行状态等信息，并生成安全分析报告。支持断点恢复、进度条、模块化扩展。

---

## 目录结构

```
Scripts/
├── README.md                    # 本文档
├── main.py                 # 统一采集入口（推荐）
│
├── core/                        # 公共核心组件
│   ├── __init__.py
│   ├── checkpoint.py            # 断点恢复
│   ├── checksum.py              # 文件校验和
│   ├── collector_base.py        # 采集模块基类
│   ├── strategy_runner.py       # 策略采集器基类
│   ├── progress.py              # 进度条
│   ├── logging_utils.py         # 日志配置
│   └── system_info.py           # 系统类型检测
│
├── strategy_config/             # 策略路径与命令配置
│   ├── __init__.py
│   ├── paths_commands.py        # 路径/命令数据结构与工厂
│   ├── apache_config.py
│   ├── selinux_config.py
│   ├── nginx_config.py
│   ├── mysql_config.py
│   ├── firewall_config.py
│   ├── ...（各策略 xxx_config.py）
│   └── user_identity_config.py  # 聚合 PAM/SSH/SSL 等
│
├── analyzer/                    # 采集结果安全分析
│   ├── __init__.py
│   ├── base.py                  # 分析器基类
│   ├── apache_analyzer.py
│   ├── selinux_analyzer.py
│   ├── nginx_analyzer.py
│   ├── ...（各策略 xxx_analyzer.py）
│   └── k8s_analyzer.py
│
├────────────────────────────
```

---

## 运行方式

main.py（统一采集入口）

基于 `core`、`strategy_config`、`analyzer` 的统一采集，支持断点恢复、进度条、摘要报告。

**参数说明**：
- `--all`：从头开始执行所有策略模块（默认）
- `--select`：选择某个/某些策略模块执行
- `--resume`：从断点开始，跳过已完成策略
- `--refresh`：检查文件更新，按校验和增量更新（默认开启）
- `--no-refresh`：禁用文件更新检查，强制全量覆盖

```bash
cd Scripts

# 从头执行所有策略（默认）
python main.py --all

# 从断点继续（跳过已完成）
python main.py --all --resume

# 选择部分策略执行
python main.py --select Apache SELinux Nginx MySQL

# 选择策略并断点续采
python main.py --select ACL --resume

# 禁用校验和增量更新，强制全量覆盖
python main.py --all --no-refresh

# 指定输出目录
python main.py --all -o /path/to/output

# 列出所有可用策略
python main.py --list
```


## 输出目录结构

```
Collected_files/                    # 或 -o 指定目录
├── test_collection_checkpoint.json # 顶层断点
├── test_collection.log             # 顶层日志
│
├── Linux_apache_config/
│   ├── Apache/
│   │   ├── config_files/           # 配置文件与策略文件（统一存放）
│   │   ├── status_info/            # 状态命令输出
│   │   ├── logs/                   # 日志
│   │   ├── file_statistics.json
│   │   └── apache_security_analysis.json
│   ├── Apache策略采集摘要.txt
│   ├── apache_collection.log
│   └── collection_checkpoint.json
│
├── Linux_selinux_config/
├── Linux_nginx_config/
├── Linux_mysql_config/
├── Linux_firewall_config/          # Iptables + Firewalld 双模块
├── Linux_docker_config/
├── Linux_k8s_security_config/
└── ...
```

---

## 核心模块说明

### core 包

| 模块 | 类/函数 | 作用 |
|------|---------|------|
| **checkpoint.py** | `CheckpointManager` | 断点恢复：加载/保存 `completed_modules`、`file_checksums`、`system_type` |
| | `save_checkpoint(module_name, completed)` | 保存检查点 |
| | `is_module_completed(module_name)` | 判断模块是否已完成 |
| **checksum.py** | `file_checksum(path, algorithm)` | 计算文件 MD5/SHA256 校验和 |
| | `FileChecksumHelper` | 结合断点判断文件是否变化，跳过未变化文件的重复复制 |
| **collector_base.py** | `CollectorModuleBase` | 采集模块基类 |
| | `_copy_file()`, `_copy_directory()` | 复制文件/目录到 output_dir |
| | `_run_command(cmd, output_file)` | 执行 shell 命令并保存输出 |
| | `_add_to_manifest()` | 登记采集文件到清单 |
| | `_generate_file_statistics()` | 生成 file_statistics.json |
| **strategy_runner.py** | `StrategyCollectorBase` | 策略采集器基类 |
| | `run()` | 遍历模块、断点跳过、执行 collect、进度条、on_after_collect |
| | `on_after_collect()` | 采集结束后钩子，可生成报告 |
| **progress.py** | `create_progress_bar()` | 创建 tqdm 进度条 |
| | `update_progress()`, `close_progress_bar()` | 更新/关闭进度条 |
| **logging_utils.py** | `setup_collection_logging()` | 配置日志（文件 + 控制台） |
| **system_info.py** | `detect_system_type()` | 检测发行版（debian/redhat/ubuntu 等） |

### strategy_config 包

| 模块 | 类/函数 | 作用 |
|------|---------|------|
| **paths_commands.py** | `StrategyPathsConfig` | 路径配置：config_paths、log_paths、extra_paths（策略文件也放入 config_paths，采集时统一到 config_files） |
| | `StrategyCommandsConfig` | 命令配置：all_commands、groups(status_info/logs/...) |
| | `build_paths_config()` | 工厂：构建 StrategyPathsConfig |
| | `build_commands_config()` | 工厂：构建 StrategyCommandsConfig |
| **xxx_config.py** | `get_xxx_paths_config()` | 返回该策略的路径配置 |
| | `get_xxx_commands_config()` | 返回该策略的命令配置 |

### analyzer 包

| 模块 | 类/函数 | 作用 |
|------|---------|------|
| **base.py** | `SecurityAnalyzerBase` | 分析器基类 |
| | `analysis_template()` | 返回初始 analysis 字典 |
| | `get_analyzer_steps()` | 返回分析步骤列表 [self._analyze_xxx, ...] |
| | `run(save, add_to_manifest)` | 执行步骤并保存 JSON |
| | `read_collected_file(rel_path)` | 读取已采集文件 |
| | `append_issue()` | 向 security_issues 追加问题 |
| | `AnalysisResult` | 分析结果（analysis、success、error） |
| **xxx_analyzer.py** | `XxxSecurityAnalyzer` | 各策略具体分析器，继承基类并实现步骤 |

---

## main.py 核心逻辑

| 类/函数 | 作用 |
|---------|------|
| `GenericStrategyModule` | 通用采集模块：基于 paths_config + commands_config + 可选 analyzer_class，执行复制、执行命令、运行分析 |
| `StrategyCollectorWithReport` | 带摘要报告的采集器：继承 StrategyCollectorBase，在 on_after_collect 中生成 `{策略}策略采集摘要.txt` |
| `_register_strategies()` | 注册所有策略：返回 (id, output_subdir, modules_factory) 列表 |
| `run_all_strategies(base_output, strategies, resume)` | 执行所有或指定策略，顶层断点 test_collection_checkpoint.json |
| `main()` | 命令行入口：--all、--select、--resume、--no-resume、--output、--list |

---

## 支持的策略列表

| 策略 ID | 输出子目录 | 说明 |
|---------|------------|------|
| Apache | Linux_apache_config | Web 服务器 |
| SELinux | Linux_selinux_config | 强制访问控制 |
| Nginx | Linux_nginx_config | Web 服务器 |
| MySQL | Linux_mysql_config | 数据库 |
| Auditd | Linux_audit_config | 审计 |
| LUKS | Linux_luks_config | 磁盘加密 |
| chkrootkit | Linux_chkrootkit_config | Rootkit 检测 |
| Docker | Linux_docker_config | 容器 |
| AppArmor | Linux_apparmor_config | 强制访问控制 |
| Firewall | Linux_firewall_config | iptables + firewalld |
| TCP_Wrappers | Linux_tcp_wrappers_config | 访问控制 |
| ACL | Linux_acl_config | 访问控制列表 |
| StartupItems | Linux_startup_config | 启动项与定时任务 |
| K8S | Linux_k8s_security_config | Kubernetes |
| User_identity | Linux_user_identity_config | PAM/SSH/SSL 等 |
| Logtools | Linux_logtools_config | Logwatch/Swatchdog |

---

## 依赖

- Python 3.7+
- tqdm（可选，用于进度条）：`pip install tqdm`

---

## 注意事项

- 部分配置文件需 root 权限才能访问，建议以 root 或 sudo 运行
- 断点恢复依赖 `test_collection_checkpoint.json`（顶层）及各策略目录下的 `collection_checkpoint.json`
- **断点与刷新**：
  - 默认从头执行：不加 `--resume` 时从头执行，已完成的也会重新采集
  - `--resume`：从断点继续，跳过已完成的策略/模块
  - 默认 `--refresh`：按校验和增量更新，只复制/更新变化的文件；`--no-refresh` 强制全量覆盖
- **校验和增量更新**：每个模块输出目录下有 `collection_checksums.json` 记录上次采集的文件校验和。使用 `--refresh` 时，通过校验和判断：新增文件会复制、删除的文件会移除、内容变化的文件会更新、未变化则跳过，实现增量更新。
- 新增策略：在 strategy_config 添加 xxx_config.py，在 analyzer 添加 xxx_analyzer.py，在 test_main 的 _register_strategies 中注册
