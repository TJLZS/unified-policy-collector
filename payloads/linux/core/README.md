# core — 策略收集脚本公共核心

本包统一封装各策略收集脚本中的**断点恢复、进度条、文件校验、日志、系统检测**以及**采集模块基类、采集器基类**，便于维护与复用。

---

## 1. 断点恢复（checkpoint.py）

- **CheckpointManager(checkpoint_file)**  
  - `_load_checkpoint()` / `save_checkpoint(module_name, completed=False)`  
  - `is_module_completed(module_name)`  
  - `get_file_checksum(file_path)` / `update_file_checksum(file_path, checksum)`  
  - `update_file_statistics(module_name, stats)`  
  - 断点内容：`completed_modules`、`file_checksums`、`system_type` 等。

---

## 2. 进度条（progress.py）

- **TQDM_AVAILABLE**：是否已安装 tqdm  
- **create_progress_bar(total, desc, unit)**：创建进度条，无 tqdm 时返回 None  
- **update_progress(progress_bar, advance)**：更新进度  
- **close_progress_bar(progress_bar)**：关闭进度条  
- **progress_iterator(iterable, desc, unit)**：对可迭代对象包装进度条  

脚本中统一使用上述接口，无 tqdm 时行为降级为无进度条显示。

---

## 3. 文件校验（checksum.py）

- **file_checksum(file_path, algorithm='md5')**：计算文件校验和  
- **FileChecksumHelper(checkpoint_manager)**  
  - `calculate(file_path)`  
  - `get_saved(file_path)`  
  - `has_file_changed(file_path)`：与断点中校验和比对，若变化则更新断点并返回 True  

采集模块基类内部使用 `FileChecksumHelper` 实现「未变化则跳过复制」。

---

## 4. 日志（logging_utils.py）

- **setup_collection_logging(base_dir, log_filename, level, format_string)**  
  配置采集用日志：同时写入 `base_dir/log_filename` 与控制台，返回 root logger。

---

## 5. 系统检测（system_info.py）

- **detect_system_type()**：返回 debian/redhat/centos/arch/ubuntu 等，供断点与报告使用。

---

## 6. 采集模块基类（collector_base.py）

- **CollectorModuleBase(name, output_dir, checkpoint_manager)**  
  - 抽象方法：`collect() -> bool`  
  - 通用方法：`_copy_file`、`_copy_directory`、`_run_command`、`_add_to_manifest`、`_generate_file_statistics`、`_format_size`  
  - 文件变化：`_has_file_changed(file_path)`（内部使用 `FileChecksumHelper`）  

子类只需实现 `collect()`，在其中调用上述方法完成复制、执行命令、生成统计等。

---

## 7. 采集器基类（strategy_runner.py）

- **StrategyCollectorBase(base_dir, modules, log_filename, checkpoint_filename)**  
  - 类属性：`strategy_name`、`log_filename`、`checkpoint_filename`  
  - `run()`：遍历 `modules`，断点跳过已完成，保存检查点 → `module.collect()` → 再保存 → 更新进度条，最后调用 `on_after_collect(success_count, failed_modules)`  
  - 子类覆盖 **on_after_collect** 以生成详细报告、摘要等  
  - 子类覆盖 **_log_exception_details** 可选写入 error_details.json  

脚本中定义「模块列表」和「报告生成逻辑」，继承 `StrategyCollectorBase` 并调用 `run()` 即可获得断点恢复与进度条。

---

## 使用示例（以 Apache 为例）

```python
from core import CheckpointManager, CollectorModuleBase, StrategyCollectorBase

# 采集模块：继承 CollectorModuleBase，实现 collect()
class ApacheConfigModule(CollectorModuleBase):
    def __init__(self, output_dir, checkpoint_manager):
        super().__init__("Apache", output_dir, checkpoint_manager)
        # ...
    def collect(self) -> bool:
        # 使用 self._copy_file, self._run_command, self._generate_file_statistics 等
        return True

# 采集器：继承 StrategyCollectorBase，传入 modules，覆盖 on_after_collect
class ApacheCollector(StrategyCollectorBase):
    strategy_name = "Apache"
    def __init__(self):
        base_dir = ...
        modules = [ApacheConfigModule(base_dir, CheckpointManager(...))]
        super().__init__(base_dir=base_dir, modules=modules, ...)
    def on_after_collect(self, success_count, failed_modules):
        self._generate_detailed_file_report()
        self._generate_summary_report(success_count, failed_modules)

# 运行
collector = ApacheCollector()
collector.collect_apache_configurations()  # 内部调用 self.run()
```

其他策略脚本可按同样方式接入 core 与 strategy_config（路径/命令/分析）。
