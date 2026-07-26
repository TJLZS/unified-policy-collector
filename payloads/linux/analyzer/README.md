# analyzer — 采集结果安全分析

本包封装各策略采集结果的安全分析逻辑，与 `strategy_config` 同级。

## 结构

- `base.py`: `SecurityAnalyzerBase` 基类与 `AnalysisResult` 数据类
- `xxx_analyzer.py`: 各策略的具体分析器（Apache、SELinux、Nginx、MySQL 等）

## 用法

```python
from analyzer.apache_analyzer import ApacheSecurityAnalyzer

analyzer = ApacheSecurityAnalyzer(output_dir)
result = analyzer.run(save=True, add_to_manifest=add_fn)
```

## 扩展

新增 `xxx_analyzer.py`，继承 `SecurityAnalyzerBase`，实现：
- `analysis_template()`: 返回初始 analysis 字典
- `get_analyzer_steps()`: 返回分析步骤列表 `[self._analyze_xxx, ...]`
