# 混合式漏洞检测工程

本项目实现了一个“静态分析 + LLM 复核”的 Python 工程，用于在精简版 Juliet 数据集上检测漏洞。

- 静态分析阶段优先使用 `Joern`
- 复核阶段调用 `DeepSeek-R1`
- 当前保留的基准集为 `20` 个目标实例
- 当前还额外支持导出 `20` 条 Good Path 的静态分析结果

## 当前基准范围

- `CWE78_OS_Command_Injection`
  - `char_connect_socket_execl`
  - 变体：`51/52/53/54/61/62/81/82/83/84`
- `CWE259_Hard_Coded_Password`
  - `w32_char`
  - 变体：`51/52/53/54/61/62/81/82/83/84`

总计 `20` 个主基准实例。

## 工具依赖

本项目默认假设 `JDK` 和 `Joern` 安装在项目外部，不再把大体积工具目录放进仓库。

需要准备：

- `JDK 19`
- `Joern`
- `DeepSeek API Key`

## 推荐配置方式

推荐使用“环境变量 + 极简本地配置文件”的方式。

环境变量优先级最高，代码逻辑见 [config.py](/d:/FDU_复试/huang_cheng/task2/src/hybrid_vuln_audit/config.py)。

### 1. 配置环境变量

PowerShell 中执行：

```powershell
setx DEEPSEEK_API_KEY "你的 DeepSeek API Key"
setx DEEPSEEK_BASE_URL "https://api.deepseek.com/v1"
setx DEEPSEEK_MODEL "deepseek-reasoner"
setx DEEPSEEK_TIMEOUT_SECONDS "180"
setx STATIC_ANALYSIS_BACKEND "joern"
setx JAVA_HOME "D:\DevTools\Java\jdk-19.0.2+7"
setx JOERN_CLI_PATH "D:\DevTools\joern\joern-cli\joern.bat"
```

如果你想把 Joern 运行中间文件放到别处，也可以继续设置：

```powershell
setx JOERN_WORKSPACE_ROOT "D:\JoernRuntime"
setx JOERN_CASE_TEMP_ROOT "D:\JoernTemp"
```

设置完成后，关闭当前终端，重新打开 PowerShell。

### 2. 本地配置文件

本地配置文件位于：

- `config/runtime_config.local.json`

如果你主要用环境变量，这个文件建议只保留非敏感默认项，例如：

```json
{
  "joern_script_path": "joern_scripts/find_case_findings.sc"
}
```

也可以保留一部分非敏感默认值：

```json
{
  "deepseek_base_url": "https://api.deepseek.com/v1",
  "deepseek_model": "deepseek-reasoner",
  "deepseek_timeout_seconds": 180,
  "static_analysis_backend": "joern",
  "joern_script_path": "joern_scripts/find_case_findings.sc"
}
```

不建议把真实 API key 提交到仓库。

## 配置检查

```powershell
python main.py --show-config
```

会打印：

- `java_home`
- `joern_cli_path`
- `joern_workspace_root`
- `joern_case_temp_root`
- `deepseek_api_key` 的掩码形式

## 运行方式

### 主基准运行

```powershell
python main.py
```

输出：

- `results/analysis_results.json`
- `results/analysis_results.csv`
- `results/summary.md`

### 主基准运行后顺带导出 Good Path 结果

```powershell
python main.py --export-good-paths
```

额外输出：

- `results/good_sample_results.json`

### 只导出 Good Path 结果

```powershell
python main.py --good-paths-only
```

## Good Path 说明

这里测试和导出的不是“Good 文件”，而是“Good Path”。

原因是 Juliet 的很多变体并不是一个文件纯 `good`、另一个文件纯 `bad`，而是在同一组文件里同时存在：

- `bad() / good()`
- `badSource / goodG2BSource`
- `badSink / goodG2BSink`

因此本项目对 Good 样例的验证按“调用路径作用域”进行，而不是按文件名硬分。

## `workspace` 是什么

`workspace` 不是源码目录，而是 `Joern` 在运行 `importCode` 时生成的工作区目录。

旧版本代码把它生成在项目根目录，所以你会看到：

- `workspace/`
- `.joern_case_tmp/`

当前版本已经支持把这些中间文件放到项目外，并且默认会把运行目录放到系统临时目录：

- `joern_workspace_root`
- `joern_case_temp_root`

另外，当前版本会在每次单个 case 分析结束后自动清理对应的 Joern 项目缓存，不再无限累积 `workspace/hybrid-vuln-audit-*` 子目录。

### 你现在能不能删项目里的 `workspace`

可以。

如果里面只是之前运行遗留的内容，可以直接删。它不属于源码，也不属于最终结果。

### 之后还会不会继续生成

会生成运行时中间文件，但默认写到系统临时目录或你配置的外部目录，不需要再落到项目根目录。

## 目录结构

```text
.
|-- benchmark_subset/
|-- config/
|   |-- runtime_config.example.json
|   `-- runtime_config.local.json
|-- docs/
|   `-- solution.md
|-- joern_scripts/
|   `-- find_case_findings.sc
|-- results/
|-- src/hybrid_vuln_audit/
|   |-- benchmark.py
|   |-- cli.py
|   |-- config.py
|   |-- good_paths.py
|   |-- joern_runner.py
|   |-- llm.py
|   |-- models.py
|   |-- prompting.py
|   |-- reporting.py
|   |-- static_analysis.py
|   `-- tokenizer.py
|-- tests/
|   `-- test_pipeline.py
`-- main.py
```

## 测试

```powershell
python -m unittest discover -s tests -v
```

当前测试覆盖：

- `20` 个主基准实例的枚举
- 典型 `CWE78` / `CWE259` 漏洞检测
- 构造/析构流变体检测
- `20` 条 Good Path 不误报验证

## 提交建议

建议提交时保留：

- `benchmark_subset/`
- `src/`
- `tests/`
- `docs/`
- `config/runtime_config.example.json`
- `results/`
- `README.md`
- `main.py`

不建议提交：

- `config/runtime_config.local.json`
- `workspace/`
- `.joern_case_tmp/`
- 外部安装的 `JDK` / `Joern`
