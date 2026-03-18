# 混合式漏洞审计工程

这个项目实现了一个面向精简 `Juliet` 子集的两阶段流程：

1. 先用 `Joern` 做静态分析，定位可能的漏洞证据。
2. 再把压缩后的静态证据交给 `DeepSeek-R1` 做语义复核，判断是否真的是漏洞。

当前保留的数据规模是：

- `20` 个任务要求的 `Bad` 基准实例
- `20` 条对应的 `Good Path` 安全路径检查

## 当前静态分析做了什么

这版静态分析不再只是“找到一个 source 和一个 sink”。

`Joern` 现在会对每个 `Juliet case` 的完整文件组建一个独立 `CPG`，然后导出：

- `source` 位置
- `sink` 位置
- `source` 所在方法
- `sink` 所在方法
- 支持变体上的真实数据流路径
- `Joern` 在该 case 内恢复出的内部调用链
- 每一跳调用边对应的文件、行号和调用代码

这些证据会进入：

- `results/analysis_results.json` 的 `flow_evidence`
- `results/analysis_results.csv` 的 `flow_evidence`
- 发送给大模型的提示词

也就是说，大模型拿到的不是两个孤立命中点，而是：

- source/sink 的代码窗口
- 变量级数据流路径
- case 级调用链
- benchmark 预期流链
- 静态分析的命中位置

这正是本项目的设计目标：先让静态分析工具找出“可能的 bug”和它的传播证据，再交给大模型判断是否是误报。

## 基准范围

保留的 `Bad` 基准包括两个 `CWE`：

- `CWE78_OS_Command_Injection`
  - `char_connect_socket_execl`
  - 变体：`51/52/53/54/61/62/81/82/83/84`
- `CWE259_Hard_Coded_Password`
  - `w32_char`
  - 变体：`51/52/53/54/61/62/81/82/83/84`

共 `20` 个 `Bad` case。

此外，项目还会为这 `20` 个 case 构造对应的 `20` 条 `Good Path`。

## Good Path 说明

这里测试的不是“Good 文件”，而是“Good 路径”。

原因是很多 `Juliet` 变体并不是：

- 一个文件纯 `good`
- 另一个文件纯 `bad`

而是同一组文件里同时包含：

- `bad()` / `good()`
- `badSource` / `goodG2BSource`
- `badSink` / `goodG2BSink`

所以项目通过 `analysis_scope` 区分当前检查的是：

- `bad`
- `good`

当前测试已经覆盖全部 `20` 条 `Good Path`，用于验证安全路径不会被误报。

## 外部依赖

本项目默认把大体积工具安装在项目外部，不再把 `JDK` 和 `Joern` 放进仓库。

需要准备：

- `JDK 19`
- `Joern`
- `DeepSeek API Key`

当前机器上的常用路径示例：

- `JAVA_HOME=D:\DevTools\java\jdk-19.0.2+7`
- `JOERN_CLI_PATH=D:\DevTools\joern\joern-cli\joern.bat`

## 推荐配置方式

推荐做法是：

- 敏感信息和本机路径走环境变量
- 项目里只保留极简本地配置文件

环境变量优先级高于 `config/runtime_config.local.json`。

### 1. 配置环境变量

在 PowerShell 中执行：

```powershell
setx DEEPSEEK_API_KEY "你的 DeepSeek API Key"
setx DEEPSEEK_BASE_URL "https://api.deepseek.com/v1"
setx DEEPSEEK_MODEL "deepseek-reasoner"
setx DEEPSEEK_TIMEOUT_SECONDS "180"
setx STATIC_ANALYSIS_BACKEND "joern"
setx JAVA_HOME "D:\DevTools\java\jdk-19.0.2+7"
setx JOERN_CLI_PATH "D:\DevTools\joern\joern-cli\joern.bat"
setx JOERN_KEEP_PROJECTS "1"
```

如果你想把 `Joern` 的运行目录放到项目外，也可以继续设置：

```powershell
setx JOERN_WORKSPACE_ROOT "D:\JoernRuntime"
setx JOERN_CASE_TEMP_ROOT "D:\JoernTemp"
```

设置完成后，关闭当前终端，再重新打开 PowerShell。

### 2. 本地配置文件

本地配置文件位于：

- `config/runtime_config.local.json`

如果你主要使用环境变量，这个文件建议只保留非敏感默认值，例如：

```json
{
  "joern_script_path": "joern_scripts/find_case_findings.sc"
}
```

也可以保留一部分非敏感默认项：

```json
{
  "deepseek_base_url": "https://api.deepseek.com/v1",
  "deepseek_model": "deepseek-reasoner",
  "deepseek_timeout_seconds": 180,
  "static_analysis_backend": "joern",
  "joern_script_path": "joern_scripts/find_case_findings.sc",
  "joern_keep_projects": true
}
```

不建议把真实 API key 提交到仓库。

## 检查当前配置

```powershell
python main.py --show-config
```

会打印：

- `java_home`
- `joern_cli_path`
- `joern_workspace_root`
- `joern_case_temp_root`
- `joern_keep_projects`
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

### 运行主基准后顺带导出 Good Path 结果

```powershell
python main.py --export-good-paths
```

额外输出：

- `results/good_sample_results.json`

### 只导出 Good Path 结果

```powershell
python main.py --good-paths-only
```

## Joern 导入粒度

当前版本会把每个 `Juliet case` 的完整文件组一起导入 `Joern`，而不是只导入端点文件。

例如：

- `CWE78 ... 51`
  - 导入 `51a.c + 51b.c`
- `CWE78 ... 54`
  - 导入 `54a.c + 54b.c + 54c.c + 54d.c + 54e.c`

这样 `Joern` 看到的是完整 case 级结构，可以恢复跨文件调用链，也能在支持的变体上恢复真实数据流路径。

## 结果里新增了什么

`analysis_results.json` 和 `good_sample_results.json` 现在会包含 `flow_evidence` 字段，例如：

- `joern source method: ...`
- `joern sink method: ...`
- `joern dataflow path (...): node -> node -> node`
- `joern call path: methodA -> methodB -> methodC`
- `joern call edge: file:line caller -> callee | code`

这些信息也会进入提示词，让大模型在复核时不只是看两段局部代码。

## 关于 `workspace`

`workspace` 不是源码目录，而是 `Joern` 运行 `importCode` 时的工作区。

如果开启：

- `JOERN_KEEP_PROJECTS=1`

那么每个 case 的项目会保留在：

- `joern_workspace_root/workspace/<project_name>`

case 输入目录会保留在：

- `joern_case_temp_root/<project_name>`

如果关闭这个开关，项目运行完会自动清理这些中间文件。

所以结论是：

- 旧的项目内 `workspace/` 可以删
- 旧的 `.joern_case_tmp/` 可以删
- 新版本默认把运行中间文件放到系统临时目录或你显式指定的外部目录

## 如何进入 Joern Shell

### 先说明一个常见错误

如果你在 `cmd` 里执行：

- `Set-Location`
- `& "xxx\joern.bat"`

会报错，因为这两个都是 PowerShell 语法，不是 `cmd` 语法。

另外，手工启动 `Joern` 时，`config/runtime_config.local.json` 不会自动帮你的 shell 设置 `JAVA_HOME`。  
它只在你运行 `python main.py` 时被 Python 读取。

所以你手工启动 `Joern shell` 时，必须在当前终端里先让 `java.exe` 和 `javac.exe` 可见。

### PowerShell

```powershell
$env:JAVA_HOME = "D:\DevTools\java\jdk-19.0.2+7"
$env:Path = "$env:JAVA_HOME\bin;$env:Path"
Set-Location "$env:LOCALAPPDATA\Temp\hybrid_vuln_audit\joern_runtime"
& "D:\DevTools\joern\joern-cli\joern.bat"
```

如果你已经把 `JOERN_WORKSPACE_ROOT` 配到了别处，就把 `Set-Location` 改成那个目录。

### CMD

```cmd
set JAVA_HOME=D:\DevTools\java\jdk-19.0.2+7
set PATH=%JAVA_HOME%\bin;%PATH%
cd /d C:\Users\lenovo\AppData\Local\Temp\hybrid_vuln_audit\joern_runtime
"D:\DevTools\joern\joern-cli\joern.bat"
```

### 进入后查看项目

```scala
workspace
project
```

切到某个保留项目：

```scala
workspace.setActiveProject("hybrid-vuln-audit-CWE78_OS_Command_Injection__char_connect_socket_execl_54-bad")
project
```

常用查询示例：

```scala
cpg.call.name("recv").location.l
cpg.call.name("(EXECL|execl|_execl)").location.l
cpg.call.name("LogonUserA").location.l
cpg.call.code.l
```

## 当前实现的边界

这版 `Joern` 静态阶段已经做到：

- case 级完整文件组导入
- source/sink 定位
- 支持变体上的真实数据流路径恢复
- 内部调用链恢复
- 调用边证据导出

但需要如实说明：

- `CWE259` 的普通参数传递变体已经能导出真实变量级数据流路径
- `CWE78` 的 `51/52/53/54` 链式调用变体已经能导出跨函数 `badSink` 参数传播路径
- 某些 `CWE78` 和构造/析构类变体仍会受到 `recv` 写缓冲区语义、成员字段传播和 `COMMAND_ARG3` 宏展开限制
- 这类样例的结果里会明确标记 `joern dataflow path: unavailable for this case`

对这组 `Juliet` 任务来说，这已经足够支撑“先静态分析，再让大模型判断”的流程，而且比只看 `source/sink` 更合理。

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
- `Joern` 全文件组导入
- `CWE78` / `CWE259` 命中定位
- 链式传播变体的调用链证据
- 支持变体上的数据流证据
- 构造/析构流
- `20` 条 `Good Path` 不误报

## 提交建议

建议提交：

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
- 外部安装的 `JDK`
- 外部安装的 `Joern`
