# 方案说明

## 1. 目标

本工程实现了一个针对精简 `Juliet` 子集的混合式漏洞审计流程：

1. 先使用静态分析工具发现可能的漏洞。
2. 再将静态分析证据交给大模型判断该告警是否可信。

本次任务覆盖两个 `CWE`：

- `CWE78_OS_Command_Injection`
- `CWE259_Hard_Coded_Password`

共 `20` 个 `Bad` 基准实例，并额外补充了 `20` 条 `Good Path` 安全路径验证。

## 2. 总体方案

整个系统采用“两阶段”设计。

### 阶段一：Joern 静态分析

静态分析阶段负责给出高置信候选漏洞证据，而不是直接替代最终判断。

这版实现里，`Joern` 对每个 `Juliet case` 的完整文件组构建一个独立 `CPG`，然后导出：

- `source` 命中位置
- `sink` 命中位置
- `source` 所在方法
- `sink` 所在方法
- 支持变体上的真实数据流路径
- case 内部调用链
- 每一跳调用边的文件、行号和调用代码

因此，静态分析输出的不再只是两个孤立点，而是：

- 变量级数据流路径
- 方法级调用传播骨架

两层证据的组合。

### 阶段二：DeepSeek-R1 复核

大模型阶段读取压缩后的静态证据，包括：

- `source/sink` 位置
- 局部代码窗口
- `Joern` 恢复的调用链证据
- `Joern` 给出的数据流路径
- benchmark 预期 `flow chain`

然后输出：

- 是否为漏洞
- 置信度
- 关键位置
- 简要原因

这种分工比较适合本任务：

- 静态分析工具擅长结构化定位和路径恢复
- 大模型擅长结合上下文做语义判断

## 3. 为什么要这样升级

早期版本只用静态分析找 `source` 和 `sink`，这会有两个问题：

1. `Joern` 看到的证据太碎，大模型只能对两个点做弱判断。
2. 对 `52/53/54` 这类跨多个文件传递的变体来说，只看端点不够解释传播过程。

升级后的实现改成：

- 每个 case 导入完整文件组
- `Joern` 提取内部调用边
- `Joern` 在支持的变体上计算真实数据流路径
- Python 侧重建 case 级方法路径
- 将这些路径作为 `flow_evidence` 传给大模型

例如 `CWE78 ... 54`，结果中现在可以看到：

- 方法级调用链：`54_bad -> 54b_badSink -> 54c_badSink -> 54d_badSink -> 54e_badSink`
- 变量级传播链：`data` 从每一层 `badSink(data)` 实参继续传到下一层形参

这样大模型复核时看到的是更接近真实漏洞传播过程的证据，而不是只看一条 `recv(...)` 和一条 `EXECL(...)`。

## 4. 具体实现

### 4.1 基准枚举

`benchmark.py` 根据 `Juliet` 命名规则枚举任务要求的 `20` 个 `Bad` case，并解析：

- case id
- variant
- source file
- sink file
- group files
- benchmark 预期 flow chain

### 4.2 Joern 查询

`joern_scripts/find_case_findings.sc` 负责在 case 级 `CPG` 中抽取结构化结果。

当前规则为：

- `CWE78`
  - source: `recv`
  - sink: `EXECL/execl/_execl`
- `CWE259`
  - source: `strcpy(..., PASSWORD)`
  - sink: `LogonUserA`

除此之外，脚本还会输出：

- 内部调用边 `CALL_EDGE`
- 数据流路径 `DATAFLOW`

Python 端的 `joern_runner.py` 再根据这些边和数据流结果重建最终 `flow_evidence`。

当前数据流覆盖范围是：

- `CWE259`
  - 普通参数传递变体可恢复 `password` 到 `LogonUserA` 的真实变量级路径
- `CWE78`
  - `51/52/53/54` 变体可恢复 `badSink` 调用参数在跨函数链中的真实传播路径
  - 其他变体若受 `recv` 语义、字段传播或宏展开限制，会明确标记数据流不可用

### 4.3 Good Path

项目没有把 `Good` 检查简化成“查带不带 `good` 文件名”。

原因是很多 `Juliet` 变体同一组文件里同时包含：

- `bad()`
- `good()`
- `badSource`
- `goodG2BSource`
- `badSink`
- `goodG2BSink`

所以本项目按“作用域”做 Good 检查：

- `analysis_scope=bad`
- `analysis_scope=good`

并验证全部 `20` 条 `Good Path` 不被误报。

## 5. Joern 工作目录与 CPG 保留

如果开启：

- `JOERN_KEEP_PROJECTS=1`

那么每个 case 的 `CPG` 会保留在：

- `joern_workspace_root/workspace/<project_name>`

对应的 case 输入目录保留在：

- `joern_case_temp_root/<project_name>`

这样可以在后续手工进入 `Joern shell` 查询保留下来的项目。

## 6. 手工进入 Joern Shell

需要注意两件事：

1. `config/runtime_config.local.json` 不会自动影响你手工打开的 shell。
2. `cmd` 和 PowerShell 语法不能混用。

### PowerShell

```powershell
$env:JAVA_HOME = "D:\DevTools\java\jdk-19.0.2+7"
$env:Path = "$env:JAVA_HOME\bin;$env:Path"
Set-Location "$env:LOCALAPPDATA\Temp\hybrid_vuln_audit\joern_runtime"
& "D:\DevTools\joern\joern-cli\joern.bat"
```

### CMD

```cmd
set JAVA_HOME=D:\DevTools\java\jdk-19.0.2+7
set PATH=%JAVA_HOME%\bin;%PATH%
cd /d C:\Users\lenovo\AppData\Local\Temp\hybrid_vuln_audit\joern_runtime
"D:\DevTools\joern\joern-cli\joern.bat"
```

进入后可以先执行：

```scala
workspace
project
```

## 7. 方案边界

这版实现已经满足本任务“先静态分析，再交给大模型判断”的目标，而且比只看 `source/sink` 更合理。

但需要如实说明：

- `CWE259` 的普通参数传递变体已经能导出真实数据流路径
- `CWE78` 的 `51/52/53/54` 链式调用变体已经能导出真实跨函数参数传播路径
- 受 `recv` 写缓冲区语义、成员字段传播和 `COMMAND_ARG3` 宏展开限制的样例，目前还不能保证每个 case 都有完整 source-to-sink 数据流
- 这些 case 会明确标记 `joern dataflow path: unavailable for this case`

因此，当前方案是：

- `Joern` 负责找候选漏洞、恢复调用链，并在支持的变体上给出真实数据流路径
- 大模型负责结合局部代码和这些静态证据做最终语义复核

## 8. 当前验证情况

已验证：

- `python -m unittest discover -s tests -v`

当前测试覆盖：

- `20` 个基准实例枚举
- `Joern` 完整文件组导入
- `CWE78` / `CWE259` 命中定位
- 链式变体调用链证据
- 支持变体上的数据流证据
- 构造/析构流
- `20` 条 `Good Path` 不误报
