# 方案说明

## 1. 任务目标

本工程实现了一个面向精简 Juliet 基准集的漏洞检测系统，要求：

- 使用 Python 统一组织工程
- 引入静态分析工具
- 接入大模型进行复核
- 给出可运行代码、测试和实验结果

当前工程聚焦两个 CWE：

- `CWE78_OS_Command_Injection`
- `CWE259_Hard_Coded_Password`

每个 CWE 保留 `10` 个目标变体，总计 `20` 个主基准实例。

## 2. 总体方案

系统采用两阶段流程。

### 第一阶段：静态分析初筛

- 根据 Juliet 文件命名规则枚举目标实例
- 结合变体编号解析 source / sink 所在文件
- 优先调用 `Joern` 从 CPG 中抽取 source/sink 证据
- 如果 `Joern` 不可用，再回退到规则匹配后端

### 第二阶段：DeepSeek-R1 复核

- 将静态分析结果压缩成最小证据包
- 只提供 source/sink、局部代码窗口和 flow chain
- 调用 `DeepSeek-R1` 输出最终判断和解释

该方案兼顾了两点：

- 静态分析负责确定候选证据
- 大模型负责利用上下文做语义复核

## 3. 静态分析实现

### 3.1 Joern 后端

本工程当前默认使用 `Joern`。

查询规则如下：

- `CWE78`
  - source: `recv`
  - sink: `EXECL/execl/_execl`
- `CWE259`
  - source: `strcpy(..., PASSWORD)`
  - sink: `LogonUserA`

查询脚本位于：

- `joern_scripts/find_case_findings.sc`

### 3.2 变体解析

变体到数据流的映射为：

- `51`: `a -> b`
- `52`: `a -> b -> c`
- `53`: `a -> b -> c -> d`
- `54`: `a -> b -> c -> d -> e`
- `61`: `b -> a`
- `62`: `b -> a`
- `81`: `a -> virtual dispatch`
- `82`: `a -> virtual dispatch`
- `83`: `constructor -> destructor`
- `84`: `constructor -> destructor`

## 4. Good Path 设计

工程除了主基准结果，还额外支持 Good Path 验证。

这里强调是 Good Path，而不是 Good 文件。

原因是 Juliet 中很多变体存在以下情况：

- 同一个文件组里既有 `bad()` 又有 `good()`
- 同一个文件里既有 `badSource` 又有 `goodG2BSource`
- 同一个文件里既有 `badSink` 又有 `goodG2BSink`

因此，判断一个样例是否安全，不能只靠文件名，而要结合“当前分析的是 good 作用域还是 bad 作用域”。

本工程通过 `analysis_scope` 区分：

- `bad`：主基准漏洞路径
- `good`：安全路径验证

Joern 查询和规则回退都会按该作用域过滤。

## 5. 配置方式

推荐采用以下方式：

- 工具安装在项目外
- API key 和工具路径使用环境变量
- 项目内只保留极简本地配置文件

环境变量优先级高于本地配置文件。

关键变量包括：

- `DEEPSEEK_API_KEY`
- `DEEPSEEK_BASE_URL`
- `DEEPSEEK_MODEL`
- `DEEPSEEK_TIMEOUT_SECONDS`
- `STATIC_ANALYSIS_BACKEND`
- `JAVA_HOME`
- `JOERN_CLI_PATH`
- `JOERN_WORKSPACE_ROOT`
- `JOERN_CASE_TEMP_ROOT`

## 6. 关于 `workspace`

`workspace` 是 Joern 的运行工作区，不是工程源码目录。

旧版本会把它直接生成在项目根目录。当前版本已经支持：

- 把 Joern 工作区放到系统临时目录
- 或通过配置显式放到项目外部目录

同时，当前版本会在每个 case 分析结束后清理对应的 Joern 项目缓存，避免 `workspace/hybrid-vuln-audit-*` 持续累积。

## 7. 输出结果

主流程输出：

- `results/analysis_results.json`
- `results/analysis_results.csv`
- `results/summary.md`

Good Path 结果输出：

- `results/good_sample_results.json`

## 8. 当前验证情况

已验证：

- `python -m unittest discover -s tests -v`
- `python main.py`
- `python main.py --good-paths-only`

测试覆盖内容包括：

- 主基准实例枚举
- 漏洞样例定位
- 构造/析构流检测
- `20` 条 Good Path 不误报
