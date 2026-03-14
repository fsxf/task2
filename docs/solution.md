# 方案说明

## 1. 任务理解

题目要求实现一个“智能体 + 静态分析”的漏洞检测工具，统一使用 Python。当前提交版本保留并分析以下 Juliet 基准子集：

- `CWE78_OS_Command_Injection` 中 `char_connect_socket_execl + 51/52/53/54/61/62/81/82/83/84`
- `CWE259_Hard_Coded_Password` 中 `w32_char + 51/52/53/54/61/62/81/82/83/84`
- 合计 `20` 个顶层实例

## 2. 总体架构

第一阶段：静态分析初筛

- 根据文件命名规则枚举目标实例。
- 按流转变体定位 bad path 里的 source 文件与 sink 文件。
- 提取 source 行、sink 行、流转链和最小代码窗口。

第二阶段：智能体复核

- 把静态分析提取出的最小证据拼成紧凑 prompt。
- 交给 DeepSeek-R1 判断：
  - 是否存在漏洞
  - 主要漏洞位置
  - 原因说明

## 3. 为什么这样能省 token

本工程只发送：

- 结构化元信息
- 1 个 source 片段
- 1 个 sink 片段
- 1 条流转链

这样每个实例的 prompt 明显更短，避免把大量模板代码重复喂给模型。

## 4. 当前数据规模

- `CWE78`：`10` 个实例
- `CWE259`：`10` 个实例
- 总计：`20` 个实例

## 5. 静态分析策略

### 5.1 CWE78

- bad source 从外部输入读入命令片段；
- bad sink 调用 `EXECL(...)`；
- `primary_line` 默认取 sink 行。

### 5.2 CWE259

- bad source 使用硬编码口令；
- sink 使用 `LogonUserA(...)`；
- `primary_line` 默认取 source 行。

## 6. 变体处理

- `51`: `a -> b`
- `52`: `a -> b -> c`
- `53`: `a -> b -> c -> d`
- `54`: `a -> b -> c -> d -> e`
- `61`: `b -> a`
- `62`: `b -> a`
- `81/82/83`: `a -> _bad.cpp`
- `84`: `_bad.cpp` 内部构造函数写 source，析构函数落 sink

## 7. DeepSeek-R1 接入

工程默认按 OpenAI-compatible 接口访问 DeepSeek：

- Base URL：`https://api.deepseek.com/v1`
- Model：`deepseek-reasoner`

当前环境未发现 API Key，因此默认实验结果以离线模式导出：

- 复核结果使用静态证据的确定性结论；
- token 使用提示词长度估算；
- 代码层面已经支持后续直接切换到真实 DeepSeek-R1。

## 8. 实验结果文件

运行后会输出：

- `analysis_results.json`
- `analysis_results.csv`
- `summary.md`

其中逐实例结果包含：

- `case_id`
- `cwe`
- `variant`
- `vulnerable`
- `primary_location`
- `source_location`
- `sink_location`
- `prompt_tokens`
- `completion_tokens`
- `total_tokens`
