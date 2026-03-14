# 混合式漏洞检测工程

这是一个按题目要求实现的完整 Python 工程：先用静态分析从 Juliet 用例里提取最小证据，再把精简后的证据交给 `DeepSeek-R1` 复核，从而兼顾检测准确率和 token 开销。

## 工程目标

- 目标 CWE
  - `CWE78_OS_Command_Injection`
  - `CWE259_Hard_Coded_Password`
- 目标流转变体
  - `51/52/53/54/61/62/81/82/83/84`
- 目标实例
  - `CWE78` 共 `50` 个顶层实例
  - `CWE259` 共 `10` 个顶层实例
  - 合计 `60` 个实例

## 核心方案

1. 静态分析层只抽取 `bad source`、`bad sink`、流转链条和上下文窗口。
2. 智能体层只接收这份压缩证据，而不是整文件源码。
3. 若配置了 `DEEPSEEK_API_KEY`，则调用 `DeepSeek-R1`（默认模型名 `deepseek-reasoner`）输出复核结论。
4. 若当前环境没有 API Key 或外网不可用，则自动退化为离线模式：
   - 仍然完整执行静态分析和结果导出；
   - token 消耗使用提示词长度估算；
   - 方便先把工程、实验脚本和结果管线跑通。

## 目录结构

```text
.
|-- benchmark_subset/
|-- docs/
|   `-- solution.md
|-- results/
|-- src/hybrid_vuln_audit/
|   |-- benchmark.py
|   |-- cli.py
|   |-- config.py
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

## 运行方式

### 1. 离线模式

```powershell
python main.py --offline
```

### 2. 在线 DeepSeek-R1 模式

```powershell
$env:DEEPSEEK_API_KEY="your_api_key"
python main.py
```

## 输出结果

运行后会生成：

- `results/analysis_results.json`
- `results/analysis_results.csv`
- `results/summary.md`

每个实例都包含：

- 是否存在漏洞
- 主要漏洞位置
- source/sink 位置
- flow variant
- token 消耗

## 说明

当前工作区未配置 `DEEPSEEK_API_KEY`，因此默认实验结果会以离线模式生成，但在线调用接口已经完整实现，后续只需补环境变量即可切换到真实 `DeepSeek-R1`。
