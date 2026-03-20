# Hybrid Vulnerability Audit (Final)

本项目用于对指定 Juliet 子集（20 个 case）执行固定流程：

1. 用 Joern 提取每个 case 的 source/sink 与调用链函数体。  
2. 生成 LLM prompt（`results/llm_prompts/*.txt`）。  
3. 调用大模型返回 `verdict/reason`，并回填最终结果文件。  

当前项目只保留主任务所需逻辑，不包含测试代码和历史版本说明。

## 1. 任务范围

- 数据集目录：`benchmark_subset/testcases`
- 覆盖 CWE：
  - `CWE78_OS_Command_Injection__char_connect_socket_execl`
  - `CWE259_Hard_Coded_Password__w32_char`
- 变体：`51/52/53/54/61/62/81/82/83/84`
- 总计：20 个 bad case

## 2. 环境依赖

- Python 3.7+
- Joern（外部安装）
- JDK（外部安装）
- DeepSeek API Key

## 3. 配置

配置读取优先级：**环境变量 > `config/runtime_config.local.json` > 默认值**

示例 `config/runtime_config.local.json`：

```json
{
  "deepseek_api_key": "YOUR_KEY",
  "deepseek_base_url": "https://api.deepseek.com/v1",
  "deepseek_model": "deepseek-reasoner",
  "deepseek_timeout_seconds": 180,
  "java_home": "D:/DevTools/Java/jdk-19.0.2+7",
  "joern_cli_path": "D:/DevTools/joern/joern-cli/joern.bat",
  "joern_script_path": "joern_scripts/find_case_findings.sc",
  "joern_workspace_root": "D:/JoernRuntime",
  "joern_case_temp_root": "D:/JoernCaseTmp",
  "joern_keep_projects": true
}
```

## 4. 运行

执行完整流程：

```powershell
python main.py
```

查看当前配置：

```powershell
python main.py --show-config
```

## 5. 输出文件

运行后会更新：

- `results/llm_prompts/*.txt`
- `results/analysis_results.json`
- `results/analysis_results.csv`
- `results/summary.md`

## 6. 目录说明

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
|   |-- joern_runner.py
|   |-- llm.py
|   |-- models.py
|   |-- prompting.py
|   |-- reporting.py
|   |-- static_analysis.py
|   `-- tokenizer.py
`-- main.py
```
