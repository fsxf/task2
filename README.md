## 环境依赖

- Python 3.7+
- Joern
- JDK
- DeepSeek API Key

## 配置

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

查看当前配置：

```powershell
python main.py --show-config
```

## 输出结果

运行后会更新：

- `results/llm_prompts/*.txt`
- `results/analysis_results.json`
- `results/analysis_results.csv`
- `results/summary.md`

## 目录说明

```text
.
|-- benchmark_subset/
|-- config/
|   |-- runtime_config.example.json
|   `-- runtime_config.local.json
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
