# 方案说明（最终版）

## 1. 目标

项目目标是对 Juliet 子集中的 20 个 bad case 执行统一审计流程，输出可复现结果文件：

- `results/analysis_results.json`
- `results/analysis_results.csv`
- `results/summary.md`

## 2. 固定流程

### 阶段 A：Joern 静态提取

对每个 case：

1. 预处理文件（用于宏展开后再导入 Joern）。
2. 按 case 维度构建 CPG（保留可查询项目）。
3. 提取 source/sink 命中与调用链函数体。
4. 对 Juliet 自定义标识符做中性化，并去注释。

### 阶段 B：LLM 复核

1. 以函数体为核心证据生成 prompt。
2. 大模型返回严格 JSON：`verdict`（布尔）+ `reason`（简短文本）。
3. 程序解析并写入最终结果文件。

## 3. 关键实现点

- 仅保留主任务相关逻辑，不包含 good-path 流程。
- `verdict` 做严格布尔解析，避免 `"false"` 字符串被误判为 `True`。
- `reason` 保留模型原始语义，不做自动改写。
- 结果文件保留在 `results/`，用于后续统计和对比。

## 4. 运行方式

```powershell
python main.py
```

可选查看配置：

```powershell
python main.py --show-config
```

## 5. 配置来源

优先级：环境变量 > `config/runtime_config.local.json` > 默认值。  
核心配置包含：DeepSeek 接口参数、JDK 路径、Joern 路径、Joern 工作目录与缓存目录。
