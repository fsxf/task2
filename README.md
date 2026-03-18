# 娣峰悎寮忔紡娲炲璁″伐绋?
杩欎釜椤圭洰瀹炵幇浜嗕竴涓潰鍚戠簿绠€ `Juliet` 瀛愰泦鐨勪袱闃舵娴佺▼锛?
1. 鍏堢敤 `Joern` 鍋氶潤鎬佸垎鏋愶紝瀹氫綅鍙兘鐨勬紡娲炶瘉鎹€?2. 鍐嶆妸鍘嬬缉鍚庣殑闈欐€佽瘉鎹氦缁?`DeepSeek-R1` 鍋氳涔夊鏍革紝鍒ゆ柇鏄惁鐪熺殑鏄紡娲炪€?
褰撳墠淇濈暀鐨勬暟鎹妯℃槸锛?
- `20` 涓换鍔¤姹傜殑 `Bad` 鍩哄噯瀹炰緥
- `20` 鏉″搴旂殑 `Good Path` 瀹夊叏璺緞妫€鏌?
## 褰撳墠闈欐€佸垎鏋愬仛浜嗕粈涔?
杩欑増闈欐€佸垎鏋愪笉鍐嶅彧鏄€滄壘鍒颁竴涓?source 鍜屼竴涓?sink鈥濄€?
`Joern` 鐜板湪浼氬姣忎釜 `Juliet case` 鐨勫畬鏁存枃浠剁粍寤轰竴涓嫭绔?`CPG`锛岀劧鍚庡鍑猴細

- `source` 浣嶇疆
- `sink` 浣嶇疆
- `source` 鎵€鍦ㄦ柟娉?- `sink` 鎵€鍦ㄦ柟娉?- 鏀寔鍙樹綋涓婄殑鐪熷疄鏁版嵁娴佽矾寰?- `Joern` 鍦ㄨ case 鍐呮仮澶嶅嚭鐨勫唴閮ㄨ皟鐢ㄩ摼
- 姣忎竴璺宠皟鐢ㄨ竟瀵瑰簲鐨勬枃浠躲€佽鍙峰拰璋冪敤浠ｇ爜

杩欎簺璇佹嵁浼氳繘鍏ワ細

- `results/analysis_results.json` 鐨?`flow_evidence`
- `results/analysis_results.csv` 鐨?`flow_evidence`
- 鍙戦€佺粰澶фā鍨嬬殑鎻愮ず璇?
涔熷氨鏄锛屽ぇ妯″瀷鎷垮埌鐨勪笉鏄袱涓绔嬪懡涓偣锛岃€屾槸锛?
- source/sink 鐨勪唬鐮佺獥鍙?- 鍙橀噺绾ф暟鎹祦璺緞
- case 绾ц皟鐢ㄩ摼
- benchmark 棰勬湡娴侀摼
- 闈欐€佸垎鏋愮殑鍛戒腑浣嶇疆

杩欐鏄湰椤圭洰鐨勮璁＄洰鏍囷細鍏堣闈欐€佸垎鏋愬伐鍏锋壘鍑衡€滃彲鑳界殑 bug鈥濆拰瀹冪殑浼犳挱璇佹嵁锛屽啀浜ょ粰澶фā鍨嬪垽鏂槸鍚︽槸璇姤銆?
## 鍩哄噯鑼冨洿

淇濈暀鐨?`Bad` 鍩哄噯鍖呮嫭涓や釜 `CWE`锛?
- `CWE78_OS_Command_Injection`
  - `char_connect_socket_execl`
  - 鍙樹綋锛歚51/52/53/54/61/62/81/82/83/84`
- `CWE259_Hard_Coded_Password`
  - `w32_char`
  - 鍙樹綋锛歚51/52/53/54/61/62/81/82/83/84`

鍏?`20` 涓?`Bad` case銆?
姝ゅ锛岄」鐩繕浼氫负杩?`20` 涓?case 鏋勯€犲搴旂殑 `20` 鏉?`Good Path`銆?
## Good Path 璇存槑

杩欓噷娴嬭瘯鐨勪笉鏄€淕ood 鏂囦欢鈥濓紝鑰屾槸鈥淕ood 璺緞鈥濄€?
鍘熷洜鏄緢澶?`Juliet` 鍙樹綋骞朵笉鏄細

- 涓€涓枃浠剁函 `good`
- 鍙︿竴涓枃浠剁函 `bad`

鑰屾槸鍚屼竴缁勬枃浠堕噷鍚屾椂鍖呭惈锛?
- `bad()` / `good()`
- `badSource` / `goodG2BSource`
- `badSink` / `goodG2BSink`

鎵€浠ラ」鐩€氳繃 `analysis_scope` 鍖哄垎褰撳墠妫€鏌ョ殑鏄細

- `bad`
- `good`

褰撳墠娴嬭瘯宸茬粡瑕嗙洊鍏ㄩ儴 `20` 鏉?`Good Path`锛岀敤浜庨獙璇佸畨鍏ㄨ矾寰勪笉浼氳璇姤銆?
## 澶栭儴渚濊禆

鏈」鐩粯璁ゆ妸澶т綋绉伐鍏峰畨瑁呭湪椤圭洰澶栭儴锛屼笉鍐嶆妸 `JDK` 鍜?`Joern` 鏀捐繘浠撳簱銆?
闇€瑕佸噯澶囷細

- `JDK 19`
- `Joern`
- `DeepSeek API Key`

褰撳墠鏈哄櫒涓婄殑甯哥敤璺緞绀轰緥锛?
- `JAVA_HOME=D:\DevTools\java\jdk-19.0.2+7`
- `JOERN_CLI_PATH=D:\DevTools\joern\joern-cli\joern.bat`

## 鎺ㄨ崘閰嶇疆鏂瑰紡

鎺ㄨ崘鍋氭硶鏄細

- 鏁忔劅淇℃伅鍜屾湰鏈鸿矾寰勮蛋鐜鍙橀噺
- 椤圭洰閲屽彧淇濈暀鏋佺畝鏈湴閰嶇疆鏂囦欢

鐜鍙橀噺浼樺厛绾ч珮浜?`config/runtime_config.local.json`銆?
### 1. 閰嶇疆鐜鍙橀噺

鍦?PowerShell 涓墽琛岋細

```powershell
setx DEEPSEEK_API_KEY "浣犵殑 DeepSeek API Key"
setx DEEPSEEK_BASE_URL "https://api.deepseek.com/v1"
setx DEEPSEEK_MODEL "deepseek-reasoner"
setx DEEPSEEK_TIMEOUT_SECONDS "180"
setx STATIC_ANALYSIS_BACKEND "joern"
setx JAVA_HOME "D:\DevTools\java\jdk-19.0.2+7"
setx JOERN_CLI_PATH "D:\DevTools\joern\joern-cli\joern.bat"
setx JOERN_KEEP_PROJECTS "1"
```

濡傛灉浣犳兂鎶?`Joern` 鐨勮繍琛岀洰褰曟斁鍒伴」鐩锛屼篃鍙互缁х画璁剧疆锛?
```powershell
setx JOERN_WORKSPACE_ROOT "D:\JoernRuntime"
setx JOERN_CASE_TEMP_ROOT "D:\JoernTemp"
```

璁剧疆瀹屾垚鍚庯紝鍏抽棴褰撳墠缁堢锛屽啀閲嶆柊鎵撳紑 PowerShell銆?
### 2. 鏈湴閰嶇疆鏂囦欢

鏈湴閰嶇疆鏂囦欢浣嶄簬锛?
- `config/runtime_config.local.json`

濡傛灉浣犱富瑕佷娇鐢ㄧ幆澧冨彉閲忥紝杩欎釜鏂囦欢寤鸿鍙繚鐣欓潪鏁忔劅榛樿鍊硷紝渚嬪锛?
```json
{
  "joern_script_path": "joern_scripts/find_case_findings.sc"
}
```

涔熷彲浠ヤ繚鐣欎竴閮ㄥ垎闈炴晱鎰熼粯璁ら」锛?
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

涓嶅缓璁妸鐪熷疄 API key 鎻愪氦鍒颁粨搴撱€?
## 妫€鏌ュ綋鍓嶉厤缃?
```powershell
python main.py --show-config
```

浼氭墦鍗帮細

- `java_home`
- `joern_cli_path`
- `joern_workspace_root`
- `joern_case_temp_root`
- `joern_keep_projects`
- `deepseek_api_key` 鐨勬帺鐮佸舰寮?
## 杩愯鏂瑰紡

### 涓诲熀鍑嗚繍琛?
```powershell
python main.py
```

杈撳嚭锛?
- `results/analysis_results.json`
- `results/analysis_results.csv`
- `results/summary.md`


## Joern 瀵煎叆绮掑害

褰撳墠鐗堟湰浼氭妸姣忎釜 `Juliet case` 鐨勫畬鏁存枃浠剁粍涓€璧峰鍏?`Joern`锛岃€屼笉鏄彧瀵煎叆绔偣鏂囦欢銆?
渚嬪锛?
- `CWE78 ... 51`
  - 瀵煎叆 `51a.c + 51b.c`
- `CWE78 ... 54`
  - 瀵煎叆 `54a.c + 54b.c + 54c.c + 54d.c + 54e.c`

杩欐牱 `Joern` 鐪嬪埌鐨勬槸瀹屾暣 case 绾х粨鏋勶紝鍙互鎭㈠璺ㄦ枃浠惰皟鐢ㄩ摼锛屼篃鑳藉湪鏀寔鐨勫彉浣撲笂鎭㈠鐪熷疄鏁版嵁娴佽矾寰勩€?
## 缁撴灉閲屾柊澧炰簡浠€涔?
`analysis_results.json` 现在会包含 `flow_evidence` 字段，例如：

- `joern source method: ...`
- `joern sink method: ...`
- `joern dataflow path (...): node -> node -> node`
- `joern call path: methodA -> methodB -> methodC`
- `joern call edge: file:line caller -> callee | code`

杩欎簺淇℃伅涔熶細杩涘叆鎻愮ず璇嶏紝璁╁ぇ妯″瀷鍦ㄥ鏍告椂涓嶅彧鏄湅涓ゆ灞€閮ㄤ唬鐮併€?
## 鍏充簬 `workspace`

`workspace` 涓嶆槸婧愮爜鐩綍锛岃€屾槸 `Joern` 杩愯 `importCode` 鏃剁殑宸ヤ綔鍖恒€?
濡傛灉寮€鍚細

- `JOERN_KEEP_PROJECTS=1`

閭ｄ箞姣忎釜 case 鐨勯」鐩細淇濈暀鍦細

- `joern_workspace_root/workspace/<project_name>`

case 杈撳叆鐩綍浼氫繚鐣欏湪锛?
- `joern_case_temp_root/<project_name>`

濡傛灉鍏抽棴杩欎釜寮€鍏筹紝椤圭洰杩愯瀹屼細鑷姩娓呯悊杩欎簺涓棿鏂囦欢銆?
鎵€浠ョ粨璁烘槸锛?
- 鏃х殑椤圭洰鍐?`workspace/` 鍙互鍒?- 鏃х殑 `.joern_case_tmp/` 鍙互鍒?- 鏂扮増鏈粯璁ゆ妸杩愯涓棿鏂囦欢鏀惧埌绯荤粺涓存椂鐩綍鎴栦綘鏄惧紡鎸囧畾鐨勫閮ㄧ洰褰?
## 濡備綍杩涘叆 Joern Shell

### 鍏堣鏄庝竴涓父瑙侀敊璇?
濡傛灉浣犲湪 `cmd` 閲屾墽琛岋細

- `Set-Location`
- `& "xxx\joern.bat"`

浼氭姤閿欙紝鍥犱负杩欎袱涓兘鏄?PowerShell 璇硶锛屼笉鏄?`cmd` 璇硶銆?
鍙﹀锛屾墜宸ュ惎鍔?`Joern` 鏃讹紝`config/runtime_config.local.json` 涓嶄細鑷姩甯綘鐨?shell 璁剧疆 `JAVA_HOME`銆? 
瀹冨彧鍦ㄤ綘杩愯 `python main.py` 鏃惰 Python 璇诲彇銆?
鎵€浠ヤ綘鎵嬪伐鍚姩 `Joern shell` 鏃讹紝蹇呴』鍦ㄥ綋鍓嶇粓绔噷鍏堣 `java.exe` 鍜?`javac.exe` 鍙銆?
### PowerShell

```powershell
$env:JAVA_HOME = "D:\DevTools\java\jdk-19.0.2+7"
$env:Path = "$env:JAVA_HOME\bin;$env:Path"
Set-Location "$env:LOCALAPPDATA\Temp\hybrid_vuln_audit\joern_runtime"
& "D:\DevTools\joern\joern-cli\joern.bat"
```

濡傛灉浣犲凡缁忔妸 `JOERN_WORKSPACE_ROOT` 閰嶅埌浜嗗埆澶勶紝灏辨妸 `Set-Location` 鏀规垚閭ｄ釜鐩綍銆?
### CMD

```cmd
set JAVA_HOME=D:\DevTools\java\jdk-19.0.2+7
set PATH=%JAVA_HOME%\bin;%PATH%
cd /d C:\Users\lenovo\AppData\Local\Temp\hybrid_vuln_audit\joern_runtime
"D:\DevTools\joern\joern-cli\joern.bat"
```

### 杩涘叆鍚庢煡鐪嬮」鐩?
```scala
workspace
project
```

鍒囧埌鏌愪釜淇濈暀椤圭洰锛?
```scala
workspace.setActiveProject("hybrid-vuln-audit-CWE78_OS_Command_Injection__char_connect_socket_execl_54-bad")
project
```

甯哥敤鏌ヨ绀轰緥锛?
```scala
cpg.call.name("recv").location.l
cpg.call.name("(EXECL|execl|_execl)").location.l
cpg.call.name("LogonUserA").location.l
cpg.call.code.l
```

## 褰撳墠瀹炵幇鐨勮竟鐣?
杩欑増 `Joern` 闈欐€侀樁娈靛凡缁忓仛鍒帮細

- case 绾у畬鏁存枃浠剁粍瀵煎叆
- source/sink 瀹氫綅
- 鏀寔鍙樹綋涓婄殑鐪熷疄鏁版嵁娴佽矾寰勬仮澶?- 鍐呴儴璋冪敤閾炬仮澶?- 璋冪敤杈硅瘉鎹鍑?
浣嗛渶瑕佸瀹炶鏄庯細

- `CWE259` 鐨勬櫘閫氬弬鏁颁紶閫掑彉浣撳凡缁忚兘瀵煎嚭鐪熷疄鍙橀噺绾ф暟鎹祦璺緞
- `CWE78` 鐨?`51/52/53/54` 閾惧紡璋冪敤鍙樹綋宸茬粡鑳藉鍑鸿法鍑芥暟 `badSink` 鍙傛暟浼犳挱璺緞
- 鏌愪簺 `CWE78` 鍜屾瀯閫?鏋愭瀯绫诲彉浣撲粛浼氬彈鍒?`recv` 鍐欑紦鍐插尯璇箟銆佹垚鍛樺瓧娈典紶鎾拰 `COMMAND_ARG3` 瀹忓睍寮€闄愬埗
- 杩欑被鏍蜂緥鐨勭粨鏋滈噷浼氭槑纭爣璁?`joern dataflow path: unavailable for this case`

瀵硅繖缁?`Juliet` 浠诲姟鏉ヨ锛岃繖宸茬粡瓒冲鏀拺鈥滃厛闈欐€佸垎鏋愶紝鍐嶈澶фā鍨嬪垽鏂€濈殑娴佺▼锛岃€屼笖姣斿彧鐪?`source/sink` 鏇村悎鐞嗐€?
## 鐩綍缁撴瀯

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
|-- tests/
|   `-- test_pipeline.py
`-- main.py
```

## 娴嬭瘯

```powershell
python -m unittest discover -s tests -v
```

褰撳墠娴嬭瘯瑕嗙洊锛?
- `20` 涓富鍩哄噯瀹炰緥鐨勬灇涓?- `Joern` 鍏ㄦ枃浠剁粍瀵煎叆
- `CWE78` / `CWE259` 鍛戒腑瀹氫綅
- 閾惧紡浼犳挱鍙樹綋鐨勮皟鐢ㄩ摼璇佹嵁
- 鏀寔鍙樹綋涓婄殑鏁版嵁娴佽瘉鎹?- 鏋勯€?鏋愭瀯娴?- `20` 鏉?`Good Path` 涓嶈鎶?
## 鎻愪氦寤鸿

寤鸿鎻愪氦锛?
- `benchmark_subset/`
- `src/`
- `tests/`
- `docs/`
- `config/runtime_config.example.json`
- `results/`
- `README.md`
- `main.py`

涓嶅缓璁彁浜わ細

- `config/runtime_config.local.json`
- `workspace/`
- `.joern_case_tmp/`
- 澶栭儴瀹夎鐨?`JDK`
- 澶栭儴瀹夎鐨?`Joern`
