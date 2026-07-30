# Autofuzz

Autofuzz 是一个使用 Go 编写的自动化编排工具。它接收一个本地 C/C++ 库目录或 GitHub/GitCode 仓库链接，由 Codex Agent 自主完成项目分析、构建和 PromeFuzz 配置，再自动执行 API 分析、fuzz driver 生成和运行验证。

Autofuzz 是独立项目，不会向 PromeFuzz 源码目录添加代码。所有 PromeFuzz 阶段都通过其现有 Python 虚拟环境以子进程方式执行。

## 功能

Autofuzz 当前可以：

1. 接收本地目录或 GitHub/GitCode 仓库链接。
2. 将本地源码复制到独立工作目录，或浅克隆 GitHub/GitCode 仓库。
3. 由 workspace-write Codex Agent 阅读项目、执行构建命令、分析失败并自行重试。
4. 由第二个 Codex Agent 直接创建和修复 `library.toml`。
5. 导出并验证 `compile_commands.json`。
6. 验收 Codex 生成的 PromeFuzz `library.toml` 并用 preprocess 验证 API 范围。
7. 依次运行 PromeFuzz 的 `preprocess`、`comprehend` 和 `generate`。
8. 从 API 调用关系中选择一组 2～6 个生命周期相关函数。
9. 编译生成的 fuzz driver，并执行 10 次 libFuzzer 冒烟测试。
10. 保存 Agent 会话、构建报告、配置报告和命令日志，支持中断后继续运行。

## 环境要求

- Go 1.22 或更高版本
- Node.js 和 npm；仅在重新构建 Web 静态资源时需要
- Git
- Clang/Clang++
- CMake
- 已构建并完成配置的 PromeFuzz
- PromeFuzz 的 `.venv` 或其他 uv 虚拟环境
- 已登录且可以正常调用的 Codex CLI；项目分析、构建规划和 PromeFuzz LLM 任务都会使用它
- 可用的 embedding 模型服务
- Bear，仅 Make 和 Autotools 项目需要

PromeFuzz 的 `config.toml` 应提前配置好 LLM 和 embedding 模型。例如本项目的验证环境使用 Codex CLI 作为 LLM，并使用兼容 OpenAI embeddings API 的本地服务。

## 编译 Autofuzz

```bash
cd /home/tsj/fuzz_agent/autofuzz
make
```

`make` 会先通过 npm/Vite 构建 Vue Web 页面到 `internal/webui/static`，再编译完整的 Go 二进制。`make test` 会同时执行 Vitest 前端组件测试和 Go 测试：

```text
bin/autofuzz
bin/autofuzz-web
```

也可以只执行单独目标：

```bash
make web
make go
make test
```

编译完成后可查看 CLI 参数：

```bash
./bin/autofuzz --help
```

## Web 控制台

Autofuzz 提供一个 Web 控制台。静态资源在编译时嵌入 `autofuzz-web`，运行已构建好的服务不需要 Node.js。启动服务：

```bash
cd /home/tsj/fuzz_agent/autofuzz
./bin/autofuzz-web
```

默认访问地址：

```text
http://127.0.0.1:8080
```

可以指定其他监听地址：

```bash
./bin/autofuzz-web --listen 127.0.0.1:9090
```

控制台使用 Vue Router 的 hash 路由保存 Dashboard、Tasks、Task Detail 和详情 Tab 状态；刷新页面或使用浏览器前进、后退时可以恢复当前视图。

Web 表单覆盖当前 Autofuzz CLI 的业务配置项：目标仓库、Git ref、workspace、PromeFuzz 路径、配置文件、虚拟环境 Python、并发度、Codex 命令/模型/profile、恢复运行和停止阶段。

启动任务后，页面会显示以下阶段：

```text
准备源码 → 自主构建 → 生成 library.toml → API 预处理
         → API 理解 → All-cover 全量生成 → 持续 Fuzz
                                      持续 Fuzz ⇄ LLM 优化分析
```

正在运行的阶段显示旋转图标，成功和失败阶段分别显示对应状态。持续 Fuzz 与 LLM 优化分析在页面中显示为循环卡组；每次定时或手动分析都会显示覆盖采集、Codex 分析、结果校验和 driver 重建状态，并在下方保留每轮摘要。流程快照写入 `logs/fuzzing/fuzz-flow.json`，刷新页面或重启 Web 服务后仍可恢复。页面使用 Server-Sent Events（SSE）持续接收运行事件，并以低频轮询刷新 coverage、snapshot 和 crash 队列等派生数据。

Autofuzz 直接启动的 Codex Agent 调用使用：

```bash
codex exec --json ...
```

Codex CLI 的 JSONL stdout 会实时显示在独立的事件面板，同时继续完整写入原有 `codex.stdout.log`。其中包括回合状态、Agent 消息、推理条目和命令执行事件。构建报告和 `library.toml` 报告仍通过 `--output-last-message` 与 JSON Schema 验收，不依赖事件流推断结果。

当前只有以下 Autofuzz 直接掌握的 Codex 阶段提供原始 JSON 事件：

- `built`：Codex 自主分析和构建。
- `configured`：Codex 创建或修复 `library.toml`。
- `fuzzing`：Codex 分析覆盖停滞、直接优化 driver，并在需要时触发重建。

`comprehended` 和 `generated` 中的 LLM 调用由 PromeFuzz Python 进程内部创建。Autofuzz 无法直接取得这些 Codex 子进程的 JSONL，因此页面将其显示为 PromeFuzz 普通日志。PromeFuzz 子进程使用 `PYTHONUNBUFFERED=1`，日志会尽可能实时转发。

Web 控制面可以执行目标仓库提供的构建代码，也允许配置本地 Codex 可执行文件。默认只监听 `127.0.0.1`；不要直接暴露到不可信网络。对于不可信仓库，仍应在一次性容器或隔离虚拟机中运行。

## 使用本地源码目录

仓库中包含一个有 8 个 API 的测试 C 库，可以直接进行完整验证：

```bash
cd /home/tsj/fuzz_agent/autofuzz

./bin/autofuzz \
  --promefuzz ../PromeFuzz \
  ./testdata/sampleclib
```

也可以传入其他本地项目的绝对路径或相对路径：

```bash
./bin/autofuzz /path/to/local/c-library
```

本地项目不会直接在原目录中构建。Autofuzz 会先将源码复制到目标工作目录，并排除 `.git`、常见构建目录和符号链接。复制完成后会计算源码内容哈希，并保存到运行状态中。

## 使用 GitHub 仓库

HTTPS 链接示例：

```bash
./bin/autofuzz \
  --promefuzz ../PromeFuzz \
  https://github.com/DaveGamble/cJSON.git
```

也支持 GitHub SSH 链接：

```bash
./bin/autofuzz git@github.com:DaveGamble/cJSON.git
```

指定分支、标签或其他 Git ref：

```bash
./bin/autofuzz \
  --ref v1.7.19 \
  https://github.com/DaveGamble/cJSON.git
```

## 使用 GitCode 仓库

Autofuzz 同样支持 [GitCode](https://gitcode.com) 仓库链接，用法与 GitHub 一致。

HTTPS 链接示例：

```bash
./bin/autofuzz \
  --promefuzz ../PromeFuzz \
  https://gitcode.com/owner/repo.git
```

也支持 GitCode SSH 链接：

```bash
./bin/autofuzz git@gitcode.com:owner/repo.git
```

指定分支、标签或其他 Git ref：

```bash
./bin/autofuzz \
  --ref <ref> \
  https://gitcode.com/owner/repo.git
```

Autofuzz 默认执行浅克隆，不递归下载 submodule，并在状态文件中记录实际使用的 commit。GitHub 和 GitCode 的处理方式完全一致。

## 安全提示

编译第三方仓库会执行仓库提供的 CMake、Makefile、configure 脚本及其他构建逻辑。Autofuzz 现在默认授权 Codex 执行这些代码：源码复制或克隆完成后会直接进入自主构建，不再提供“只准备源码并等待信任授权”的分支。

这项默认行为不表示仓库已经过安全审计。对于不可信项目，应在一次性容器或隔离虚拟机中运行 Autofuzz。

## 自主构建和配置 Agent

构建阶段以 `--ephemeral --sandbox workspace-write --ignore-rules` 启动 Codex。Codex 在源码副本所在的目标 workspace 中全权负责：

1. 阅读 README、CI、构建文件、源码、测试和示例。
2. 选择并实际执行 CMake、Make、Meson、Autotools 或项目特有的本地构建命令。
3. 查看编译错误、修改 disposable 源码副本或构建选项并自行重试。
4. 使用 Clang、ASan 和调试信息，生成编译数据库和非测试静态库。
5. 验证产物后返回 `build-report.json`。

Go 不再生成或执行结构化 Plan，也没有命令白名单和固定构建兜底。Go 只验收 Codex 报告的路径确实位于目标 workspace、`compile_commands.json` 含 ASan，且静态库真实存在。

构建完成后，第二个 workspace-write Codex Agent直接创建 `library.toml`。它自主选择公共头文件、consumer、exclude/source 路径、静态库和链接参数，并可编译运行 consumer 验证配置。Go 会额外验收 `header_paths` 必须来自 `compile_commands.json` 可观测到的源码/构建头，并且每个头都能与 `install_dir` 下同名且内容一致的公开安装头对应；若 PromeFuzz 提取到 0 API，会把错误交回 Codex 修复 TOML 后再试。

指定 Codex 模型：

```bash
./bin/autofuzz \
  --codex-model <model> \
  /path/to/local/c-library
```

## 自动执行流程

Autofuzz 按以下阶段推进：

1. `cloned`：复制本地源码或克隆 GitHub/GitCode 仓库。
2. `built`：Codex 自主分析并构建项目，Go 验收 ASan 编译数据库和静态库。
3. `configured`：Codex 直接写 `library.toml`，Go 验收关键字段和路径。
4. `preprocessed`：运行 PromeFuzz API 提取；0 API 时要求 Codex 修复配置。
5. `comprehended`：运行 `funcpurp` 和 `funcrel` 源码理解任务。
6. `generated`：选择 API 生命周期并生成 fuzz driver。
7. `verified`：重新编译 driver，并执行 10 次 libFuzzer 冒烟测试。

生成的 library 配置固定使用：

```toml
document_paths = []
document_has_api_usage = false
```

第一版不会自动生成文档路径，也不会假定目标项目文档中包含 API 使用示例。

## 中断后继续运行

每完成一个阶段，Autofuzz 都会原子更新 `agent-state.json`。中断后可使用相同参数加 `--resume` 继续：

```bash
./bin/autofuzz \
  --resume \
  https://github.com/DaveGamble/cJSON.git
```

如果某个阶段为 `blocked` 或 `failed`，恢复时会回到最后一个成功阶段，只重试未完成的步骤。

注意：恢复时必须使用相同的仓库输入和 workspace。

## 只运行到指定阶段

可以通过 `--stop-after` 检查中间结果。例如只完成编译和 library 配置生成：

```bash
./bin/autofuzz \
  --stop-after configured \
  /path/to/local/c-library
```

可用阶段：

```text
built
configured
preprocessed
comprehended
generated
verified
```

## 常用参数

| 参数 | 默认值 | 说明 |
| --- | --- | --- |
| `--workspace` | `autofuzz-work` | 保存源码副本、构建结果和日志的目录 |
| `--promefuzz` | （必填） | PromeFuzz 项目路径 |
| `--promefuzz-config` | `<promefuzz>/config.toml` | PromeFuzz 主配置路径 |
| `--python` | `<promefuzz>/.venv/bin/python` | PromeFuzz 虚拟环境中的 Python |
| `--ref` | 空 | Git 分支、标签或 ref |
| `--jobs` | CPU 核心数 | 编译并行度 |
| `--pool-size` | `5` | PromeFuzz/Codex 并发度 |
| `--max-functions` | `6` | 单个初始 driver 最多包含的 API 数量 |
| `--codex-command` | `codex` | 自主构建和配置使用的 Codex CLI 程序 |
| `--codex-model` | 空 | 自主 Agent 使用的可选 Codex 模型 |
| `--codex-profile` | 空 | 自主 Agent 使用的可选 Codex profile |
| `--resume` | `false` | 从已有状态继续运行 |
| `--stop-after` | `verified` | 在指定阶段完成后停止 |
| `--verbose` | `false` | 在终端显示子进程输出，同时继续保存日志 |

## 工作目录和产物

默认情况下，每个目标保存在：

```text
autofuzz-work/<项目名>/
```

目录结构示例：

```text
autofuzz-work/sampleclib/
├── agent-state.json
├── source/
├── build/
├── install/
├── build-report.json
├── library-report.json
├── library.toml
├── logs/
└── out/
    ├── preprocessor/
    ├── comprehender/
    └── fuzz_driver/
        ├── fuzz_driver_1.c
        ├── fuzz_driver_1
        └── build_fuzz_driver_1.sh
```

主要产物：

- `agent-state.json`：当前阶段、源码版本、构建结果、选中 API 和错误记录。
- `build-report.json`：Codex 自主构建后报告的构建系统、语言、编译数据库和静态库。
- `library-report.json`：Codex 直接写入并验证 `library.toml` 后的报告。
- `library.toml`：Codex 直接创建的 PromeFuzz library 配置。
- `logs/autonomous-build-agent/`：自主构建 Agent 的 prompt、响应和完整执行日志。
- `logs/configure-agent-NN/`：直接生成或修复 TOML 的 Agent 日志。
- `logs/`：每条外部命令的参数、标准输出和标准错误。
- `out/preprocessor/api.json`：PromeFuzz 提取的 API 信息。
- `out/preprocessor/call_order.json`：用于选择 API 生命周期的调用关系。
- `out/fuzz_driver/fuzz_driver_1.c`：最终生成并通过验证的 fuzz driver。

## 测试

运行所有 Go 单元测试和构建集成测试：

```bash
env GOCACHE=/tmp/autofuzz-go-cache go test ./...
```

执行静态检查：

```bash
env GOCACHE=/tmp/autofuzz-go-cache go vet ./...
```

测试范围包括：

- 本地目录复制、排除规则和内容哈希。
- GitHub/GitCode URL 解析。
- 状态保存、加载和失败恢复。
- 自主构建报告的路径边界、ASan 编译数据库和静态库验收。
- Codex 直接生成的 TOML 必需字段、路径和静态库引用验收。
- API 解析和生命周期选择。
- 真实 CMake、Clang、ASan 静态库构建。

## 第一版限制

- 构建完全依赖 Codex 的分析和本机已有工具，没有固定构建兜底。
- Codex 可以修改 disposable 源码副本和执行仓库构建脚本，必须在隔离环境中处理不可信仓库。
- 当前要求目标项目可以生成静态库。
- 不会自动安装缺少的编译器、构建工具或系统依赖。
- API 数量超过 2000 时，不自动运行计算成本较高的语义相关性分析。
- API 数量超过 1000 时，认为头文件范围过宽并停止，暂不自动缩小范围。
- 每次生成一个聚焦的初始 driver，不自动启动 all-cover 模式。
- 目标项目依赖 submodule 时，需要后续增加 submodule 策略或手动准备本地源码。

## 常见问题

### 提示状态已经存在

已有目标状态时，可以继续运行：

```bash
./bin/autofuzz --resume <目标>
```

也可以通过 `--workspace` 指定一个新的工作目录。

### PromeFuzz 无法调用 Codex 或 embedding 服务

先在 PromeFuzz 目录中确认：

- `.venv/bin/python` 存在。
- `config.toml` 中的 LLM 类型为已配置的 Codex CLI 类型。
- Codex CLI 已登录并可以独立执行。
- embedding 服务地址和模型名称正确。
- Autofuzz 的 `--promefuzz-config` 与 `--python` 指向正确文件。

### 生成 driver 后验证失败

检查目标目录下的：

```text
logs/generate/
logs/verify/
out/fuzz_driver/
```

命令参数、标准输出和标准错误分别保存在对应的 `*.command.log`、`*.stdout.log` 和 `*.stderr.log` 文件中。
