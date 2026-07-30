# PromeFuzz 各阶段产物说明

本文从 fuzz 测试业务角度梳理 PromeFuzz 的主要阶段，并结合实际产物说明：

- 每个阶段会生成什么文件
- 这些文件的结构大致长什么样
- 这些文件是如何生成出来的
- 它们会被后续哪个阶段消费

示例主要取自本地样本库 `sampleclib` 的输出目录：

- [sampleclib output](/home/tsj/fuzz_agent/autofuzz/autofuzz-work/sampleclib/output)

## 总览

PromeFuzz 的主链路可以理解为：

1. 配置测试对象
2. 抽取公开 API 和源码结构
3. 推断 API 之间的使用关系
4. 理解 API 语义和文档
5. 选择一组 API 作为一个测试场景
6. 生成并修复 fuzz driver
7. 汇总可用 driver 形成统一 fuzz 入口
8. 运行 fuzz 并分析 crash

从产物依赖关系看，大致是：

```text
library.toml + compile_commands.json
  -> output/preprocessor/*
  -> output/comprehender/*
  -> output/fuzz_driver/* + output/generator/*
  -> synthesized driver / corpus / crash reports / stats
```

## 阶段 0：测试对象配置

这一阶段的目标不是分析代码，而是定义“测试边界”。

关键输入：

- [library.toml](/home/tsj/fuzz_agent/autofuzz/autofuzz-work/sampleclib/library.toml)
- `compile_commands.json`
- 安装后的头文件和静态库

这一步没有复杂中间产物，但会决定后面所有结果的正确性。配置里最关键的是：

- `header_paths`：哪些编译/AST 侧头文件代表公开 API（且必须能与 install 头一一对应）
- `source_paths`：哪些源码属于库本体
- `consumer_case_paths`：有没有真实调用样例
- `driver_build_args`：driver 编译时怎么链接
- `output_path`：后续所有阶段产物写到哪里

如果这一步有误，后面很可能会出现两类问题：

- 抽到 0 个 API
- 把内部函数、配置头、工具函数错误地当成公开 fuzz 目标

## 阶段 1：Preprocess

这一阶段把“普通源码树”变成“结构化测试知识”。

产物目录：

- [output/preprocessor](/home/tsj/fuzz_agent/autofuzz/autofuzz-work/sampleclib/output/preprocessor)

### 1. `api.json`

作用：

- 公开 API 清单
- 按头文件归类
- 记录声明位置和实现位置

实际示例：

```json
{
  "/.../source/include/sample.h": {
    "sample_context_sum": [
      {
        "loc": "/.../source/src/sample.c:142:6",
        "decl_loc": "/.../source/include/sample.h:16:6"
      }
    ],
    "sample_context_create": [
      {
        "loc": "/.../source/src/sample.c:61:17",
        "decl_loc": "/.../source/include/sample.h:12:17"
      }
    ]
  }
}
```

来源文件：

- [api.json](/home/tsj/fuzz_agent/autofuzz/autofuzz-work/sampleclib/output/preprocessor/api.json)

如何生成：

1. 读取 `library.toml` 里的 `header_paths`
2. 通过 `compile_commands.json` 获得真实编译上下文
3. 用 AST 分析头文件里的公开声明
4. 在源码里定位这些声明对应的真实实现
5. 过滤掉不属于公开测试面的符号

由谁生成：

- [cli/preprocess.py](/home/tsj/fuzz_agent/PromeFuzz/cli/preprocess.py:105)

后续由谁使用：

- `comprehend`：逐个 API 做语义理解
- `generate`：决定有哪些 API 要覆盖
- `analyze`：判断 crash 相关 API

### 2. `api.pkl`

作用：

- 与 `api.json` 对应的内部二进制格式

如何生成：

- 与 `api.json` 同源，只是持久化为 Python 可直接加载的数据结构

后续由谁使用：

- `comprehend`
- `generate`
- `analyze`
- `stats`

### 3. `info.json`

作用：

- API 源码级详情仓库
- 补充签名、类型依赖、实现范围

实际示例：

```json
{
  "function_infos": {
    "/.../sample.c:61:17": {
      "signature": "sample_context *sample_context_create(void);",
      "used_typedefs": [
        "sample_context (.../sample.h:10:31)"
      ],
      "impl_range": [
        "/.../sample.c:61:1",
        "/.../sample.c:64:1"
      ],
      "name": "sample_context_create"
    }
  },
  "typedef_infos": {
    "/.../sample.h:10:31": {
      "definition": "typedef struct sample_context sample_context;"
    }
  }
}
```

来源文件：

- [info.json](/home/tsj/fuzz_agent/autofuzz/autofuzz-work/sampleclib/output/preprocessor/info.json)

如何生成：

1. 扫描编译数据库覆盖到的源码
2. 提取函数、结构体、typedef、类定义
3. 建立“函数签名 -> 依赖类型 -> 实现范围”的索引

由谁生成：

- [cli/preprocess.py](/home/tsj/fuzz_agent/PromeFuzz/cli/preprocess.py:170)

后续由谁使用：

- `comprehend`：给 LLM 提供函数上下文
- `generate`：生成 driver 时补充类型、签名、实现信息
- `analyze`：把 crash 报告和源码关联起来

### 4. `meta.json`

作用：

- 更底层的源码元数据
- 是 `info.json` 的原始来源之一

如何生成：

1. 直接对源码做 AST 级提取
2. 将函数、类型、定义位置等原始信息落盘

由谁生成：

- [cli/preprocess.py](/home/tsj/fuzz_agent/PromeFuzz/cli/preprocess.py:105)

后续用途：

- 主要给 `info`、`relevance`、`complexity` 计算使用

### 5. `incidentals.json`

作用：

- API 之间的间接关联
- 表示“测某个 API 时，可能顺带带动哪些 API”

实际示例：

```json
{
  "sample_context_parse at sample.c:91:5 in sample.h": [
    "sample_context_set at sample.c:66:5 in sample.h"
  ]
}
```

来源文件：

- [incidentals.json](/home/tsj/fuzz_agent/autofuzz/autofuzz-work/sampleclib/output/preprocessor/incidentals.json)

如何生成：

1. 从库内部调用图出发
2. 看每个公开 API 会触发哪些其他 API 或相关能力
3. 抽出“顺带覆盖关系”

由谁生成：

- [cli/preprocess.py](/home/tsj/fuzz_agent/PromeFuzz/cli/preprocess.py:139)

后续由谁使用：

- `generate` 阶段的调度器

业务意义：

- 一个 driver 如果直接测了 `A`，同时顺带覆盖 `B`
- 调度器会把这类“带动覆盖”的价值算进去

### 6. `call_order.json`

作用：

- 真实 consumer 或测试代码中的调用顺序模式

实际示例：

```json
{
  "OrderSet 1": {
    "size": 6,
    "apis": [
      "sample_context_create ...",
      "sample_context_parse ...",
      "sample_context_sum ...",
      "sample_context_serialize ...",
      "sample_buffer_free ...",
      "sample_context_destroy ..."
    ]
  }
}
```

来源文件：

- [call_order.json](/home/tsj/fuzz_agent/autofuzz/autofuzz-work/sampleclib/output/preprocessor/call_order.json)

如何生成：

1. 遍历 `consumer_case_paths`
2. 对示例代码建调用图
3. 抽出“初始化 -> 使用 -> 清理”类顺序

由谁生成：

- [cli/preprocess.py](/home/tsj/fuzz_agent/PromeFuzz/cli/preprocess.py:159)

后续由谁使用：

- `generate`

业务意义：

- 如果能从真实代码学到顺序，driver 更容易有效
- 没有这个产物时，生成阶段只能更多依赖相关性和 LLM 猜测

### 7. `sources.json`

作用：

- 库源码文件清单

如何生成：

1. 汇总 compile_commands 对应源文件
2. 加上 API 头文件

由谁生成：

- [cli/preprocess.py](/home/tsj/fuzz_agent/PromeFuzz/cli/preprocess.py:121)

后续由谁使用：

- `analyze`

业务意义：

- crash 栈里如果落在这些文件上，更可能是库问题
- 如果落在 driver 或外部库上，归因方向不同

### 8. `complexity.pkl` 和相关性文件

常见产物：

- `complexity.pkl`
- `type_relev.pkl`
- `class_scope_relev.pkl`
- `call_scope_relev.pkl`

作用：

- API 难度和相关性打分

如何生成：

1. 从函数体、类型、consumer 调用范围计算复杂度和相关性
2. 落为调度器可直接消费的数据

后续由谁使用：

- `generate`

业务意义：

- 决定“下一轮该优先测谁”
- 覆盖低、复杂度高、相关性强的 API 更容易被选中

## 阶段 2：Comprehend

这一阶段补的是“语义知识”，不是结构知识。

产物目录：

- [output/comprehender](/home/tsj/fuzz_agent/autofuzz/autofuzz-work/sampleclib/output/comprehender)

### 1. `documents/documents.json`

作用：

- 文档源列表

实际示例：

```json
[
  "/home/tsj/fuzz_agent/autofuzz/autofuzz-work/sampleclib/source/CMakeLists.txt"
]
```

来源文件：

- [documents.json](/home/tsj/fuzz_agent/autofuzz/autofuzz-work/sampleclib/output/comprehender/documents/documents.json)

如何生成：

1. 读取 `library.toml` 的 `document_paths`
2. 将文件、目录、网页 URL 展开成待索引清单

由谁生成：

- `Knowledge.from_config(...)`
- 落盘逻辑在 [llm/rag.py](/home/tsj/fuzz_agent/PromeFuzz/src/llm/rag.py:202)

### 2. `documents/chroma.sqlite3`

作用：

- 文档切片后的向量检索库

如何生成：

1. 切分文档内容
2. 对切片做 embedding
3. 存到 Chroma 向量数据库

后续由谁使用：

- `comprehend` 自己
- 后续 crash 分析中的语义补充

业务意义：

- 后续每次问 LLM 时，先检索相关文档片段，而不是把整库文档扔进去

### 3. `comp.json`

作用：

- 库用途和 API 用法的自然语言总结

实际示例：

```json
{
  "purpose": "",
  "functions": {
    "sample_context_create": "`sample_context_create` allocates and zero-initializes a `sample_context` struct...",
    "sample_context_parse": "`sample_context_parse` parses a text string into integer values stored in `context`...",
    "sample_buffer_free": "`sample_buffer_free` is a wrapper around the standard C `free()` function..."
  }
}
```

来源文件：

- [comp.json](/home/tsj/fuzz_agent/autofuzz/autofuzz-work/sampleclib/output/comprehender/comp.json)

如何生成：

1. 加载 `preprocessor/api.pkl` 和 `info.pkl`
2. 对每个 API 检索相关文档片段
3. 把签名、源码结构、文档片段一起喂给 LLM
4. 输出函数用途、参数含义、资源管理、失败语义等说明

由谁生成：

- [cli/comprehend.py](/home/tsj/fuzz_agent/PromeFuzz/cli/comprehend.py:146)

后续由谁使用：

- `generate`
- `analyze`

业务意义：

- 这是防止 LLM 乱写 driver 的关键语义来源

### 4. `comp.pkl`

作用：

- `comp.json` 的内部格式

后续由谁使用：

- `generate`
- `analyze`

### 5. `semantic_relev.pkl`

作用：

- API 语义相关性

如何生成：

1. LLM 批量判断 API 之间是否属于同一使用场景或生命周期
2. 产出相关性矩阵

由谁生成：

- [cli/comprehend.py](/home/tsj/fuzz_agent/PromeFuzz/cli/comprehend.py:154)

后续由谁使用：

- `generate`

业务意义：

- 让调度器知道“谁和谁应该一起测”

## 阶段 3：Generate

这一阶段把结构知识和语义知识变成真正的 fuzz driver。

产物目录：

- [output/fuzz_driver](/home/tsj/fuzz_agent/autofuzz/autofuzz-work/sampleclib/output/fuzz_driver)
- [output/generator](/home/tsj/fuzz_agent/autofuzz/autofuzz-work/sampleclib/output/generator)
- [output/tmp](/home/tsj/fuzz_agent/autofuzz/autofuzz-work/sampleclib/output/tmp)

### 1. `fuzz_driver_*.c` 或 `fuzz_driver_*.cpp`

作用：

- 单个最终通过验证的 fuzz driver

实际示例：

- [fuzz_driver_1.c](/home/tsj/fuzz_agent/autofuzz/autofuzz-work/sampleclib/output/fuzz_driver/fuzz_driver_1.c)

片段：

```c
#include "sample.h"

int LLVMFuzzerTestOneInput(const uint8_t *Data, size_t Size) {
    sample_context_destroy(NULL);
    sample_buffer_free(NULL);

    sample_context *ctx = sample_context_create();
    if (!ctx) return 0;

    if (Size > 0) {
        char *text = (char *)malloc(Size + 1);
        memcpy(text, Data, Size);
        text[Size] = '\0';
        sample_context_parse(ctx, text);
        sample_context_sum(ctx);
        free(text);
    }

    sample_context_destroy(ctx);
    return 0;
}
```

如何生成：

1. 调度器先选出一个 API 集合
2. 信息收集器从 `info.pkl`、`comp.pkl`、`call_order.pkl` 等收集上下文
3. LLM 生成 driver 初稿
4. 本地编译并运行短时间验证
5. 若编译失败或运行崩溃，进入修复轮次
6. 通过后保存到 `fuzz_driver/`

由谁生成：

- [generator.py](/home/tsj/fuzz_agent/PromeFuzz/src/generator/generator.py:88)
- [worker.py](/home/tsj/fuzz_agent/PromeFuzz/src/generator/worker.py:96)
- [sanitizer.py](/home/tsj/fuzz_agent/PromeFuzz/src/generator/sanitizer.py:141)

### 2. `build_fuzz_driver_*.sh`

作用：

- 单个 driver 的真实构建脚本

实际示例：

- [build_fuzz_driver_1.sh](/home/tsj/fuzz_agent/autofuzz/autofuzz-work/sampleclib/output/fuzz_driver/build_fuzz_driver_1.sh)

片段：

```bash
clang .../fuzz_driver_1.c -o .../fuzz_driver_1 \
  -fsanitize=fuzzer,address,undefined -g \
  -I.../source/include \
  .../build/libsampleclib.a
```

如何生成：

1. 读取 `library.toml` 的 `driver_build_args`
2. 根据语言和源文件名拼接 build 命令

由谁生成：

- [driver.py](/home/tsj/fuzz_agent/PromeFuzz/src/generator/driver.py:173)

用途：

- 人工复现构建
- 外层系统复编译验收

### 3. `state.pkl` 和 `state.txt`

作用：

- 生成阶段账本

实际示例：

- [state.txt](/home/tsj/fuzz_agent/autofuzz/autofuzz-work/sampleclib/output/generator/state.txt)

片段：

```python
{
  'function_set_number': 12,
  'fuzz_driver_number': 12,
  'fuzz_driver_success': {1: True, 2: True, 4: False},
  'scheduler_statistics': {
    'total_occurrences': 120,
    'total_tested': 8
  }
}
```

如何生成：

1. 每调度一个 API 集合更新一次
2. 每生成、修复、成功或失败一个 driver 更新一次
3. 持续写回 `state.pkl`
4. 额外输出 `state.txt` 供人工查看

由谁生成：

- [worker.py](/home/tsj/fuzz_agent/PromeFuzz/src/generator/worker.py:317)

后续由谁使用：

- `generate` 自己的断点恢复
- `stats`

业务意义：

- 知道哪些 API 已覆盖
- 知道哪些 driver 成功，哪些失败
- 知道哪些 API 反复生成失败

### 4. `tmp/fuzz_driver_*`

作用：

- driver 修复过程中的中间代码和临时二进制

实际示例结构：

```text
tmp/fuzz_driver_3/
  fuzz_driver_3_sanitizing_1784881435.c
  fuzz_driver_3_sanitizing_1784881435
```

如何生成：

1. 每次修复轮次都会把当前代码写到临时目录
2. 编译并运行 1 秒短跑

由谁生成：

- [sanitizer.py](/home/tsj/fuzz_agent/PromeFuzz/src/generator/sanitizer.py:57)

用途：

- 排查“为什么这个 driver 修不好”

### 5. `tmp/postprocessing/*.json`

作用：

- 检查 driver 实际调用了哪些 API

如何生成：

1. 对生成后的 driver 再做一次 AST/调用检查
2. 与目标 API 集合比对

由谁生成：

- [driver.py](/home/tsj/fuzz_agent/PromeFuzz/src/generator/driver.py:388)

业务意义：

- 防止“名义上瞄准 6 个 API，实际上只调到了 2 个”

## 阶段 4：Synthesize

这一阶段把多个成功 driver 合成一个统一 fuzz 入口。

### 1. `synthesized/entry.c`

作用：

- 总入口
- 按输入首字节分发到不同子 driver

实际示例：

- [entry.c](/home/tsj/fuzz_agent/autofuzz/autofuzz-work/sampleclib/output/fuzz_driver/synthesized/entry.c)

片段：

```c
int LLVMFuzzerTestOneInput(const uint8_t *Data, size_t Size) {
    unsigned int driverIndex = 0;
    memcpy(&driverIndex, Data, 1);
    switch (driverIndex % 6) {
        case 0:
            return LLVMFuzzerTestOneInput_1(remainData, remainSize);
        case 1:
            return LLVMFuzzerTestOneInput_2(remainData, remainSize);
    }
    return 0;
}
```

如何生成：

1. 收集所有成功 driver
2. 把各自的 `LLVMFuzzerTestOneInput` 改名为带编号版本
3. 生成一个统一入口做分发

由谁生成：

- [synthesizer.py](/home/tsj/fuzz_agent/PromeFuzz/src/generator/synthesizer.py:270)

### 2. `synthesized/*.c`

作用：

- 每个成功 driver 的汇总版副本

用途：

- 最终一起编译成统一二进制

### 3. `build_synthesized_driver.sh`

作用：

- 汇总 driver 的构建脚本

实际示例：

- [build_synthesized_driver.sh](/home/tsj/fuzz_agent/autofuzz/autofuzz-work/sampleclib/output/fuzz_driver/build_synthesized_driver.sh)

片段：

```bash
clang .../synthesized/*.c -o .../synthesized_driver \
  -fsanitize=fuzzer,address,undefined -g ...
```

如何生成：

- 根据单个 driver 的构建信息统一合成

其他相关脚本：

- `build_aflpp_synthesized_driver.sh`
- `build_gcov_synthesized_driver.sh`
- `build_cov_synthesized_driver.sh`

用途：

- 分别服务于持续 fuzz、覆盖统计等不同运行模式

## 阶段 5：Fuzz 运行

严格说这不完全属于 PromeFuzz 主 CLI 的 `generate` 阶段，但它直接消费前面的 driver 产物。

典型产物：

- `fuzz_driver/corpus/*`

作用：

- libFuzzer 保存下来的有效输入样本

如何生成：

1. 运行统一 driver 或单个 driver
2. 变异输入
3. 发现新路径或保留有价值样本时写入 corpus

用途：

- 回归测试
- 继续 fuzz
- 覆盖分析

## 阶段 6：Analyze

这一阶段输入 crash 日志，输出 triage 报告。

产物形式：

- `TP-*.md`
- `FP-*.md`
- `UN-*.md`

实际示例来源：

- [example report](/home/tsj/fuzz_agent/PromeFuzz/examples/rapidcsv/report/TP-heap-buffer-overflow@_promefuzz_database_rapidcsv_latest_code_src_rapidcsv.h:844:18-3.log.md)

结构示例：

```md
# Fuzz driver
```cpp
...触发 crash 的 driver...
```

# Crash report
## Crash reason
AddressSanitizer: heap-buffer-overflow ...

## Backtrace
#0 ...
#1 ...

# Analysis from LLM
The crash is a Bug in library...
```

如何生成：

1. 解析 crash 日志
2. 对 crash 做去重
3. 用 `sources.json` 判断 crash 落点
4. 用 `api.pkl`、`info.pkl`、`comp.pkl` 组装上下文
5. LLM 输出归因结论
6. 按 `TP`、`FP`、`UN` 分类写 Markdown

由谁生成：

- [cli/analyze.py](/home/tsj/fuzz_agent/PromeFuzz/cli/analyze.py:118)
- [analyzer/report.py](/home/tsj/fuzz_agent/PromeFuzz/src/analyzer/report.py:108)

业务意义：

- `TP`：更像库自身 bug
- `FP`：更像 driver 误用
- `UN`：无法确认

## 阶段 7：Stats

这一阶段做汇总报告。

关键输入：

- `preprocessor/api.pkl`
- `generator/state.pkl`
- `fuzz_driver/*`
- crash 报告

典型输出：

- 一个 Excel 报告文件

如何生成：

1. 读取 API 总数
2. 读取成功/失败 driver 数量
3. 读取 LLM token 和耗时
4. 汇总 crash 情况

由谁生成：

- [cli/stats.py](/home/tsj/fuzz_agent/PromeFuzz/cli/stats.py:72)

业务意义：

- 看 API 覆盖率
- 看 driver 成功率
- 看 LLM 成本
- 看 crash 产出质量

## 按阶段看最值得人工检查的文件

如果只人工抽查几个文件，优先顺序建议是：

1. 配置阶段：
   [library.toml](/home/tsj/fuzz_agent/autofuzz/autofuzz-work/sampleclib/library.toml)

2. Preprocess：
   [api.json](/home/tsj/fuzz_agent/autofuzz/autofuzz-work/sampleclib/output/preprocessor/api.json)

3. Comprehend：
   [comp.json](/home/tsj/fuzz_agent/autofuzz/autofuzz-work/sampleclib/output/comprehender/comp.json)

4. Generate：
   [state.txt](/home/tsj/fuzz_agent/autofuzz/autofuzz-work/sampleclib/output/generator/state.txt)
   和
   [fuzz_driver_1.c](/home/tsj/fuzz_agent/autofuzz/autofuzz-work/sampleclib/output/fuzz_driver/fuzz_driver_1.c)

5. Analyze：
   任意 `TP/FP/UN` 报告

这几个文件基本能反映：

- API 面定义得对不对
- LLM 理解得对不对
- driver 生成得像不像真实使用方式
- crash 判断是否可信
