---
title: CodeQL 从入门到哪里我也不知道啊啊啊
date: 2025-07-31 15:18:00
tags: [静态分析]
categories: 学习
---

怎么全是报错啊啊啊啊啊啊
<!--more-->

## What is CodeQL?

CodeQL 是由 GitHub 开发的一款语义代码分析引擎，它允许开发者和安全研究人员通过编写查询来发现代码中的漏洞和安全问题。与传统静态分析工具不同，CodeQL 将代码视为数据，通过查询代码中的数据关系来发现潜在问题。

跟 SQL 长挺像

需要少许数据库的基础，至少得能看懂简单的查询语句

## 做个小测试

假设有以下 Python 代码：

```python
if error: pass
```

很明显，这个 `if` 语句是冗余的，因为它啥都没干，有没有都一样。
那么我们可以用 CodeQL 来查找这种冗余的 `if` 语句。
使用以下 CodeQL 查询：

```sql
import python

from If ifstmt, Stmt pass
where pass = ifstmt.getStmt(0) and
  pass instanceof Pass
select ifstmt, "This 'if' statement is redundant."
```

那这个 QL 是什么意思呢

`import python` 是导入 Python 语言的 CodeQL 库，里面定义了如何处理 Python 代码，正如你平时的编程一样，一般情况下，库文件如何通过底层代码实现是无需理会的。
`from If ifstmt, Stmt pass` 是在查询中定义了两个变量：`ifstmt` 和 `pass`，`If` 和 `Stmt` 分别是对应的 CodeQL 类型。`If` 代表一个 if 语句，而 `Stmt` 代表一个通用的语句。
`where pass = ifstmt.getStmt(0) and pass instanceof Pass` 是查询的条件部分，包含两个条件：

1. `pass = ifstmt.getStmt(0)`：表示 `ifstmt` 的第一个语句是 `pass`。
2. `pass instanceof Pass`：表示 `pass` 是一个 `Pass` 语句。

`select ifstmt, "This 'if' statement is redundant."` 是查询的结果部分，表示如果满足上述条件，则返回 `ifstmt` 和一条消息，如此就可以找到所有冗余的 if 语句。

## 又老又新的语法，落后的 AI

我用 AI 生成的 QL 查询语句，基本没有能跑的，查了好久发现 DataFlow 进行过一次[改革](https://github.blog/changelog/2023-08-14-new-dataflow-api-for-writing-custom-codeql-queries/)
旧语法在 2024 年 12 月开始就开始完全不支持了，但是互联网的资料基本都停留在 2020 年左右，导致基本没法抄

以下是传统派的写法：

```sql
class SensitiveLoggerConfiguration extends TaintTracking::Configuration {
  SensitiveLoggerConfiguration() { this = "SensitiveLoggerConfiguration" } // 6: characteristic predicate with dummy string value (see below)

  override predicate isSource(DataFlow::Node source) { source.asExpr() instanceof CredentialExpr }

  override predicate isSink(DataFlow::Node sink) { sinkNode(sink, "log-injection") }

  override predicate isSanitizer(DataFlow::Node sanitizer) {
    sanitizer.asExpr() instanceof LiveLiteral or
    sanitizer.getType() instanceof PrimitiveType or
    sanitizer.getType() instanceof BoxedType or
    sanitizer.getType() instanceof NumberType or
    sanitizer.getType() instanceof TypeType
  }

  override predicate isSanitizerIn(DataFlow::Node node) { this.isSource(node) }
}

import DataFlow::PathGraph

from SensitiveLoggerConfiguration cfg, DataFlow::PathNode source, DataFlow::PathNode sink
where cfg.hasFlowPath(source, sink)
select sink.getNode(), source, sink, "This $@ is written to a log file.",
 source.getNode(),
  "potentially sensitive information"
```

维新派则如下：

```sql
module SensitiveLoggerConfig implements DataFlow::ConfigSig {  // 1: module always implements DataFlow::ConfigSig or DataFlow::StateConfigSig
  predicate isSource(DataFlow::Node source) { source.asExpr() instanceof CredentialExpr } // 3: no need to specify 'override'
  predicate isSink(DataFlow::Node sink) { sinkNode(sink, "log-injection") }

  predicate isBarrier(DataFlow::Node sanitizer) {  // 4: 'isBarrier' replaces 'isSanitizer'
    sanitizer.asExpr() instanceof LiveLiteral or
    sanitizer.getType() instanceof PrimitiveType or
    sanitizer.getType() instanceof BoxedType or
    sanitizer.getType() instanceof NumberType or
    sanitizer.getType() instanceof TypeType
  }

  predicate isBarrierIn(DataFlow::Node node) { isSource(node) } // 4: isBarrierIn instead of isSanitizerIn

}

module SensitiveLoggerFlow = TaintTracking::Global<SensitiveLoggerConfig>; // 2: TaintTracking selected 

import SensitiveLoggerFlow::PathGraph  // 7: the PathGraph specific to the module you are using

from SensitiveLoggerFlow::PathNode source, SensitiveLoggerFlow::PathNode sink  // 8 & 9: using the module directly
where SensitiveLoggerFlow::flowPath(source, sink)  // 9: using the flowPath from the module 
select sink.getNode(), source, sink, "This $@ is written to a log file.", source.getNode(),
  "potentially sensitive information"
```

上面的变化有空再慢慢研究

## 遇到的问题

可能会遇到权限问题，因为 CodeQL 在 `sudo` 创建数据库时会把整个文件夹的权限改成 `root`，导致后续执行 query 的时候报错：

```bash
sudo chown -R $(whoami):$(whoami) <dir>
```

现在我找到了一个 SQL 注入漏洞，想用 CodeQL 把它查出来，但是我不知道怎么写查询语句。
大概测了一下，发现 Source 和 Sink 都能找到，但是路径一条都没找出来。

因为现在漏洞还没公开，先暂停更新

// TODO

## 参考

<https://codeql.github.com/docs/codeql-language-guides/basic-query-for-python-code/>
