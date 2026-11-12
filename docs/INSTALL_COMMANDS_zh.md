# 安装命令

Claude Code 插件路线与手动克隆/构建的完整命令。方法一与方法三较短，留在 README：[umbra-sentry](../README_zh.md) · [English](INSTALL_COMMANDS.md)

## 方法二：用命令安装

**Claude Code** —— 在终端执行（v2.1.292+），一步完成注册与安装：

```bash
claude plugin install umbra-sentry --marketplace https://github.com/JiamingShi-JsPhys/umbra-sentry.git
```

**Claude Code** —— 在会话内执行（v2.1.275+），先用 URL 添加市场，并锁定发布 tag：

```text
/plugin marketplace add https://github.com/JiamingShi-JsPhys/umbra-sentry.git#v1.0.0
```

再安装它列出的条目：

```text
/plugin install umbra-sentry@umbra-sentry-marketplace
```

**手动克隆** —— 插件提供 `harden` 技能；流水线本身是一个 Python 包。从克隆的仓库安装：

```bash
git clone https://github.com/JiamingShi-JsPhys/umbra-sentry.git
cd umbra-sentry
python -m pip install -e .
```

原生内核是可选的：

```bash
cd defense/native/umbra-native && cargo build --release && cd ../../..
```

不构建时，`native-poison` 与 `native-exhaust` 会发出带审计的 `SKIPPED` 事件，并保持编译产物不变。

## 环境要求

- Python 3.12+。
- Pydantic 2.7+ 与 PyYAML 6.0+（`pip install -e .` 会安装）。
- Rust stable，可选，仅原生内核需要。

## 该选哪条路线？

| 路线 | 得到什么 | 需要什么 |
| --- | --- | --- |
| 插件 + 克隆 | `harden` 技能与 CLI | Python 包；原生内核另需 Rust |
| 只装插件 | 技能面，但不是可用的 CLI | 克隆后 `pip install -e .` |
| 手动克隆 | CLI 与 Python API，没有插件技能 | Python 包 |
