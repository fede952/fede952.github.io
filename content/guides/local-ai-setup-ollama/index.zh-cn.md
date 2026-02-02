---
title: "别再为 AI 付费了：免费在本地运行 DeepSeek 和 Llama 3"
date: 2026-02-02
description: "了解如何使用 Ollama 在自己的电脑上免费运行 DeepSeek 和 Llama 3 等强大 AI 模型。完全隐私、零月费、离线可用。"
tags: ["AI", "Ollama", "Privacy", "Tutorial", "LocalLLM"]
categories: ["Guides", "Artificial Intelligence"]
author: "Federico Sella"
draft: false
---

你不需要每月花 20 美元的订阅费来使用强大的 AI 助手。借助一个名为 **Ollama** 的免费开源工具，你可以直接在自己的电脑上运行最先进的大语言模型——包括 **Meta 的 Llama 3** 和 **DeepSeek-R1**。没有云端、没有账号、数据永远不会离开你的机器。

本指南将在 10 分钟内带你完成整个安装。

## 为什么要在本地运行 AI？

### 完全隐私

当你使用云端 AI 服务时，你输入的每一个提示都会被发送到远程服务器。这包括代码片段、商业创意、个人问题——一切。使用**本地 LLM**，你的对话留在你的硬件上。就是这样。

### 零月费

ChatGPT Plus 每月 20 美元。Claude Pro 每月 20 美元。GitHub Copilot 每月 10 美元。本地模型在初始下载后**完全免费**。这些模型都是开源的，可以免费使用。

### 离线可用

在飞机上？在没有 Wi-Fi 的小屋里？没关系。本地模型完全在你的 CPU 和内存上运行——不需要互联网连接。

---

## 前提条件

你不需要 GPU 或高端工作站。以下是最低要求：

- **操作系统：** Windows 10/11、macOS 12+ 或 Linux
- **内存：** 最低 8 GB（较大模型建议 16 GB）
- **磁盘空间：** 约 5 GB 可用空间（用于应用程序和一个模型）
- **可选：** 独立显卡（NVIDIA/AMD）可以加速推理，但**不是必需的**

---

## 第一步：下载并安装 Ollama

**Ollama** 是一个轻量级运行时，可以用一条命令下载、管理和运行大语言模型。在每个平台上安装都很简单。

### Windows

1. 访问 [ollama.com](https://ollama.com) 并点击 **Download for Windows**。
2. 运行安装程序——大约需要一分钟。
3. 安装后 Ollama 会自动在后台运行。

### macOS

你有两个选择：

```bash
# 选项 A：Homebrew（推荐）
brew install ollama

# 选项 B：直接下载
# 访问 https://ollama.com 下载 .dmg 文件
```

### Linux

一条命令搞定一切：

```bash
curl -fsSL https://ollama.com/install.sh | sh
```

安装后，验证是否正常工作：

```bash
ollama --version
```

你应该能在终端看到一个版本号。

---

## 第二步：运行你的第一个模型——神奇的命令

就是现在。打开终端，输入：

```bash
ollama run llama3
```

就是这样。Ollama 会在首次运行时下载 **Llama 3 8B** 模型（约 4.7 GB），然后直接在终端中进入交互式聊天会话：

```
>>> 你是谁？
我是 Llama，一个由 Meta 训练的大语言模型。今天有什么可以帮你的？

>>> 写一个 Python 函数来检查一个数是否是质数。
def is_prime(n):
    if n < 2:
        return False
    for i in range(2, int(n**0.5) + 1):
        if n % i == 0:
            return False
    return True
```

### 试试 DeepSeek-R1 处理推理任务

**DeepSeek-R1** 擅长数学、逻辑和逐步问题求解：

```bash
ollama run deepseek-r1
```

### 其他热门模型

| 模型 | 命令 | 最适合 |
|---|---|---|
| Llama 3 8B | `ollama run llama3` | 通用聊天、编程 |
| DeepSeek-R1 8B | `ollama run deepseek-r1` | 数学、逻辑、推理 |
| Mistral 7B | `ollama run mistral` | 快速高效的全能型 |
| Gemma 2 9B | `ollama run gemma2` | Google 的开源模型 |
| Qwen 2.5 7B | `ollama run qwen2.5` | 多语言任务 |

运行 `ollama list` 查看已下载的模型，`ollama rm <模型名>` 删除模型并释放磁盘空间。

---

## 第三步：使用 Open WebUI 添加聊天界面（可选）

终端可以工作，但如果你想要一个精美的 **ChatGPT 风格界面**，请安装 **Open WebUI**。最快的方法是使用 Docker：

```bash
docker run -d -p 3000:8080 --add-host=host.docker.internal:host-gateway \
  -v open-webui:/app/backend/data --name open-webui \
  --restart always ghcr.io/open-webui/open-webui:main
```

然后在浏览器中打开 [http://localhost:3000](http://localhost:3000)。你将获得一个熟悉的聊天界面，带有对话历史、模型切换、文件上传等功能——全部连接到你的本地 Ollama 实例。

> **没有 Docker？** 还有其他轻量级前端，如 [Chatbox](https://chatboxai.app)（桌面应用）或 [Ollama Web UI](https://github.com/ollama-webui/ollama-webui)，不需要 Docker。

---

## 本地 AI vs. 云端 AI：全面对比

| 特性 | 本地 AI（Ollama） | 云端 AI（ChatGPT、Claude） |
|---|---|---|
| **隐私** | 你的数据永远不会离开你的电脑 | 数据发送到远程服务器 |
| **费用** | 完全免费 | 高级版每月 20 美元 |
| **需要互联网** | 不需要——完全离线工作 | 需要——始终 |
| **速度** | 取决于你的硬件 | 快速（服务器端 GPU） |
| **模型质量** | 优秀（Llama 3、DeepSeek） | 优秀（GPT-4o、Claude） |
| **安装难度** | 一条命令 | 创建账号 |
| **可定制性** | 完全控制，可微调 | 有限 |
| **数据保留** | 你完全控制 | 适用提供商的政策 |

**总结：** 云端模型在最大型任务的原始能力上仍有优势，但对于日常编程辅助、写作、头脑风暴和问答，本地模型**绰绰有余**——而且免费且私密。

---

## 结语

运行本地 AI 不再是拥有昂贵 GPU 的研究人员的小众爱好。得益于 **Ollama** 和开源模型生态系统，任何拥有现代笔记本电脑的人都可以在 10 分钟内拥有一个私密、免费、可离线使用的 AI 助手。

需要记住的命令：

```bash
# 安装（Linux）
curl -fsSL https://ollama.com/install.sh | sh

# 运行模型
ollama run llama3

# 列出你的模型
ollama list
```

试试看。一旦你体验了本地 LLM 的速度和隐私，你可能会发现自己越来越少依赖云端。

> 在使用本地 AI 编程时需要保持专注？试试我们的 [ZenFocus 环境音混音器和番茄钟计时器](/zh-cn/tools/zen-focus/)——另一个完全在浏览器中运行、零追踪的工具。
