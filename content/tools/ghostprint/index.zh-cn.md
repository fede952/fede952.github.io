---
title: "GhostPrint：浏览器指纹检测 —— 你有多容易被追踪？"
description: "看看你的浏览器悄悄交给每个网站的隐形指纹 —— GPU、canvas、字体、音频等 —— 并获得唯一性评分。100% 在浏览器中运行，绝不上传任何内容。"
date: 2026-07-06
tags: ["privacy", "security", "developer-tools", "fingerprinting"]
keywords: ["浏览器指纹检测", "我是否唯一", "设备指纹", "canvas 指纹", "我有多容易被追踪", "浏览器指纹识别", "webgl 指纹", "音频指纹", "在线隐私测试", "反追踪测试"]
layout: "tool"
draft: false
tool_file: "/tools/ghostprint/"
tool_height: "2200"
schema_json: >
  {"@context": "https://schema.org", "@type": "SoftwareApplication", "name": "GhostPrint —— 浏览器指纹检测", "description": "免费的客户端浏览器指纹检测，根据 GPU、canvas、音频、字体等评估你的浏览器有多独特、多容易被追踪。", "applicationCategory": "SecurityApplication", "operatingSystem": "Web", "browserRequirements": "Requires JavaScript", "isAccessibleForFree": true, "offers": {"@type": "Offer", "price": "0", "priceCurrency": "USD"}}
---

## 为什么指纹比 Cookie 更难摆脱

Cookie 很容易屏蔽，但你的**浏览器指纹**不行。你的设备、GPU、字体、屏幕和设置的组合方式，构成了一个跨网站跟随你的标识符 —— 而且它**能挺过无痕模式、清除的 Cookie 以及大多数「隐私」浏览。** GhostPrint 在几秒内向你展示你的指纹，附带唯一性评分和每一个泄露信号的详细分解。

真正说明问题的一点是：下面的每个信号都在**你的浏览器内**读取，并**不发送到任何地方** —— 没有上传、没有日志、没有服务器。但你访问的任何网站都能在不征求许可的情况下静默读取这些相同的值，广告和反欺诈网络正是这么做的。刷新页面你的数据就消失了 —— 而追踪者不会给你那个按钮。

## GhostPrint 读取哪些内容

- **硬件与 GPU** —— 你的显卡（通过 WebGL）、CPU 核心数、内存和屏幕参数
- **渲染指纹** —— canvas 与音频哈希：你系统独有的像素级和采样级细微差异
- **环境** —— 已安装字体、时区、语言、平台和显示偏好
- **隐私信号** —— Cookie、Do-Not-Track 和 Global Privacy Control 状态

## 如何淡化这个「幽灵」

- **Tor 浏览器**是黄金标准 —— 每个用户都被刻意做得彼此相同。
- **Firefox** 提供 `privacy.resistFingerprinting`；**Brave** 默认对 canvas 和音频进行随机化。
- 反指纹扩展和禁用 WebGL 会有帮助 —— 而且违反直觉的是，奇特的硬件和罕见字体会让你*更*容易被识别，而非更难。

运行上方的扫描获取你的唯一性评分，然后下载可分享的卡片，比较你的其他浏览器。
