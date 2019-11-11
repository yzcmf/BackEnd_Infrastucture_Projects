<p align = "center">
<img alt="BND" width="128" src="https://raw.githubusercontent.com/b3log/baidu-netdisk-downloaderx/master/bnd2/react/public/logo.png">
<br><br>
一款图形界面的百度网盘不限速下载器，支持 Windows、Linux 和 Mac
<br><br>
<a title="Hits" target="_blank" href="https://github.com/b3log/hits"><img src="https://hits.b3log.org/b3log/baidu-netdisk-downloaderx.svg"></a>
<a title="Code Size" target="_blank" href="https://github.com/b3log/baidu-netdisk-downloaderx"><img src="https://img.shields.io/github/languages/code-size/b3log/baidu-netdisk-downloaderx.svg?style=flat-square&color=6699FF"></a>
<a title="GPLv3" target="_blank" href="https://github.com/b3log/baidu-netdisk-downloaderx/blob/master/LICENSE"><img src="https://img.shields.io/badge/license-GPLv3-orange.svg?style=flat-square"></a>
<br>
<a title="GitHub Commits" target="_blank" href="https://github.com/b3log/baidu-netdisk-downloaderx/commits/master"><img src="https://img.shields.io/github/commit-activity/m/b3log/baidu-netdisk-downloaderx.svg?style=flat-square"></a>
<a title="Last Commit" target="_blank" href="https://github.com/b3log/baidu-netdisk-downloaderx/commits/master"><img src="https://img.shields.io/github/last-commit/b3log/baidu-netdisk-downloaderx.svg?style=flat-square&color=FF9900"></a>
<a title="GitHub Pull Requests" target="_blank" href="https://github.com/b3log/baidu-netdisk-downloaderx/pulls"><img src="https://img.shields.io/github/issues-pr-closed/b3log/baidu-netdisk-downloaderx.svg?style=flat-square&color=FF9966"></a>
<br>
<a title="Releases" target="_blank" href="https://github.com/b3log/baidu-netdisk-downloaderx/releases"><img src="https://img.shields.io/github/release/b3log/baidu-netdisk-downloaderx.svg?style=flat-square&color=CC6666"></a>
<a title="Release Date" target="_blank" href="https://github.com/b3log/baidu-netdisk-downloaderx/releases"><img src="https://img.shields.io/github/release-date/b3log/baidu-netdisk-downloaderx.svg?style=flat-square&color=99CCFF"></a>
<a title="Downloads" target="_blank" href="https://github.com/b3log/baidu-netdisk-downloaderx/releases"><img src="https://img.shields.io/github/downloads/b3log/baidu-netdisk-downloaderx/total.svg?style=flat-square&color=99CC99"></a>
<br><br>
<a title="GitHub Watchers" target="_blank" href="https://github.com/b3log/baidu-netdisk-downloaderx/watchers"><img src="https://img.shields.io/github/watchers/b3log/baidu-netdisk-downloaderx.svg?label=Watchers&style=social"></a>&nbsp;&nbsp;
<a title="GitHub Stars" target="_blank" href="https://github.com/b3log/baidu-netdisk-downloaderx/stargazers"><img src="https://img.shields.io/github/stars/b3log/baidu-netdisk-downloaderx.svg?label=Stars&style=social"></a>&nbsp;&nbsp;
<a title="GitHub Forks" target="_blank" href="https://github.com/b3log/baidu-netdisk-downloaderx/network/members"><img src="https://img.shields.io/github/forks/b3log/baidu-netdisk-downloaderx.svg?label=Forks&style=social"></a>&nbsp;&nbsp;
<a title="Author GitHub Followers" target="_blank" href="https://github.com/88250"><img src="https://img.shields.io/github/followers/88250.svg?label=Followers&style=social"></a>

## 💡 简介

[BND](https://github.com/b3log/baidu-netdisk-downloaderx) 是一款图形界面的百度网盘不限速下载器，支持 Windows、Linux 和 Mac，下载请看[这里](https://hacpai.com/article/1563154719934)。

BND 分为两个系列，BND1 和 BND2，下面分别进行介绍。

## ⚡ BND1

[又一个百度网盘不限速下载器 BND](https://hacpai.com/article/1524460877352)

* 小巧省资源
* 支持 Windows、Linux 和 Mac

![bnd1-windows](https://user-images.githubusercontent.com/970828/61263783-cad29780-a7bc-11e9-8920-329035fa8de0.png)

![bnd1-linux](https://user-images.githubusercontent.com/970828/61263781-ca3a0100-a7bc-11e9-8dd5-0a7fa6fe36da.png)

![bnd1-mac](https://user-images.githubusercontent.com/970828/61263782-cad29780-a7bc-11e9-880a-b05dbeb423bf.png)

### 代码

本项目是基于 [BaiduPCS-Go](https://github.com/iikira/BaiduPCS-Go) 开发：

* 在其基础上增加了 UI 界面，主要修改点是 pcscommand 包
* Windows 版引入了 Aria2，下载超过 512M 文件时会切换到 Aria2

### 编译

1. 安装 golang 环境
2. 项目目录 $GOPATH/src/github.com/b3log/bnd （不支持 Go Modules）
3. 参考[这里](https://github.com/andlabs/libui)编译 UI 库
4. 不支持交叉编译，只能在目标平台上编译
5. Windows 执行 build.bat，Linux/Mac 执行 build.sh

### 其他

* aria2 原有设计是在启动后检查版本并远程拉取的，现已改为本地打包
* 保留了版本检查机制，可搜索 rhythm.b3log.org 进行相关修改
* 和服务端交互时用于加密请求响应数据的密钥已在源码中公开

## ⚡ BND2

[百度不限速下载器 BND2 技术架构简介](https://hacpai.com/article/1535277215816)

* 界面美观，操作便捷
* 支持多任务并发下载
* 仅支持 Windows 和 Mac

![bnd2](https://user-images.githubusercontent.com/970828/61263780-ca3a0100-a7bc-11e9-9ef5-8742f20e94c5.png)

### 编译

1. 安装 golang、node 环境
2. Windows 执行 build.bat，Mac 执行 build.sh
3. `electron/dist` 目录下运行可执行文件进行安装

### 其他

* 内核可执行文件以及 aria2 原有设计是在启动后检查版本并远程拉取的，现已改为本地打包
* 保留了版本检查机制，可搜索 rhythm.b3log.org 进行相关修改
* 和服务端交互时用于加密请求响应数据的密钥已在源码中公开

## 🏘️ 社区

BND 项目的主要贡献者来自于 B3log 开源社区，欢迎大家对 BND 的开发、测试、反馈、推广等贡献自己的一份力量。

* [讨论区](https://hacpai.com/tag/bnd)
* [报告问题](https://github.com/b3log/baidu-netdisk-downloaderx/issues/new/choose)
* [B3log 开源社区欢迎大家加入！](https://hacpai.com/article/1463025124998)

## 📄 授权

BND 使用 [GPLv3](https://www.gnu.org/licenses/gpl-3.0.txt) 开源协议。

## 🙏 鸣谢

* [aria2](https://github.com/aria2/aria2)：超高速的下载引擎
* [BaiduPCS-Go](https://github.com/iikira/BaiduPCS-Go)：百度网盘客户端 - Go 语言编写
* [andlabs/ui](https://github.com/andlabs/ui)：跨平台的 Go GUI 库
* [Gulu](https://github.com/b3log/gulu)：Go 语言常用工具库，这个轱辘还算圆！
* [React](https://github.com/facebook/react)：使用 JS 构建用户界面库
* [Electron](https://github.com/electron/electron)：使用 JS、HTML、CSS 的跨平台桌面应用库

---

## 👍 开源项目推荐

* [前端精选问题集，每天仅需 30 秒](https://github.com/b3log/30-seconds-zh_CN)
* 如果你需要搭建一个个人博客系统，可以考虑使用 [Solo](https://github.com/b3log/solo)
* 如果你需要搭建一个多用户博客平台，可以考虑使用 [Pipe](https://github.com/b3log/pipe)
* 如果你需要搭建一个社区平台，可以考虑使用 [Sym](https://github.com/b3log/symphony)
* 欢迎加入我们的小众开源社区，详情请看[这里](https://hacpai.com/article/1463025124998)
