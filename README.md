# Reflective DLL Injection

Windows 反射型 DLL 注入研究与实现。  
核心思路：将 DLL 以内存形式写入目标进程，手动完成 PE 加载（修复 IAT、重定位等），无需调用 `LoadLibrary`。

## 项目结构

Reflective/

├── Reflective.c          # 核心反射加载器：手动 PE 映射

├── Header.h              # PE 结构定义与函数原型

├── dllmain.cpp           # DLL 入口

├── framework.h           # 预编译头依赖

├── Reflective.sln        # Visual Studio 解决方案

└── .gitignore            # 忽略编译产物

## 技术要点

- 手动解析 PE 头（DOS / NT Headers / Section Headers）
- 内存映像分配与节区映射
- 导入地址表（IAT）修复
- 基址重定位（Base Relocation）处理
- 反射式加载，不依赖系统 `LoadLibrary`

## 编译环境

- Visual Studio 2022
- Windows SDK 10.0+
- 目标平台：x64

## Roadmap

- [ ] Injector：远程进程注入器（CreateRemoteThread / APC）
- [ ] x86 支持
- [ ] 详细技术文档

## 参考

- [Stephen Fewer/ReflectiveDLLInjection](https://github.com/stephenfewer/ReflectiveDLLInjection)
- [Blog: sayble.xyz](http://sayble.xyz)

## Disclaimer

本项目仅供安全技术研究与学习，禁止用于任何未经授权的渗透测试或恶意活动。
