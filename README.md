## 📖 概述

**Reflective** 是一个 **反射式 DLL** 注入技术的实现库，使用纯 C 编写。与传统的 LoadLibrary 注入不同，反射式注入
不需要目标进程中存在 `LoadLibrary` 调用——DLL 通过一个内置的 **ReflectiveLoader** 函数自行将自己加载到进程中，完
全绕过 Windows 的加载器。

> ⚠️ **免责声明：** 本工具仅用于**授权的安全测试、教育培训和逆向工程研究**。未经授权使用此工具攻击他人系统是违
法的。

## 🔬 技术原理

传统 DLL 注入依赖 `CreateRemoteThread` + `LoadLibrary`，但这种方式会在目标进程中留下明显的调用痕迹。反射式注入
的核心思路是：**让 DLL 自己把自己加载进内存**。

### 工作流程

```
┌─────────────────────────────────────────────────────────────┐
│ ① 注入器将 DLL 原始字节写入目标进程（VirtualAllocEx +         │
│    WriteProcessMemory），然后通过 Crea
│    执行 ReflectiveLoader                                       │
├───────────────────────────────────────
│ ② ReflectiveLoader 反向扫描自身内存找到 PE 头 (MZ)            │
├─────────────────────────────────────────────────────────────┤
│ ③ 通过 PEB (Process Environment Block) 找到 kernel32.dll    │
│    在目标进程中的基址                                        │
├───────────────────────────────────────
│ ④ 手动解析 kernel32 的导出表，获取 LoadLibraryA、            │
│    GetProcAddress、VirtualAlloc 的函数地址                     │
├───────────────────────────────────────
│ ⑤ VirtualAlloc 分配新内存 → 复制 PE 头和节区                    │
├─────────────────────────────────────────────────────────────┤
│ ⑥ 修复重定位表（如果实际加载地址 ≠ 首
├─────────────────────────────────────────────────────────────┤
│ ⑦ 解析导入表，调用 LoadLibraryA 加载依
├─────────────────────────────────────────────────────────────┤
│ ⑧ 调用 DLL 入口点 (DllMain)                                   │
└─────────────────────────────────────────────────────────────┘
```

### 关键特性

- **无 LoadLibrary 调用** — 不从外部调用 `LoadLibrary` 加载自身，避免 API 监控
- **PEB 遍历** — 通过进程环境块手动定位
- **手动导出解析** — 不使用 `GetProcAddress` 获取自身函数，而是直接解析 PE 导出表
- **字符串堆栈化** — API 名称以字符数组形式存储在栈上，避免 PE 文件中出现明文字符串
- **完整重定位修复** — 支持 IMAGE_REL_BA
- **完整导入表修复** — 自动解析并填充 IAT

## 📁 项目结构

```
Reflective/
├── Reflective.c              # 核心源文
├── dllmain.cpp               # DLL 入口点（可选，本项目中 Reflective.c 自带 DllMain）
├── Header.h                  # LDR_DATA_TABLE_ENTRY、PEB 等自定义结构体定义
├── framework.h               # Windows
├── Reflective.sln            # Visual Studio 解决方案文件
├── Reflective.vcxproj        # Visual Studio 项目文件
├── Reflective.vcxproj.filters # 项目筛
├── .gitignore                # Git 忽略规则
└── README.md                 # 本文件
```

## 🚀 构建

使用 Visual Studio 2022 打开 `Reflective.sln`，选择 **Release | x64** 配置编译。

### 关键编译选项

| 选项 | 值 | 说明 |
|------|-----|------|
| 配置类型 | 动态库 (.dll) | 输出为 DLL |
| 字符集 | Unicode | — |
| 安全检查 (Release) | 禁用 (`/GS-`) | 避免 GS cookie 破坏反射加载 |
| 固定基址 (Release) | 否 (`/DYNAMICBASE:NO`) | 允许重定位 |
| 全程序优化 (Release) | 禁用 | 防止编译
| 运行时库 (Release) | 多线程 (`/MT`) | 静态链接 CRT，减少依赖 |

## 📦 核心 API
| 安全检查 (Release) | 禁用 (`/GS-`) | 避免 GS cookie 破坏反射加载 |
| 固定基址 (Release) | 否 (`/DYNAMICBASE:NO`) | 允许重定位 |
| 全程序优化 (Release) | 禁用 | 防止编译
| 运行时库 (Release) | 多线程 (`/MT`) | 静态链接 CRT，减少依赖 |

## 📦 核心 API

### `ReflectiveLoader`

```c
__declspec(dllexport) ULONG_PTR WINAPI ReflectiveLoader(LPVOID lpParameter);
```

反射加载器的入口点。注入器通过 `CreateRemoteThread` 以该函数为起始地址启动线程，DLL 将自行完成加载。

- **参数：** `lpParameter` — 未使用（可传 NULL）
- **返回值：** DLL 在目标进程中加载后的基址（`uiNewBase`）

### `DllMain`

```c
BOOL APIENTRY DllMain(HMODULE hModule, DWORD reason, LPVOID lpReserved);
```

DLL 入口点。当 `ReflectiveLoader` 完成加载后，会自动调用此函数，`reason` 为 `DLL_PROCESS_ATTACH`。

## ⚙️ 与注入器配合使用

```c
// 伪代码：注入器侧
HANDLE hProcess = OpenProcess(PROCESS_ALL_ACCESS, FALSE, pid);
LPVOID pRemoteBuf = VirtualAllocEx(hProcess, NULL, dllSize, MEM_COMMIT, PAGE_EXECUTE_READWRITE);
WriteProcessMemory(hProcess, pRemoteBuf, dllBytes, dllSize, NULL);

// 计算 ReflectiveLoader 在远程内存中的
ULONG_PTR pLoadFunc = (ULONG_PTR)pRemoteBuf + offset_of_ReflectiveLoader;
CreateRemoteThread(hProcess, NULL, 0, (LPTHREAD_START_ROUTINE)pLoadFunc, NULL, 0, NULL);
```

## 📝 注意事项

1. **编译配置至关重要：** 必须关闭安全检查 (`/GS-`) 和全程序优化，否则 `ReflectiveLoader` 可能因 GS cookie、函
数内联等导致定位失败或崩溃。
2. **Hardcode 字符串：** `LoadLibraryA`、`GetProcAddress`、`VirtualAlloc` 和 `kernel32.dll` 均以栈上字符数组形
式硬编码，避免 PE 文件中出现可被扫描的明文字符串。
3. **位数匹配：** x64 的 DLL 只能注入 x6
4. **依赖解析：** 反射加载的 DLL 如果依赖其他 DLL，需要通过导入表正常加载这些依赖——`ReflectiveLoader` 会调用 `L
oadLibraryA` 加载它们。

## 🔗 关联项目

- [APCInjection_2](https://github.com/Sayb1e/APCInjection_2) — 基于 APC 的 DLL 注入工具

## 📜 许可证

本项目仅供学习研究使用。
