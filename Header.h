#pragma once
#include <windows.h>

// ------------------------------------------------------------
// 自定义必需的内部结构（不用 winternl.h）
// ------------------------------------------------------------
typedef struct _UNICODE_STR {
    USHORT Length;
    USHORT MaximumLength;
    PWSTR  Buffer;
} UNICODE_STR, * PUNICODE_STR;

typedef struct _LDR_DATA_TABLE_ENTRY {
    LIST_ENTRY InLoadOrderLinks;
    LIST_ENTRY InMemoryOrderLinks;
    LIST_ENTRY InInitializationOrderLinks;
    PVOID      DllBase;        // 模块基址
    PVOID      EntryPoint;
    ULONG      SizeOfImage;
    UNICODE_STR FullDllName;
    UNICODE_STR BaseDllName;   // 模块名（如 kernel32.dll）
    // 后续字段省略，因为我们只用到这里
} LDR_DATA_TABLE_ENTRY, * PLDR_DATA_TABLE_ENTRY;

typedef struct _PEB_LDR_DATA {
    ULONG      Length;
    BOOLEAN    Initialized;
    PVOID      SsHandle;
    LIST_ENTRY InLoadOrderModuleList;
    LIST_ENTRY InMemoryOrderModuleList;   // 我们遍历的链表
    LIST_ENTRY InInitializationOrderModuleList;
} PEB_LDR_DATA, * PPEB_LDR_DATA;

// PEB 结构，只定义到 Ldr 字段，后续全部省略
typedef struct _PEB {
    BYTE           Reserved1[2];
    BYTE           BeingDebugged;
    BYTE           Reserved2[1];
    PVOID          Reserved3[2];
    PPEB_LDR_DATA  Ldr;          // 指向 PEB_LDR_DATA 的指针
} PEB, * PPEB; 
