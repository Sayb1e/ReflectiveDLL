#include <windows.h>
#include <winternl.h>

// ========== 辅助函数 ==========

// 从完整路径中提取文件名（例如 "\Windows\System32\kernel32.dll" → "kernel32.dll"）
wchar_t* ExtractDllName(const wchar_t* fullDllName) {
    wchar_t* fileName = NULL;
    wchar_t* temp = (wchar_t*)fullDllName;
    while (*temp) {
        if (*temp == L'\\') fileName = temp + 1;
        temp++;
    }
    if (!fileName) fileName = (wchar_t*)fullDllName;
    return fileName;
}

// 不区分大小写的宽字符串比较
BOOL MyCompareStringW(const wchar_t* str1, const wchar_t* str2) {
    if (!str1 || !str2) return FALSE;
    while (*str1 && *str2) {
        wchar_t c1 = (*str1 >= L'A' && *str1 <= L'Z') ? (*str1 + 32) : *str1;
        wchar_t c2 = (*str2 >= L'A' && *str2 <= L'Z') ? (*str2 + 32) : *str2;
        if (c1 != c2) return FALSE;
        str1++; str2++;
    }
    return (*str1 == L'\0' && *str2 == L'\0');
}

// ASCII 字符串比较（严格相等）
BOOL StrCmpA(const char* a, const char* b) {
    while (*a && *b) { if (*a != *b) return FALSE; a++; b++; }
    return (*a == '\0' && *b == '\0');
}

// 提供 memset（ReflectiveLoader 内部使用）
#pragma function(memset)
void* __cdecl memset(void* dest, int val, size_t size) {
    unsigned char* p = (unsigned char*)dest;
    while (size--) *p++ = (unsigned char)val;
    return dest;
}

// ========== DllMain ==========
BOOL APIENTRY DllMain(HMODULE hModule, DWORD reason, LPVOID lpReserved) {
    if (reason == DLL_PROCESS_ATTACH) {
        MessageBoxA(NULL, "DllMain called!", "Reflective Injected", MB_OK);
    }
    return TRUE;
}

// ========== ReflectiveLoader ==========
__declspec(dllexport) ULONG_PTR WINAPI ReflectiveLoader(LPVOID lpParameter) {
    // 1. 获取自身基址（暴力扫描 MZ）
    ULONG_PTR uiBase = (ULONG_PTR)ReflectiveLoader;
    PIMAGE_NT_HEADERS pNtHeader = NULL;
    while (TRUE) {
        PIMAGE_DOS_HEADER pDos = (PIMAGE_DOS_HEADER)uiBase;
        if (pDos->e_magic == IMAGE_DOS_SIGNATURE) {
            ULONG_PTR lfanew = pDos->e_lfanew;
            if (lfanew >= sizeof(IMAGE_DOS_HEADER) && lfanew < 1024) {
                pNtHeader = (PIMAGE_NT_HEADERS)(uiBase + lfanew);
                if (pNtHeader->Signature == IMAGE_NT_SIGNATURE) break;
            }
        }
        uiBase--;
    }
    if (!uiBase) return 0;

    // 保存原始 ImageBase
    ULONG_PTR uiOldImageBase = pNtHeader->OptionalHeader.ImageBase;

    // 2. 通过 PEB 找到 kernel32.dll 基址（使用 FullDllName + 提取文件名）
    PPEB pPeb = (PPEB)__readgsqword(0x60);
    PPEB_LDR_DATA pLdr = pPeb->Ldr;
    PLIST_ENTRY pHead = &pLdr->InMemoryOrderModuleList;
    PLIST_ENTRY pEntry = pHead->Flink;
    HMODULE hKernel32 = NULL;

    // 目标字符串定义在栈上，不受重定位影响
    wchar_t targetKernel32[] = { L'k','e','r','n','e','l','3','2','.',L'd','l','l', L'\0' };

    while (pEntry != pHead) {
        PLDR_DATA_TABLE_ENTRY pMod = CONTAINING_RECORD(pEntry, LDR_DATA_TABLE_ENTRY, InMemoryOrderLinks);
        if (pMod->DllBase && pMod->FullDllName.Buffer) {
            wchar_t* dllName = ExtractDllName(pMod->FullDllName.Buffer);
            if (MyCompareStringW(dllName, targetKernel32)) {
                hKernel32 = (HMODULE)pMod->DllBase;
                break;
            }
        }
        pEntry = pEntry->Flink;
    }
    if (!hKernel32) return 0;

    // 3. 解析 kernel32 导出表，获取 LoadLibraryA、GetProcAddress、VirtualAlloc
    typedef FARPROC(WINAPI* fnGetProcAddress)(HMODULE, LPCSTR);
    typedef HMODULE(WINAPI* fnLoadLibraryA)(LPCSTR);
    typedef LPVOID(WINAPI* fnVirtualAlloc)(LPVOID, SIZE_T, DWORD, DWORD);

    // API 名称同样定义在栈上
    CHAR loadLibraryA_name[] = { 'L','o','a','d','L','i','b','r','a','r','y','A','\0' };
    CHAR getProcAddress_name[] = { 'G','e','t','P','r','o','c','A','d','d','r','e','s','s','\0' };
    CHAR virtualAlloc_name[] = { 'V','i','r','t','u','a','l','A','l','l','o','c','\0' };

    PIMAGE_DOS_HEADER pKDos = (PIMAGE_DOS_HEADER)hKernel32;
    PIMAGE_NT_HEADERS pKNt = (PIMAGE_NT_HEADERS)((ULONG_PTR)hKernel32 + pKDos->e_lfanew);
    PIMAGE_EXPORT_DIRECTORY pExport = (PIMAGE_EXPORT_DIRECTORY)(
        (ULONG_PTR)hKernel32 + pKNt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress);

    DWORD* pFuncs = (DWORD*)((ULONG_PTR)hKernel32 + pExport->AddressOfFunctions);
    DWORD* pNames = (DWORD*)((ULONG_PTR)hKernel32 + pExport->AddressOfNames);
    WORD* pOrds = (WORD*)((ULONG_PTR)hKernel32 + pExport->AddressOfNameOrdinals);

    fnLoadLibraryA   pLoadLibraryA = NULL;
    fnGetProcAddress pGetProcAddress = NULL;
    fnVirtualAlloc   pVirtualAlloc = NULL;

    for (DWORD i = 0; i < pExport->NumberOfNames; i++) {
        char* funcName = (char*)((ULONG_PTR)hKernel32 + pNames[i]);
        if (StrCmpA(funcName, loadLibraryA_name))
            pLoadLibraryA = (fnLoadLibraryA)((ULONG_PTR)hKernel32 + pFuncs[pOrds[i]]);
        else if (StrCmpA(funcName, getProcAddress_name))
            pGetProcAddress = (fnGetProcAddress)((ULONG_PTR)hKernel32 + pFuncs[pOrds[i]]);
        else if (StrCmpA(funcName, virtualAlloc_name))
            pVirtualAlloc = (fnVirtualAlloc)((ULONG_PTR)hKernel32 + pFuncs[pOrds[i]]);
    }

    if (!pLoadLibraryA || !pGetProcAddress || !pVirtualAlloc) return 0;

    // 4. 分配新内存
    ULONG_PTR uiNewBase = (ULONG_PTR)pVirtualAlloc(NULL, pNtHeader->OptionalHeader.SizeOfImage,
        MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
    if (!uiNewBase) return 0;

    // 5. 复制 PE 头和节区
    for (DWORD i = 0; i < pNtHeader->OptionalHeader.SizeOfHeaders; i++)
        *((BYTE*)uiNewBase + i) = *((BYTE*)uiBase + i);

    PIMAGE_SECTION_HEADER pSec = IMAGE_FIRST_SECTION(pNtHeader);
    for (WORD i = 0; i < pNtHeader->FileHeader.NumberOfSections; i++) {
        if (pSec[i].SizeOfRawData > 0) {
            BYTE* src = (BYTE*)(uiBase + pSec[i].PointerToRawData);
            BYTE* dst = (BYTE*)(uiNewBase + pSec[i].VirtualAddress);
            for (DWORD j = 0; j < pSec[i].SizeOfRawData; j++) dst[j] = src[j];
        }
        if (pSec[i].Misc.VirtualSize > pSec[i].SizeOfRawData) {
            BYTE* dst = (BYTE*)(uiNewBase + pSec[i].VirtualAddress);
            DWORD extra = pSec[i].Misc.VirtualSize - pSec[i].SizeOfRawData;
            for (DWORD j = 0; j < extra; j++) dst[pSec[i].SizeOfRawData + j] = 0;
        }
    }

    // 6. 基址重定位
    ULONG_PTR delta = uiNewBase - uiOldImageBase;
    if (delta != 0) {
        PIMAGE_DATA_DIRECTORY pRelocDir = &pNtHeader->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC];
        if (pRelocDir->Size > 0) {
            PIMAGE_BASE_RELOCATION pBlock = (PIMAGE_BASE_RELOCATION)(uiNewBase + pRelocDir->VirtualAddress);
            while (pBlock->VirtualAddress) {
                DWORD count = (pBlock->SizeOfBlock - sizeof(IMAGE_BASE_RELOCATION)) / sizeof(WORD);
                WORD* items = (WORD*)((ULONG_PTR)pBlock + sizeof(IMAGE_BASE_RELOCATION));
                for (DWORD i = 0; i < count; i++) {
                    if ((items[i] >> 12) == IMAGE_REL_BASED_DIR64) {
                        ULONG_PTR* patch = (ULONG_PTR*)(uiNewBase + pBlock->VirtualAddress + (items[i] & 0xFFF));
                        *patch += delta;
                    }
                }
                pBlock = (PIMAGE_BASE_RELOCATION)((ULONG_PTR)pBlock + pBlock->SizeOfBlock);
            }
        }
    }

    // 7. 导入表修复
    PIMAGE_DATA_DIRECTORY pImportDir = &pNtHeader->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT];
    if (pImportDir->Size > 0) {
        PIMAGE_IMPORT_DESCRIPTOR pImp = (PIMAGE_IMPORT_DESCRIPTOR)(uiNewBase + pImportDir->VirtualAddress);
        while (pImp->Name) {
            char* dllName = (char*)(uiNewBase + pImp->Name);
            HMODULE hMod = pLoadLibraryA(dllName);
            if (hMod) {
                PIMAGE_THUNK_DATA pOrig = (PIMAGE_THUNK_DATA)(uiNewBase + pImp->OriginalFirstThunk);
                PIMAGE_THUNK_DATA pThunk = (PIMAGE_THUNK_DATA)(uiNewBase + pImp->FirstThunk);
                if (!pOrig) pOrig = pThunk;
                while (pOrig->u1.AddressOfData) {
                    FARPROC func;
                    if (pOrig->u1.Ordinal & IMAGE_ORDINAL_FLAG)
                        func = pGetProcAddress(hMod, (LPCSTR)IMAGE_ORDINAL(pOrig->u1.Ordinal));
                    else {
                        PIMAGE_IMPORT_BY_NAME pByName = (PIMAGE_IMPORT_BY_NAME)(uiNewBase + pOrig->u1.AddressOfData);
                        func = pGetProcAddress(hMod, pByName->Name);
                    }
                    pThunk->u1.Function = (ULONG_PTR)func;
                    pOrig++; pThunk++;
                }
            }
            pImp++;
        }
    }

    // 8. 调用入口点（DllMain）
    typedef BOOL(WINAPI* fnDllMain)(HINSTANCE, DWORD, LPVOID);
    fnDllMain pDllMain = (fnDllMain)(uiNewBase + pNtHeader->OptionalHeader.AddressOfEntryPoint);
    pDllMain((HINSTANCE)uiNewBase, DLL_PROCESS_ATTACH, NULL);

    return uiNewBase;
}