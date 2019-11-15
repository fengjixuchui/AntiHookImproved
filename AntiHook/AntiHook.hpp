#pragma once
#ifndef __ANTIHOOK_H__
#define __ANTIHOOK_H__
#include <Windows.h>
#define SIZEOF_FUNC_NAME MAX_PATH

typedef enum _ERR_CODE {
  ERR_SUCCESS,
  ERR_ENUM_PROCESS_MODULES_FAILED,
  ERR_SIZE_TOO_SMALL,
  ERR_MOD_NAME_NOT_FOUND,
  ERR_MOD_QUERY_FAILED,
  ERR_CREATE_FILE_FAILED,
  ERR_CREATE_FILE_MAPPING_FAILED,
  ERR_CREATE_FILE_MAPPING_ALREADY_EXISTS,
  ERR_MAP_FILE_FAILED,
  ERR_MEM_DEPROTECT_FAILED,
  ERR_MEM_REPROTECT_FAILED,
  ERR_TEXT_SECTION_NOT_FOUND,
  ERR_FILE_PATH_QUERY_FAILED
} ERR_CODE;

typedef struct _HOOK_FUNC_INFO {
  HMODULE hModule;							// Module of the hooked function, if exists.
  WORD wOrdinal;							// Ordinal of the function.
  LPVOID lpFuncAddress;						// Address of the function.
  CHAR szFuncName[SIZEOF_FUNC_NAME];			// Name of hooked function.
  CHAR szHookModuleName[SIZEOF_FUNC_NAME];	// Name of the hooking module, if exists.
  LPVOID lpHookAddress;						// Destinaton of the address of the redirection.
} HOOK_FUNC_INFO, *LPHOOK_FUNC_INFO;

LPHOOK_FUNC_INFO NewHookFuncInfo(void);
BOOL FreeHookFuncInfo(LPHOOK_FUNC_INFO *info);
DWORD GetModules(HMODULE *hModules, const DWORD nSize, LPDWORD dwNumModules);
DWORD GetModuleName(const HMODULE hModule, LPSTR szModuleName, const DWORD nSize);
DWORD CheckModuleForHooks(const HMODULE hModule, LPHOOK_FUNC_INFO *infos, const SIZE_T nSize, LPDWORD cbNeeded);
DWORD UnhookModule(const HMODULE hModule);

FORCEINLINE void log()
{
}

template <typename First, typename ...Rest>
FORCEINLINE void log(First &&message, Rest &&...rest)
{
  std::cout << std::forward<First>(message);
  log(std::forward<Rest>(rest)...);
}

#endif // !__ANTIHOOK_H__
