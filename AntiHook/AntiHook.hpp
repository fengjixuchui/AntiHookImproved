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

DWORD GetModuleName(const HMODULE hModule, LPSTR szModuleName, const DWORD nSize);
DWORD UnhookModule(const HMODULE hModule);

FORCEINLINE void log_()
{
}

template <typename First, typename ...Rest>
FORCEINLINE void log_(First &&message, Rest &&...rest)
{
  std::cout << std::forward<First>(message);
  log_(std::forward<Rest>(rest)...);
}

#endif // !__ANTIHOOK_H__
