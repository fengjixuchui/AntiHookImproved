#pragma once
#ifndef __ANTIHOOK_H__
#define __ANTIHOOK_H__
#include <Windows.h>
#include <Psapi.h>
#include <Shlwapi.h>

#pragma comment(lib, "Shlwapi.lib")

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

inline DWORD GetModuleName(const HMODULE hModule, LPSTR szModuleName, const DWORD nSize)
{
  DWORD dwLength = GetModuleFileNameExA(
                     GetCurrentProcess(),	// Process handle.
                     hModule,				// Module handle.
                     szModuleName,			// Pointer to buffer to receive file name.
                     nSize					// Size of the buffer in characters.
                   );
  // GetModuleFileNameEx returns 0 on error.
  if (dwLength == 0) {
    // Default value if the module name cannot be found.
    strncpy(szModuleName, "<not found>", nSize - 1);
    return ERR_MOD_NAME_NOT_FOUND;
  }
  return ERR_SUCCESS;
}

inline static DWORD ProtectMemory(const LPVOID lpAddress, const SIZE_T nSize, const DWORD flNewProtect)
{
  DWORD flOldProtect = 0;
  BOOL bRet = VirtualProtect(
                lpAddress,		// Base address to protect.
                nSize,			// Size to protect.
                flNewProtect,	// Desired protection.
                &flOldProtect	// Previous protection.
              );
  if (bRet == FALSE) {
    return 0;
  }
  return flOldProtect;
}

inline static DWORD ReplaceExecSection(const HMODULE hModule, const LPVOID lpMapping)
{
  // Parse the PE headers.
  PIMAGE_DOS_HEADER pidh = (PIMAGE_DOS_HEADER)lpMapping;
  PIMAGE_NT_HEADERS pinh = (PIMAGE_NT_HEADERS)((DWORD_PTR)lpMapping + pidh->e_lfanew);
  // Walk the section headers and find the .text section.
  for (WORD i = 0; i < pinh->FileHeader.NumberOfSections; i++) {
    PIMAGE_SECTION_HEADER pish = (PIMAGE_SECTION_HEADER)((DWORD_PTR)IMAGE_FIRST_SECTION(pinh) + ((DWORD_PTR)IMAGE_SIZEOF_SECTION_HEADER * i));
    if (!strcmp((const char *)pish->Name, ".text")) {
      // Deprotect the module's memory region for write permissions.
      DWORD flProtect = ProtectMemory(
                          (LPVOID)((DWORD_PTR)hModule + (DWORD_PTR)pish->VirtualAddress),	// Address to protect.
                          pish->Misc.VirtualSize,											// Size to protect.
                          PAGE_EXECUTE_READWRITE											// Desired protection.
                        );
      if (!flProtect) {
        // Deprotecting failed!
        return ERR_MEM_DEPROTECT_FAILED;
      }
      // Replace the hooked module's .text section with the newly mapped module's.
      memcpy(
        (LPVOID)((DWORD_PTR)hModule + (DWORD_PTR)pish->VirtualAddress),
        (LPVOID)((DWORD_PTR)lpMapping + (DWORD_PTR)pish->VirtualAddress),
        pish->Misc.VirtualSize
      );
      // Reprotect the module's memory region.
      flProtect = ProtectMemory(
                    (LPVOID)((DWORD_PTR)hModule + (DWORD_PTR)pish->VirtualAddress),	// Address to protect.
                    pish->Misc.VirtualSize,											// Size to protect.
                    flProtect														// Revert to old protection.
                  );
      if (!flProtect) {
        // Reprotecting went wrong!
        return ERR_MEM_REPROTECT_FAILED;
      }
      return ERR_SUCCESS;
    }
  }
  // .text section not found?
  return ERR_TEXT_SECTION_NOT_FOUND;
}

inline DWORD UnhookModule(const HMODULE hModule)
{
  CHAR szModuleName[MAX_PATH];
  ZeroMemory(szModuleName, sizeof(szModuleName));
  // Get the full path of the module.
  DWORD dwRet = GetModuleName(
                  hModule,
                  szModuleName,
                  sizeof(szModuleName)
                );
  if (dwRet == ERR_MOD_NAME_NOT_FOUND) {
    // Failed to get module name.
    return dwRet;
  }
  // Get a handle to the module's file.
  HANDLE hFile = CreateFileA(
                   szModuleName,		// Module path name.
                   GENERIC_READ,		// Desired access.
                   FILE_SHARE_READ,	// Share access.
                   NULL,				// Security attributes.
                   OPEN_EXISTING,		// Creation disposition.
                   0,					// Attributes.
                   NULL				// Template file handle.
                 );
  if (hFile == INVALID_HANDLE_VALUE) {
    // Failed to open file.
    return ERR_CREATE_FILE_FAILED;
  }
  // Create a mapping object for the module.
  HANDLE hFileMapping = CreateFileMapping(
                          hFile,						// Handle to file.
                          NULL,						// Mapping attributes.
                          PAGE_READONLY | SEC_IMAGE,	// Page protection.
                          0,							// Maximum size high DWORD.
                          0,							// Maximum size low DWORD.
                          NULL						// Name of mapping object.
                        );
  if (!hFileMapping) {
    // Failed to create mapping handle.
    // Clean up.
    CloseHandle(hFile);
    return ERR_CREATE_FILE_MAPPING_FAILED;
  }
  else if (GetLastError() == ERROR_ALREADY_EXISTS) {
    // Error creating mapping handle.
    // Clean up.
    CloseHandle(hFile);
    return ERR_CREATE_FILE_MAPPING_ALREADY_EXISTS;
  }
  // Map the module.
  LPVOID lpMapping = MapViewOfFile(
                       hFileMapping,	// Handle of mapping object.
                       FILE_MAP_READ,	// Desired access.
                       0,				// File offset high DWORD.
                       0,				// File offset low DWORD.
                       0				// Number of bytes to map.
                     );
  if (!lpMapping) {
    // Mapping failed.
    // Clean up.
    CloseHandle(hFileMapping);
    CloseHandle(hFile);
    return ERR_MAP_FILE_FAILED;
  }
  // printf("Mapping at [%016p]\n", lpMapping);
  // Unhook hooks.
  dwRet = ReplaceExecSection(
            hModule,		// Handle to the hooked module.
            lpMapping		// Pointer to the newly mapped module.
          );
  if (dwRet) {
    // Something went wrong!
    // Clean up.
    UnmapViewOfFile(lpMapping);
    CloseHandle(hFileMapping);
    CloseHandle(hFile);
    return dwRet;
  }
  //getchar();
  // Clean up.
  UnmapViewOfFile(lpMapping);
  CloseHandle(hFileMapping);
  CloseHandle(hFile);
  return ERR_SUCCESS;
}

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
