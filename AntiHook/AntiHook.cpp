#include <Windows.h>
#include <Psapi.h>
#include <Shlwapi.h>

#include "AntiHook.hpp"

#pragma comment(lib, "Shlwapi.lib")

/*
 * Enum that describes the type of hook.
 *
 * TODO: Probably a good idea to make values specific
 * to each jump type e.g. HOOK_PUSH_RET or HOOK_JMP_E9
 * so that each condition can be identified and handled
 * in a separate and appropriate manner.
 *
 * Members:
 * - HOOK_NONE: No hook.
 * - HOOK_RELATIVE: Hook uses a relative address.
 * - HOOK_ABSOLUTE: Hook uses an absolute address.
 */
typedef enum _HOOK_TYPE {
  HOOK_NONE,
  HOOK_UNSUPPORTED,
  HOOK_RELATIVE,
  HOOK_ABSOLUTE,
  HOOK_ABSOLUTE_INDIRECT,
  HOOK_ABSOLUTE_INDIRECT_64
} HOOK_TYPE;

/*
 * NewHookFuncInfo
 * Returns a heap-allocated pointer to HOOK_FUNC_INFO. The pointer can be freed using the
 * FreeHookFuncInfo function.
 *
 * Returns an LPHOOK_FUNC_INFO if successful, else, NULL.
 */
LPHOOK_FUNC_INFO NewHookFuncInfo(void) {
  LPHOOK_FUNC_INFO info = (LPHOOK_FUNC_INFO)HeapAlloc(
                            GetProcessHeap(),			// Handle to heap.
                            HEAP_ZERO_MEMORY,			// Heap allocation flag options.
                            sizeof(HOOK_FUNC_INFO)		// Number of bytes to be allocated.
                          );
  if (!info) {
    return NULL;
  }
  info->hModule = NULL;
  info->lpFuncAddress = NULL;
  ZeroMemory(info->szFuncName, sizeof(info->szFuncName));
  ZeroMemory(info->szHookModuleName, sizeof(info->szHookModuleName));
  info->lpHookAddress = NULL;
  return info;
}

/*
 * FreeHookFuncInfo
 * Frees the heap-allocated resource provided by the NewHookFuncInfo function. The pointer
 * is set to NULL after being released.
 *
 * Parameters:
 * - info: Reference to a heap-allocated pointer to HOOK_FUNC_INFO.
 *
 * Returns TRUE on success, else, FALSE.
 */
BOOL FreeHookFuncInfo(LPHOOK_FUNC_INFO *info) {
  BOOL bRet = HeapFree(
                GetProcessHeap(),	// Handle to heap.
                0,					// Heap free flag options.
                *info				// Pointer to memory to be freed.
              );
  // Avoid dangling pointer.
  *info = NULL;
  return bRet;
}

/*
 * GetModules
 * Enumerates the current process's modules.
 *
 * Parameters:
 * - hModules: An array of HMODULES to receive the list of module handles.
 * - nSize: Size of the array of hModules in bytes.
 * - dwNumModules: Number of modules enumerated.
 *
 * Returns:
 * - ERR_SUCCESS: If successful.
 * - ERR_ENUM_PROCESS_MODULES_FAILED: If the call to EnumProcessModules failed.
 * - ERR_SIZE_TOO_SMALL: If the hModules array is too small. Call the function again with a
 * larger array.
 */
DWORD GetModules(HMODULE *hModules, const DWORD nSize, LPDWORD dwNumModules) {
  DWORD cbNeeded = 0;
  BOOL bRet = EnumProcessModules(
                GetCurrentProcess(),	// Process handle.
                hModules,				// Module array.
                nSize,					// Size of module array.
                &cbNeeded				// Number of bytes required to store all module
                // handles.
              );
  // Check if the call was successful.
  if (bRet == FALSE) {
    return ERR_ENUM_PROCESS_MODULES_FAILED;
  }
  // If cbNeeded > nSize, increase the size of the module array and call this function again.
  if (cbNeeded > nSize) {
    return ERR_SIZE_TOO_SMALL;
  }
  // Get the number of modules enumerated.
  *dwNumModules = cbNeeded / sizeof(HMODULE);
  return ERR_SUCCESS;
}

/*
 * GetModuleName
 * Retrieves the full path name of the desired module.
 *
 * Parameters:
 * - hModule: The handle to the desired module.
 * - szModuleName: The array to receive the full path name.
 * - nSize: The size of the array in bytes.
 *
 * Returns:
 * - ERR_SUCCESS: If successful.
 * - ERR_MOD_NAME_NOT_FOUND: The name of the module does not exist. szModuleName will
 * be contain the "<not found>" string.
 */
DWORD GetModuleName(const HMODULE hModule, LPSTR szModuleName, const DWORD nSize) {
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

// https://github.com/David-Reguera-Garcia-Dreg/anticuckoo/blob/master/anticuckoo.cpp
/*
 * IsHooked
 * Determines if the given address contains code to redirect the instruction pointer.
 * This function is in no means complete nor can it account for every different code pattern.
 *
 * Parameters:
 * - lpFuncAddress: The address in question.
 * - dwAddressOffset: A pointer to a DWORD_PTR to receive the offset from lpFuncAddress that
 * contains the address to which the instruction pointer will be redirected.
 *
 * Returns:
 * - HOOK_NONE: No hook is detected.
 * - HOOK_RELATIVE: A hook is detected that uses a relative address.
 * - HOOK_ABSOLUTE: A hook is detected that uses an absolute address.
 */
static HOOK_TYPE IsHooked(const LPVOID lpFuncAddress, DWORD_PTR *dwAddressOffset) {
  LPCBYTE lpAddress = (LPCBYTE)lpFuncAddress;
  if (lpAddress[0] == 0xE9) {
    *dwAddressOffset = 1;
    return HOOK_RELATIVE;
  } else if (lpAddress[0] == 0x90 && lpAddress[1] == 0xE9) {
    *dwAddressOffset = 2;
    return HOOK_RELATIVE;
  } else if (lpAddress[0] == 0x8B && lpAddress[1] == 0xFF && lpAddress[2] == 0xE9) {
    *dwAddressOffset = 3;
    return HOOK_RELATIVE;
  } else if (lpAddress[0] == 0x68 && lpAddress[5] == 0xC3) {
    *dwAddressOffset = 1;
    return HOOK_ABSOLUTE;
  } else if (lpAddress[0] == 0x90 && lpAddress[1] == 0x68 && lpAddress[6] == 0xC3) {
    *dwAddressOffset = 2;
    return HOOK_ABSOLUTE;
  } else if (lpAddress[0] == 0xFF && lpAddress[1] == 0x25) {
    *dwAddressOffset = 2;
    return HOOK_ABSOLUTE_INDIRECT;
    //return HOOK_UNSUPPORTED;
  } else if (lpAddress[0] == 0x8B && lpAddress[1] == 0xFF && lpAddress[2] == 0xFF && lpAddress[3] == 0x25) {
    *dwAddressOffset = 4;
    return HOOK_ABSOLUTE_INDIRECT;
    //return HOOK_UNSUPPORTED;
  } else if (lpAddress[0] == 0xB8 && lpAddress[5] == 0xFF && lpAddress[6] == 0xE0) {
    *dwAddressOffset = 1;
    return HOOK_ABSOLUTE;
  } else if (lpAddress[0] == 0xB8 && lpAddress[5] == 0x50 && lpAddress[6] == 0xC3) {
    *dwAddressOffset = 1;
    return HOOK_ABSOLUTE;
  } else if (lpAddress[0] == 0xA1 && lpAddress[5] == 0xFF && lpAddress[6] == 0xE0) {
    *dwAddressOffset = 1;
    return HOOK_ABSOLUTE;
  } else if (lpAddress[0] == 0xA1 && lpAddress[5] == 0x50 && lpAddress[6] == 0xC3) {
    *dwAddressOffset = 1;
    return HOOK_ABSOLUTE;
  } else if (lpAddress[0] == 0x90 && lpAddress[1] == 0x90 && lpAddress[3] == 0xE9) {
    *dwAddressOffset = 4;
    return HOOK_ABSOLUTE;
  } else if (lpAddress[5] == 0xFF && lpAddress[6] == 0x25) {
    *dwAddressOffset = 7;
    //return HOOK_ABSOLUTE_INDIRECT;
    return HOOK_UNSUPPORTED;
  } else if (lpAddress[0] == 0x48 && lpAddress[1] == 0xFF && lpAddress[2] == 0x25) {
    *dwAddressOffset = 3;
    //return HOOK_ABSOLUTE_INDIRECT_64;
    return HOOK_UNSUPPORTED;
  }
  return HOOK_NONE;
}

/*
 * CompareFilePaths
 * Checks if two given strings contain the same file path.
 *
 * Parameters:
 * - lpszFilePath1: Pointer to a C ASCII string that contains a file path.
 * - lpszFielPath2: Pointer to a C ASCII string that contains a file path.
 *
 * Returns TRUE if paths are the same, else, FALSE.
 */
static BOOL CompareFilePaths(LPCSTR lpszFilePath1, LPCSTR lpszFilePath2) {
  // Extract the paths first.
  BOOL bRet = FALSE;
  // Get first path.
  CHAR szFilePath1[MAX_PATH];
  ZeroMemory(szFilePath1, sizeof(szFilePath1));
  strncpy(szFilePath1, lpszFilePath1, sizeof(szFilePath1) - 1);
#pragma warning(suppress: 6053)
  bRet = PathRemoveFileSpec(
           (LPWSTR)szFilePath1		// Pointer to NULL-terminated string of length MAX_PATH.
         );
  // Get second path.
  CHAR szFilePath2[MAX_PATH];
  ZeroMemory(szFilePath2, sizeof(szFilePath2));
  strncpy(szFilePath2, lpszFilePath2, sizeof(szFilePath2) - 1);
#pragma warning(suppress: 6053)
  bRet = PathRemoveFileSpec(
           (LPWSTR)szFilePath2		// Pointer to NULL-terminated string of length MAX_PATH.
         );
  return !_stricmp(szFilePath1, szFilePath2) ? TRUE : FALSE;
}

/*
 * CheckModuleForHooks
 * Checks a module for hooked functions. A function is considered hooked if the beginning of
 * the code (offset 0) has an instruction pointer redirect outside of the module's pages.
 *
 * Parameters:
 * - hModule: Handle to the module to be checked.
 * - infos: An array of HOOK_FUNC_INFO pointers to store hooked functions' information.
 * - nSize: Number of elements available in infos.
 * - cbNeeded: Number of hooked functions detected. If this number exceeds nSize, call this
 * function again with a larger infos array.
 *
 * Returns:
 * - ERR_SUCCESS: If successful.
 * - ERR_MOD_QUERY_FAILED: If a call to query the redirected address in the hook fails.
 */
DWORD CheckModuleForHooks(const HMODULE hModule, LPHOOK_FUNC_INFO *infos, const SIZE_T nSize, LPDWORD cbNeeded) {
  // Keep track of the number of HOOK_FUNC_INFOs.
  SIZE_T nCurrentSize = 0;
  // Initialise required number of elements for infos.
  *cbNeeded = 0;
  // Initialise return value to no error.
  DWORD dwError = ERR_SUCCESS;
  // Parse the module's PE headers.
  PIMAGE_DOS_HEADER pidh = (PIMAGE_DOS_HEADER)hModule;
  PIMAGE_NT_HEADERS pinh = (PIMAGE_NT_HEADERS)((DWORD_PTR)hModule + pidh->e_lfanew);
  // Check if the export table exists.
  if (pinh->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress != 0) {
    // Get the export table for the module.
    PIMAGE_EXPORT_DIRECTORY pied = (PIMAGE_EXPORT_DIRECTORY)((DWORD_PTR)hModule + pinh->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress);
    LPDWORD lpFunctionTable = (LPDWORD)((DWORD_PTR)hModule + pied->AddressOfFunctions);
    LPDWORD lpNameTable = (LPDWORD)((DWORD_PTR)hModule + pied->AddressOfNames);
    LPWORD lpOrdinalTable = (LPWORD)((DWORD_PTR)hModule + pied->AddressOfNameOrdinals);
    // Walk the export table.
    for (DWORD i = 0; i < pied->NumberOfNames; i++) {
      // Get the address of the function.
      FARPROC fpFunc = (FARPROC)((DWORD_PTR)hModule + lpFunctionTable[lpOrdinalTable[i]]);
      // Check if the function is hooked.
      // If the function is hooked, dwAddressOffset will point to the redirected address.
      DWORD_PTR dwAddressOffset = 0;
      HOOK_TYPE hookType = IsHooked(
                             (LPVOID)fpFunc,		// Address of function.
                             &dwAddressOffset	// Offset of redirected address, if hook exists.
                           );
      if (hookType == HOOK_NONE || hookType == HOOK_UNSUPPORTED) {
        // Not hooked or unsupported, check next function.
        continue;
      }
      // Function is hooked, get information.
      LPHOOK_FUNC_INFO info = NewHookFuncInfo();
      // Set the module handle in the struct.
      info->hModule = hModule;
      // Set function's ordinal.
      info->wOrdinal = lpOrdinalTable[i];
      info->lpFuncAddress = fpFunc;
      // Get function name.
      // Default name, if no name exists.
      LPSTR lpszFuncName = (LPSTR)"<no name>";
      // Copy it into the struct.
      strncpy(info->szFuncName, lpszFuncName, sizeof(info->szFuncName) - 1);
      // Check if the function exists within the names.
      if (i < pied->NumberOfNames) {
        lpszFuncName = (LPSTR)((DWORD_PTR)hModule + lpNameTable[i]);
        // Copy it into the struct.
        ZeroMemory(info->szFuncName, sizeof(info->szFuncName));
        strncpy(info->szFuncName, lpszFuncName, sizeof(info->szFuncName) - 1);
      }
      // Get the address of the hook and set it into the struct.
      if (hookType == HOOK_RELATIVE) {
        // Relative distance + relative address.
        info->lpHookAddress = (LPVOID)(*(PINT)((LPBYTE)fpFunc + dwAddressOffset) + (DWORD_PTR)((LPBYTE)fpFunc + dwAddressOffset + 4));
      } else if (hookType == HOOK_ABSOLUTE) {
        info->lpHookAddress = (LPVOID)(*(LPDWORD)((LPBYTE)fpFunc + dwAddressOffset));
      } else if (hookType == HOOK_ABSOLUTE_INDIRECT) {
        // FF 25 indirect jmp
        info->lpHookAddress = (LPVOID)(*(DWORD_PTR *)(((LPBYTE)fpFunc + 6 + * (LPDWORD)((LPVOID)((LPBYTE)fpFunc + dwAddressOffset)))));
      } else if (hookType == HOOK_ABSOLUTE_INDIRECT_64) {
        // 48 FF 25 indirect jmp
        // TODO: fix this
        //info->lpHookAddress = (LPVOID)(*(DWORD_PTR *)(((LPBYTE)fpFunc + 7 + *(LPDWORD)((LPVOID)((LPBYTE)fpFunc + dwAddressOffset)))));
      }
      // Query the module address and name.
      MEMORY_BASIC_INFORMATION mbi;
      SIZE_T nSize = VirtualQuery(
                       info->lpHookAddress,				// Pointer to the base address.
                       // Value is rounded down to the next page
                       // boundary.
                       &mbi,								// Pointer to MEMORY_BASIC_INFORMATION.
                       sizeof(MEMORY_BASIC_INFORMATION)	// Size of buffer of the second parameter.
                     );
      // VirtualQuery returns 0 on error.
      if (nSize == 0) {
        // Failed to check if legitimate hook or query module name.
        // Append to infos list.
        if (nCurrentSize < nSize) {
          infos[nCurrentSize] = info;
          nCurrentSize++;
        }
        *cbNeeded = *cbNeeded + 1;
        // Set return value error.
        dwError = ERR_MOD_QUERY_FAILED;
        FreeHookFuncInfo(&info);
        continue;
      }
      // Check if the the hook is within the same module.
      if ((DWORD_PTR)mbi.AllocationBase == (DWORD_PTR)hModule) {
        // It's the same module, not third-party?
        FreeHookFuncInfo(&info);
        continue;
      }
      // Check kernel32 -> kernelbase
      CHAR szTargetModName[MAX_PATH];
      ZeroMemory(szTargetModName, sizeof(szTargetModName));
      GetModuleName(hModule, szTargetModName, sizeof(szTargetModName));
      CHAR szHookModName[MAX_PATH];
      ZeroMemory(szHookModName, sizeof(szHookModName));
      GetModuleName((HMODULE)mbi.AllocationBase, szHookModName, sizeof(szHookModName));
      if (StrStrI((LPWSTR)szTargetModName, (LPWSTR)"kernel32.dll") && StrStrI((LPWSTR)szHookModName, (LPWSTR)"kernelbase.dll")) {
        FreeHookFuncInfo(&info);
        continue;
      }
      // Get the hooking module name, if it exists.
      CHAR szHookModuleName[MAX_PATH];
      ZeroMemory(szHookModuleName, sizeof(szHookModuleName));
      DWORD dwLength = GetModuleName(
                         (HMODULE)mbi.AllocationBase,		// Module handle.
                         szHookModuleName,					// Pointer to buffer to receive name.
                         sizeof(szHookModuleName)			// Max size of the buffer.
                       );
      // Set the hooking module name.
      strncpy(info->szHookModuleName, szHookModuleName, sizeof(info->szHookModuleName) - 1);
      // Hooking module name must exist.
      if (strlen(info->szHookModuleName)) {
        // Get the current module's name.
        ZeroMemory(szHookModuleName, sizeof(szHookModuleName));
        DWORD dwLength = GetModuleName(
                           hModule,							// Module handle.
                           szHookModuleName,					// Pointer to buffer to receive name.
                           sizeof(szHookModuleName)			// Max size of the buffer.
                         );
        // Check if both modules have the same path.
        if (CompareFilePaths(info->szHookModuleName, szHookModuleName)) {
          // File paths are the same, assume not third-party.
          FreeHookFuncInfo(&info);
          continue;
        }
      }
      // Append to infos list.
      if (nCurrentSize < nSize) {
        infos[nCurrentSize] = info;
        nCurrentSize++;
      }
      *cbNeeded = *cbNeeded + 1;
    }
  }
  return dwError;
}

/*
 * ProtectMemory
 * Sets the protection for a memory page.
 *
 * Parameters:
 * - lpAddress: The address of the desired memory to be protected (rounded down to the nearest
 * page alignment).
 * - nSize: Size of the page.
 * - flNewProtect: The desired protection.
 *
 * Returns the old page protection if successful, else, 0.
 */
static DWORD ProtectMemory(const LPVOID lpAddress, const SIZE_T nSize, const DWORD flNewProtect) {
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

/*
 * RepalceExecSection
 * Replaces the .text section of an existing module with the provided, mapped module. The
 * module and the mapped module must be the same.
 *
 * Parameters:
 * - hModule: The handle to the module whose .text section will be replaced.
 * - lpMapping: The address of the mapped module that contains the .text section that will be
 * used to replace hModule's.
 *
 * Returns:
 * - ERR_SUCCESS: If successful.
 * - ERR_MEM_DEPROTECT_FAILED: If deprotecting hModule's .text section failed.
 * - ERR_MEM_REPROTECT_FAILED: If reverting hModule's .text section to the original
 * protection failed.
 * - ERR_TEXT_SECTION_NOT_FOUND: If the .text section in lpMapping's module was not found.
 */
static DWORD ReplaceExecSection(const HMODULE hModule, const LPVOID lpMapping) {
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

/*
 * UnhookModule
 * Attempts to unhook a given module. The module is located by retrieving the full path name
 * of the desired module and then mapped into the process. The newly-mapped module is then
 * used to recover a clean copy of the code section with which it is used to overwrite the
 * original module.
 *
 * Parameters:
 * - hModule: The module to be unhooked.
 *
 * Returns:
 * - ERR_SUCCESS: If successful.
 * - ERR_MOD_NAME_NOT_FOUND: If the full path name of the module is not found.
 * - ERR_CREATE_FILE_FAILED: If access a handle to the module's file failed.
 * - ERR_CREATE_FILE_MAPPING_FAILED: If the file mapping object already exists.
 * - ERR_MAP_FILE_FAILED: If mapping the module's file failed.
 */
DWORD UnhookModule(const HMODULE hModule) {
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
  } else if (GetLastError() == ERROR_ALREADY_EXISTS) {
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