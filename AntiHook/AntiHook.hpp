#pragma once

#ifndef __ANTIHOOK_H__
#define __ANTIHOOK_H__

#include <Windows.h>
#include <Psapi.h>
#include <Shlwapi.h>
#include <winternl.h>
#include <ntstatus.h>

#pragma comment(lib, "Shlwapi.lib")

#define NtCurrentProcess() ((HANDLE)-1)

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

typedef enum _SUSPEND_RESUME_TYPE {
  srtSuspend,
  srtResume
} SUSPEND_RESUME_TYPE, * PSUSPEND_RESUME_TYPE;

typedef struct _SUSPEND_RESUME_INFO {
  ULONG CurrentPid;
  ULONG CurrentTid;
  SUSPEND_RESUME_TYPE Type;
} SUSPEND_RESUME_INFO, * PSUSPEND_RESUME_INFO;

typedef struct _WRK_SYSTEM_PROCESS_INFORMATION {
  ULONG NextEntryOffset;
  ULONG NumberOfThreads;
  LARGE_INTEGER SpareLi1;
  LARGE_INTEGER SpareLi2;
  LARGE_INTEGER SpareLi3;
  LARGE_INTEGER CreateTime;
  LARGE_INTEGER UserTime;
  LARGE_INTEGER KernelTime;
  UNICODE_STRING ImageName;
  KPRIORITY BasePriority;
  HANDLE UniqueProcessId;
  HANDLE InheritedFromUniqueProcessId;
  ULONG HandleCount;
  ULONG SessionId;
  ULONG_PTR PageDirectoryBase;
  SIZE_T PeakVirtualSize;
  SIZE_T VirtualSize;
  ULONG PageFaultCount;
  SIZE_T PeakWorkingSetSize;
  SIZE_T WorkingSetSize;
  SIZE_T QuotaPeakPagedPoolUsage;
  SIZE_T QuotaPagedPoolUsage;
  SIZE_T QuotaPeakNonPagedPoolUsage;
  SIZE_T QuotaNonPagedPoolUsage;
  SIZE_T PagefileUsage;
  SIZE_T PeakPagefileUsage;
  SIZE_T PrivatePageCount;
  LARGE_INTEGER ReadOperationCount;
  LARGE_INTEGER WriteOperationCount;
  LARGE_INTEGER OtherOperationCount;
  LARGE_INTEGER ReadTransferCount;
  LARGE_INTEGER WriteTransferCount;
  LARGE_INTEGER OtherTransferCount;
  SYSTEM_THREAD_INFORMATION Threads[1];
} WRK_SYSTEM_PROCESS_INFORMATION, * PWRK_SYSTEM_PROCESS_INFORMATION;

typedef enum _WRK_MEMORY_INFORMATION_CLASS {
  MemoryBasicInformation
} WRK_MEMORY_INFORMATION_CLASS, * PWRK_MEMORY_INFORMATION_CLASS;

extern "C" NTSYSAPI NTSTATUS NTAPI NtOpenThread(
  OUT PHANDLE ThreadHandle,
  IN ACCESS_MASK DesiredAccess,
  IN POBJECT_ATTRIBUTES ObjectAttributes,
  IN CLIENT_ID *ClientId
);

extern "C" NTSYSAPI NTSTATUS NTAPI NtSuspendThread(
  IN HANDLE ThreadHandle,
  OUT OPTIONAL PULONG PreviousSuspendCount
);

extern "C" NTSYSAPI NTSTATUS NTAPI NtResumeThread(
  IN HANDLE ThreadHandle,
  OUT OPTIONAL PULONG SuspendCount
);

extern "C" NTSYSAPI NTSTATUS NTAPI NtAllocateVirtualMemory(
  IN HANDLE ProcessHandle,
  IN OUT PVOID *BaseAddress,
  IN ULONG ZeroBits,
  IN OUT PSIZE_T RegionSize,
  IN ULONG AllocationType,
  IN ULONG Protect
);
extern "C" NTSYSAPI NTSTATUS NTAPI NtFreeVirtualMemory(
  IN HANDLE ProcessHandle,
  IN PVOID *BaseAddress,
  IN OUT PSIZE_T RegionSize,
  IN ULONG FreeType
);

extern "C" NTSYSAPI NTSTATUS NTAPI NtSuspendThread(
  IN HANDLE ThreadHandle,
  OUT OPTIONAL PULONG PreviousSuspendCount
);

extern "C" NTSYSAPI NTSTATUS NTAPI NtResumeThread(
  IN HANDLE ThreadHandle,
  OUT OPTIONAL PULONG SuspendCount
);

void *__teb()
{
#ifdef _AMD64_
  return (void *)__readgsqword(0x30);
#else
  return (void *)__readfsdword(0x18);
#endif
}

unsigned int __pid()
{
#ifdef _AMD64_
  return *(unsigned int *)((unsigned char *)__teb() + 0x40);
#else
  return *(unsigned int *)((unsigned char *)__teb() + 0x20);
#endif
}

unsigned int __tid()
{
#ifdef _AMD64_
  return *(unsigned int *)((unsigned char *)__teb() + 0x48);
#else
  return *(unsigned int *)((unsigned char *)__teb() + 0x24);
#endif
}

PVOID Alloc(OPTIONAL PVOID Base, SIZE_T Size, ULONG Protect)
{
  NTSTATUS Status = NtAllocateVirtualMemory(NtCurrentProcess(), &Base, Base ? 12 : 0, &Size, MEM_RESERVE | MEM_COMMIT, Protect);
  return NT_SUCCESS(Status) ? Base : NULL;
}

VOID Free(PVOID Base)
{
  SIZE_T RegionSize = 0;
  NtFreeVirtualMemory(NtCurrentProcess(), &Base, &RegionSize, MEM_RELEASE);
}

BOOLEAN NTAPI EnumProcesses_(
  BOOLEAN(*Callback)(
    PWRK_SYSTEM_PROCESS_INFORMATION Process,
    OPTIONAL PVOID Argument
  ),
  OPTIONAL PVOID Argument
) {
  ULONG Length = 0;
  NTSTATUS Status = NtQuerySystemInformation(SystemProcessInformation, NULL, 0, &Length);
  if (Status != STATUS_INFO_LENGTH_MISMATCH) return FALSE;
  PWRK_SYSTEM_PROCESS_INFORMATION Info = (PWRK_SYSTEM_PROCESS_INFORMATION)Alloc(NULL, Length, PAGE_READWRITE);
  if (!Info) return FALSE;
  Status = NtQuerySystemInformation(SystemProcessInformation, Info, Length, &Length);
  if (!NT_SUCCESS(Status)) {
    Free(Info);
    return FALSE;
  }
  do {
    if (!Callback(Info, Argument)) break;
    Info = (PWRK_SYSTEM_PROCESS_INFORMATION)((PBYTE)Info + Info->NextEntryOffset);
  } while (Info->NextEntryOffset);
  Free(Info);
  return TRUE;
}

BOOLEAN SuspendResumeCallback(PWRK_SYSTEM_PROCESS_INFORMATION Process, PVOID Arg)
{
  if (!Process || !Arg) return FALSE;
  PSUSPEND_RESUME_INFO Info = (PSUSPEND_RESUME_INFO)Arg;
  if ((SIZE_T)Process->UniqueProcessId != (SIZE_T)Info->CurrentPid) return TRUE; // Continue the processes enumeration loop
  for (unsigned int i = 0; i < Process->NumberOfThreads; ++i) {
    if ((SIZE_T)Process->Threads[i].ClientId.UniqueThread == (SIZE_T)Info->CurrentTid) continue;
    HANDLE hThread = NULL;
    NTSTATUS Status = NtOpenThread(&hThread, THREAD_SUSPEND_RESUME, NULL, &Process->Threads[i].ClientId);
    if (NT_SUCCESS(Status) && hThread) {
      ULONG SuspendCount = 0;
      switch (Info->Type) {
        case srtSuspend:
          NtSuspendThread(hThread, &SuspendCount);
          break;
        case srtResume:
          NtResumeThread(hThread, &SuspendCount);
          break;
      }
      NtClose(hThread);
    }
  }
  return FALSE; // Stop the processes enumeration loop
}

BOOLEAN SuspendThreads()
{
  SUSPEND_RESUME_INFO Info;
  Info.CurrentPid = __pid();
  Info.CurrentTid = __tid();
  Info.Type = srtSuspend;
  return EnumProcesses_(SuspendResumeCallback, &Info);
}

BOOLEAN ResumeThreads()
{
  SUSPEND_RESUME_INFO Info;
  Info.CurrentPid = __pid();
  Info.CurrentTid = __tid();
  Info.Type = srtResume;
  return EnumProcesses_(SuspendResumeCallback, &Info);
}

DWORD GetModuleName(const HMODULE hModule, LPSTR szModuleName, const DWORD nSize)
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

DWORD ProtectMemory(const LPVOID lpAddress, const SIZE_T nSize, const DWORD flNewProtect)
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

DWORD ReplaceExecSection(const HMODULE hModule, const LPVOID lpMapping)
{
  SuspendThreads();
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
        ResumeThreads();
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
        ResumeThreads();
        // Reprotecting went wrong!
        return ERR_MEM_REPROTECT_FAILED;
      }
      ResumeThreads();
      return ERR_SUCCESS;
    }
  }
  // .text section not found?
  ResumeThreads();
  return ERR_TEXT_SECTION_NOT_FOUND;
}

DWORD UnhookModule(const HMODULE hModule)
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

void log_()
{
}

template <typename First, typename ...Rest>
void log_(First &&message, Rest &&...rest)
{
  std::cout << std::forward<First>(message);
  log_(std::forward<Rest>(rest)...);
}

HMODULE AddModule(const char *lpLibName) {
  HMODULE hModule = GetModuleHandleA(lpLibName);
  if (!hModule) {
    hModule = LoadLibraryA(lpLibName);
  }
  return hModule;
}

DWORD Unhook(const char *lpLibName) {
  HMODULE hModule = AddModule(lpLibName);
  DWORD hMod = UnhookModule(hModule);
  // free lib
  if (hMod) {
    FreeModule(hModule);
  }
  else {
    FreeModule(hModule);
  }
  return hMod;
}

#endif // !__ANTIHOOK_H__
