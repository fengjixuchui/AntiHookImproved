#include <stdio.h>
#include <stdlib.h>
#include <time.h>
#include <stdarg.h>
#include <Windows.h>

#include "AntiHook.hpp"
#include <iostream>

typedef NTSTATUS(NTAPI *p_nt_query_information_process)(IN HANDLE, IN UINT, OUT PVOID, IN ULONG, OUT PULONG);

BOOL nt_query_information_process_process_debug_object()
{
  // ProcessDebugFlags
  const auto process_debug_object_handle = 0x1e;
  const auto nt_query_info_process = reinterpret_cast<p_nt_query_information_process>(GetProcAddress(
                                       GetModuleHandleA("ntdll.dll"), "NtQueryInformationProcess"));
  HANDLE h_debug_object = nullptr;
  const unsigned long d_process_information_length = sizeof(ULONG) * 2;
  const auto status = nt_query_info_process(GetCurrentProcess(), process_debug_object_handle, &h_debug_object,
                      d_process_information_length,
                      nullptr);
  if (status == 0x00000000 && h_debug_object)
    return TRUE;
  return FALSE;
}


int main(int argc, char *argv[]) {
  DWORD ntdll = Unhook("ntdll.dll");
  if (ntdll == 0) {
    log_("ntdll restored\r\n");
  }
  else {
    log_("ntdll fail restored\r\n");
  }
  /*DWORD kernel32 = Unhook("kernel32.dll");
  if (kernel32 == 0) {
    log_("kernel32 restored\r\n");
  }
  else {
    log_("kernel32 fail restored\r\n");
  }*/
  DWORD user32 = Unhook("user32.dll");
  if (user32 == 0) {
    log_("user32 restored\r\n");
  }
  else {
    log_("user32 fail restored\r\n");
  }
  if (nt_query_information_process_process_debug_object() != FALSE)
  {
    log_("NtQueryInformationProcess with ProcessDebugObject detected\r\n");
  }
#pragma warning(suppress: 6031)
  getchar();
  return 0;
}