#include <stdio.h>
#include <stdlib.h>
#include <time.h>
#include <stdarg.h>
#include <Windows.h>

#include "AntiHook.hpp"
#include <iostream>

BOOL check_remote_debugger_present_api()
{
  auto b_is_dbg_present = FALSE;
  CheckRemoteDebuggerPresent(GetCurrentProcess(), &b_is_dbg_present);
  return b_is_dbg_present;
}

int main(int argc, char *argv[]) {
  DWORD ntdll = Unhook("ntdll.dll");
  if (ntdll == 0) {
    log_("ntdll restored\r\n");
  }
  else {
    log_("ntdll fail restored\r\n");
  }
  DWORD kernel32 = Unhook("kernel32.dll");
  if (kernel32 == 0) {
    log_("kernel32 restored\r\n");
  }
  else {
    log_("kernel32 fail restored\r\n");
  }
  DWORD user32 = Unhook("user32.dll");
  if (user32 == 0) {
    log_("user32 restored\r\n");
  }
  else {
    log_("user32 fail restored\r\n");
  }
  if (check_remote_debugger_present_api() != FALSE)
  {
    log_("CheckRemoteDebuggerPresent detected\r\n");
  }
  return 0;
}