/*
 * TODO: x86 has a bug, maybe it exists in x64 too.
 * Maybe this entire project is a bug itself.
 * Who really knows...?
 */

#include <stdio.h>
#include <stdlib.h>
#include <time.h>
#include <stdarg.h>
#include <Windows.h>

#include "AntiHook.hpp"
#include <iostream>

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
  return hMod;
}

int main(int argc, char *argv[]) {
  DWORD ntdll;
  if (ntdll = Unhook("ntdll.dll") == 0) {
  }
#pragma warning(suppress: 6031)
  getchar();
  return 0;
}