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

#include "AntiHook.h"
#include "err.h"

HMODULE AddModule(const LPSTR lpLibName) {
  HMODULE hModule = GetModuleHandleA(lpLibName);
  if (!hModule) {
    hModule = LoadLibraryA(lpLibName);
  }
  return hModule;
}

int main(int argc, char *argv[]) {
  HMODULE hModule = AddModule("ntdll.dll");
  DWORD hMod = UnhookModule(hModule);
  // Free the randomly added module.
  if (hMod) {
    FreeModule(hModule);
  }
#pragma warning(suppress: 6031)
  getchar();
  return 0;
}