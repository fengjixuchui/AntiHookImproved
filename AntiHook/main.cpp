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
  DWORD ntdll = Unhook("ntdll.dll");
  if (ntdll == 0) {
    log("ntdll restored\r\n");
  }
  else {
    log("ntdll fail restored\r\n");
  }
  DWORD kernelbase = Unhook("kernelbase.dll");
  if (kernelbase == 0) {
    log("kernelbase restored\r\n");
  }
  else {
    log("kernelbase fail restored\r\n");
  }
  DWORD user32 = Unhook("user32.dll");
  if (user32 == 0) {
    log("user32 restored\r\n");
  }
  else {
    log("user32 fail restored\r\n");
  }
#pragma warning(suppress: 6031)
  getchar();
  return 0;
}