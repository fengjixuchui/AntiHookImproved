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

// Calculates the number of elements in an array.
#define SIZEOF_ARRAY(x) ((sizeof(x))/(sizeof(*x)))

// Console colours.
#define CONSOLE_RED FOREGROUND_RED | FOREGROUND_INTENSITY
#define CONSOLE_DARK_RED FOREGROUND_RED
#define CONSOLE_GREEN FOREGROUND_GREEN | FOREGROUND_INTENSITY
#define CONSOLE_DARK_GREEN FOREGROUND_GREEN
#define CONSOLE_BLUE FOREGROUND_BLUE | FOREGROUND_INTENSITY
#define CONSOLE_DARK_BLUE FOREGROUND_BLUE
#define CONSOLE_CYAN FOREGROUND_BLUE | FOREGROUND_GREEN | FOREGROUND_INTENSITY
#define CONSOLE_YELLOW FOREGROUND_GREEN | FOREGROUND_RED | FOREGROUND_INTENSITY
#define CONSOLE_DARK_YELLOW FOREGROUND_GREEN | FOREGROUND_RED
#define CONSOLE_PURPLE FOREGROUND_BLUE | FOREGROUND_RED | FOREGROUND_INTENSITY
#define CONSOLE_DARK_PURPLE FOREGROUND_BLUE | FOREGROUND_RED
#define CONSOLE_WHITE FOREGROUND_BLUE | FOREGROUND_GREEN | FOREGROUND_RED | FOREGROUND_INTENSITY
#define CONSOLE_GRAY FOREGROUND_BLUE | FOREGROUND_GREEN | FOREGROUND_RED

typedef enum _DEBUG_LEVEL {
  DEBUG_INFO,
  DEBUG_SUCCESS,
  DEBUG_WARNING,
  DEBUG_ERROR
} DEBUG_LEVEL;

CHAR dbgSym[] = {
  '*',	// DEBUG_INFO.
  '+',	// DEBUG_SUCCESS.
  '!',	// DEBUG_WARNING.
  '-'		// DEBUG_ERROR.
};

WORD dbgColour[] = {
  CONSOLE_WHITE,	// DEBUG_INFO.
  CONSOLE_GREEN,	// DEBUG_SUCCESS.
  CONSOLE_YELLOW,	// DEBUG_WARNING.
  CONSOLE_RED		// DEBUG_ERROR.
};

#define PRINT_INFO(fmt, ...) PrintDebug(DEBUG_INFO, fmt, __VA_ARGS__)
#define PRINT_SUCCESS(fmt, ... ) PrintDebug(DEBUG_SUCCESS, fmt, __VA_ARGS__)
#define PRINT_WARNING(fmt, ...) PrintDebug(DEBUG_WARNING, fmt, __VA_ARGS__)
#define PRINT_ERROR(fmt, ...) PrintDebug(DEBUG_ERROR, fmt, __VA_ARGS__)

/*
 * Struct to group the HOOK_FUNC_INFO structures by their module.
 *
 * Members:
 * - hModule: Handle to the hooked module.
 * - szModuleName: ASCII C string of the full path of the module.
 * - dwNumHooks: Number of hooks in the module.
 * - infos: Pointer to an array of HOOK_FUNC_INFO structures.
 */
typedef struct _MODULE_HOOK_INFO {
  HMODULE hModule;				// Handle to the hooked module.
  CHAR szModuleName[MAX_PATH];	// Full path to module name.
  DWORD dwNumHooks;				// Number of hooks in the module.
  LPHOOK_FUNC_INFO infos[1024];	// Hooked functions information.
} MODULE_HOOK_INFO, *LPMODULE_HOOK_INFO;

void PrintColour(const WORD wColour, const LPSTR fmt, ...) {
  // Save the state of the console.
  CONSOLE_SCREEN_BUFFER_INFO info;
  GetConsoleScreenBufferInfo(GetStdHandle(STD_OUTPUT_HANDLE), &info);
  // Change console colour.
  SetConsoleTextAttribute(GetStdHandle(STD_OUTPUT_HANDLE), wColour);
  // Print variadic arguments.
  va_list ap;
  va_start(ap, fmt);
  vprintf(fmt, ap);
  va_end(ap);
  // Restore original state of the console.
  SetConsoleTextAttribute(GetStdHandle(STD_OUTPUT_HANDLE), info.wAttributes);
}

void PrintDebug(const DEBUG_LEVEL l, const LPSTR fmt, ...) {
  // Print variadic arguments.
  va_list ap;
  va_start(ap, fmt);
  printf("[");
  PrintColour(dbgColour[l], "%c", dbgSym[l]);
  printf("] ");
  vprintf(fmt, ap);
  va_end(ap);
}

void PrintHookFuncInfo(const LPHOOK_FUNC_INFO info) {
  PRINT_WARNING("");
  PrintColour(CONSOLE_GREEN, "%s", info->szFuncName);
  printf(" (ordinal: ");
  PrintColour(CONSOLE_PURPLE, "%u", info->wOrdinal);
  printf(") hooked at [");
#ifdef _WIN64
  PrintColour(CONSOLE_RED, "0x%016p", info->lpHookAddress);
#else
  PrintColour(CONSOLE_RED, "0x%08p", info->lpHookAddress);
#endif
  printf("]\n");
  printf("\tModule name : ");
  PrintColour(CONSOLE_DARK_YELLOW, "%s\n", info->szHookModuleName);
}

void PrintBanner(void) {
  WORD wColours[] = {
    //CONSOLE_RED,
    CONSOLE_DARK_RED,
    CONSOLE_GREEN,
    //CONSOLE_DARK_GREEN,
    CONSOLE_BLUE,
    //CONSOLE_DARK_BLUE,
    CONSOLE_CYAN,
    //CONSOLE_YELLOW,
    CONSOLE_DARK_YELLOW,
    CONSOLE_PURPLE,
    //CONSOLE_DARK_PURPLE,
    //CONSOLE_WHITE,
    CONSOLE_GRAY
  };
  // lol
  srand((unsigned int)__rdtsc());
  PrintColour(
    wColours[rand() % SIZEOF_ARRAY(wColours)],
    " ________  ________   _________  ___  ___  ___  ________  ________  ___  __       \n"
    "|\\   __  \\|\\   ___  \\|\\___   ___\\\\  \\|\\  \\|\\  \\|\\   __  \\|\\   __  \\|\\  \\|\\  \\     \n"
    "\\ \\  \\|\\  \\ \\  \\\\ \\  \\|___ \\  \\_\\ \\  \\ \\  \\\\\\  \\ \\  \\|\\  \\ \\  \\|\\  \\ \\  \\/  /|_   \n"
    " \\ \\   __  \\ \\  \\\\ \\  \\   \\ \\  \\ \\ \\  \\ \\   __  \\ \\  \\\\\\  \\ \\  \\\\\\  \\ \\   ___  \\  \n"
    "  \\ \\  \\ \\  \\ \\  \\\\ \\  \\   \\ \\  \\ \\ \\  \\ \\  \\ \\  \\ \\  \\\\\\  \\ \\  \\\\\\  \\ \\  \\\\ \\  \\ \n"
    "   \\ \\__\\ \\__\\ \\__\\\\ \\__\\   \\ \\__\\ \\ \\__\\ \\__\\ \\__\\ \\_______\\ \\_______\\ \\__\\\\ \\__\\\n"
    "    \\|__|\\|__|\\|__| \\|__|    \\|__|  \\|__|\\|__|\\|__|\\|_______|\\|_______|\\|__| \\|__|\n\n"
  );
}

/*
 * AddModule
 * Returns a handle to a module if it exists, otherwise, loads a new module using
 * LoadLibrary and returns a handle to the module if successful.
 *
 * Parameters:
 * - lpLibName: Pointer to an ASCII C string of the desired module.
 *
 * Returns an HMDOULE of the desired module if successful, else, NULL.
 */
HMODULE AddModule(const LPSTR lpLibName) {
  HMODULE hModule = GetModuleHandleA(lpLibName);
  if (!hModule) {
    hModule = LoadLibraryA(lpLibName);
  }
  return hModule;
}

/*
 * NewModuleHookInfo
 * Returns a heap-allocated pointer to an array of heap-allocated MODULE_HOOK_INFO
 * structures. The pointer can be freed using the FreeModuleHookInfo function.
 *
 * Parameters:
 * - nSize: Desired number of elements of the array.
 *
 * Returns an LPMODULE_HOOK_INFO pointer if successful, else, NULL.
 */
LPMODULE_HOOK_INFO *NewModuleHookInfo(SIZE_T nSize) {
  // Create a pointer to an array of MODULE_HOOK_INFO.
  LPMODULE_HOOK_INFO *mods = (LPMODULE_HOOK_INFO *)HeapAlloc(
                               GetProcessHeap(),					// Handle to heap.
                               HEAP_ZERO_MEMORY,					// Heap allocation flag options.
                               sizeof(LPMODULE_HOOK_INFO) * nSize	// Number of bytes to be allocated.
                             );
  if (!mods) {
    return NULL;
  }
  ZeroMemory(mods, sizeof(sizeof(LPMODULE_HOOK_INFO) * nSize));
  for (SIZE_T i = 0; i < nSize; i++) {
    // Allocate a LPMODULE_HOOK_INFO.
    mods[i] = (LPMODULE_HOOK_INFO)HeapAlloc(
                GetProcessHeap(),			// Handle to heap.
                HEAP_ZERO_MEMORY,			// Heap allocation flag options.
                sizeof(MODULE_HOOK_INFO)	// Number of bytes to be allocated.
              );
    if (!mods[i]) {
      return NULL;
    }
    ZeroMemory(mods[i], sizeof(MODULE_HOOK_INFO));
    //ZeroMemory(mods[i]->szModuleName, sizeof(mods[i]->szModuleName));
    //mods[i]->dwNumHooks = 0;
    //ZeroMemory(mods[i]->infos, sizeof(mods[i]->infos));
  }
  return mods;
}

/*
 * FreeModuleHookInfo
 * Frees the heap-allocated resource provided by the NewModuleHookInfo function.
 *
 * Parameters:
 * - mod: Pointer to the LPMODULE_HOOK_INFO.
 * - nSize: Number of allocated elements.
 *
 * Returns TRUE if successful, else, FALSE???
 */
BOOL FreeModuleHookInfo(LPMODULE_HOOK_INFO *mod, SIZE_T nSize) {
  BOOL bRet = FALSE;
  // Free each LPMODULE_HOOK_INFO.
  for (SIZE_T i = 0; i < nSize; i++) {
    if (mod[i]) {
      bRet = HeapFree(
               GetProcessHeap(),	// Handle to heap.
               0,					// Heap free flag options.
               mod[i]				// Pointer to memory to be freed.
             );
      // Avoid dangling pointer.
      mod[i] = NULL;
    }
  }
  // Free the LPMODULE_HOOK_INFO array.
  if (!*mod) {
    bRet = HeapFree(
             GetProcessHeap(),	// Handle to heap.
             0,					// Heap free flag options.
             *mod				// Pointer to memory to be freed.
           );
    // Avoid dangling pointer.
    *mod = NULL;
  }
  return bRet;
}

/*
 * TestCreateProcess
 * Calls CreateProcess to check the integrity of the unhooked module's functions. Outputs
 * the process and thread IDs of the created process if successful.
 *
 * Parameters:
 * - lpApplicationName: Pointer to an ASCII C string of the desired application's full
 * path.
 * - bShowWindow: Boolean specifying whether to show or hide the application's window. If
 * the window is not shown, it will be automatically terminated if the process has been
 * successfully spawned.
 */
void TestCreateProcess(const LPSTR lpApplicationName, const BOOL bShowWindow) {
  PRINT_INFO("Testing ");
  PrintColour(CONSOLE_GREEN, "CreateProcess");
  printf(" with ");
  PrintColour(CONSOLE_CYAN, "%s\n", lpApplicationName);
  STARTUPINFOA si;
  ZeroMemory(&si, sizeof(si));
  si.cb = sizeof(si);
  // Don't show application window.
  si.dwFlags = STARTF_USESHOWWINDOW;
  si.wShowWindow = bShowWindow ? SW_SHOW : SW_HIDE;
  PROCESS_INFORMATION pi;
  ZeroMemory(&pi, sizeof(pi));
  BOOL bRet = CreateProcess(
                lpApplicationName,	// Application path.
                NULL,				// Command line arguments.
                NULL,				// Process security attributes.
                NULL,				// Thread security attributes.
                FALSE,				// Inherit handles.
                0,					// Creation flags.
                NULL,				// Environment.
                NULL,				// Current directory.
                &si,				// Startup information.
                &pi					// Process information.
              );
  if (bRet == TRUE) {
    PRINT_INFO("Process ID: %u\n", pi.dwProcessId);
    PRINT_INFO("Thread ID: %u\n", pi.dwThreadId);
    PRINT_SUCCESS("Test success!\n\n");
    // If process is created, kill it and clean up.
    if (!bShowWindow) {
      TerminateProcess(pi.hProcess, 0);
    }
    CloseHandle(pi.hProcess);
    CloseHandle(pi.hThread);
  } else {
    DWORD dwError = GetLastError();
    PRINT_ERROR("Test failed: 0x%08x\n\n", dwError);
  }
}

int main(int argc, char *argv[]) {
  HMODULE hModule = GetModuleHandleA("ntdll.dll");
  DWORD hMod = UnhookModule(hModule);
  // Free the randomly added module.
  if (hMod) {
    FreeModule(hModule);
  }
#pragma warning(suppress: 6031)
  getchar();
  return 0;
}