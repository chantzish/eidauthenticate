/**
 *  Tracing function.
 */



/*
WINEVENT_LEVEL_CRITICAL Abnormal exit or termination events.
WINEVENT_LEVEL_ERROR Severe error events.
WINEVENT_LEVEL_WARNING Warning events such as allocation failures.
WINEVENT_LEVEL_INFO Non-error events such as entry or exit events.
WINEVENT_LEVEL_VERBOSE Detailed trace events.
*/

#pragma once

#define WINEVENT_LEVEL_CRITICAL 1
#define WINEVENT_LEVEL_ERROR    2
#define WINEVENT_LEVEL_WARNING  3
#define WINEVENT_LEVEL_INFO     4
#define WINEVENT_LEVEL_VERBOSE  5

void EIDCardLibraryTracingRegister();
void EIDCardLibraryTracingUnRegister();

#define EIDCardLibraryTrace(dwLevel, ...) \
	EIDCardLibraryTraceEx(__FILE__,__LINE__,__FUNCTION__, dwLevel, __VA_ARGS__);

void EIDCardLibraryTraceEx(LPCSTR szFile, DWORD dwLine, LPCSTR szFunction, UCHAR dwLevel, PCWSTR szFormat,...);

#define EIDCardLibraryDumpMemory(memory, memorysize) \
	EIDCardLibraryDumpMemoryEx(__FILE__,__LINE__,__FUNCTION__, memory, memorysize);

void EIDCardLibraryDumpMemoryEx(LPCSTR szFile, DWORD dwLine, LPCSTR szFunction, PUCHAR memory, DWORD memorysize);

/**
 *  Display a messagebox giving an error code
 */
void MessageBoxWin32Ex(DWORD status, LPCSTR szFile, DWORD dwLine);
#define MessageBoxWin32(status) MessageBoxWin32Ex (status, __FILE__,__LINE__);