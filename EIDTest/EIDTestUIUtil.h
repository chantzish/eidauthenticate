#pragma once
BOOL AskUsername(WCHAR* Username, WCHAR* ComputerName);
BOOL AskPin(WCHAR* Pin);


PCCERT_CONTEXT SelectCerts(__in LPCWSTR szReaderName,__in LPCWSTR szCardName, 
				__out LPWSTR szOutProviderName,__in DWORD dwOutProviderLength,
				__out LPWSTR szOutContainerName,__in DWORD dwOutContainerLength,
				__in_opt PDWORD pdwKeySpec);




typedef void (TracingWindowsCallback)(void);
HWND CreateDialogTracing(TracingWindowsCallback *ponDestroy);
BOOL DisplayTrace(HWND hTracingWindow, PCTSTR szMessage);