
extern HINSTANCE g_hinst;

extern BOOL fHasAlreadySmartCardCredential;
extern BOOL fShowNewCertificatePanel;
extern BOOL fGotoNewScreen;

extern WCHAR szReader[];
extern DWORD dwReaderSize;
extern WCHAR szCard[];
extern DWORD dwCardSize;
extern WCHAR szUserName[];
extern DWORD dwUserNameSize;

VOID CenterWindow(HWND hWnd);
BOOL IsElevated();
BOOL DialogForceSmartCardLogonPolicy();
BOOL DialogRemovePolicy();
BOOL CreateDebugReport(PTSTR szLogFile);
BOOL SendReport(DWORD dwErrorCode, PTSTR szEmail);
VOID SetIcon(HWND hWnd);
