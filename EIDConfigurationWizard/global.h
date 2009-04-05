
extern HINSTANCE g_hinst;

extern BOOL fHasAlreadySmartCardCredential;
extern BOOL fShowNewCertificatePanel;
extern BOOL fGotoNewScreen;

VOID CenterWindow(HWND hWnd);
BOOL IsElevated();
BOOL ChangeRemovePolicy(BOOL fActivate);
BOOL ChangeForceSmartCardLogonPolicy(BOOL fActivate);