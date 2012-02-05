class CWinLogon;

class CGina
{
public:
    //
    // The following methods map directly onto the exported functions from the GINA
    //
    static BOOL Negotiate(DWORD dwWinlogonVersion, DWORD* pdwDllVersion);
    static BOOL Initialize(LPWSTR                  lpWinsta,
							HANDLE                  hWlx,
							PVOID                   pvReserved,
							PVOID                   pWinlogonFunctions,
							CGina** ppNewGina);
    
    int LoggedOutSAS(DWORD dwSasType, PLUID pAuthenticationId, PSID pLogonSid, PDWORD pdwOptions, PHANDLE phToken, PWLX_MPR_NOTIFY_INFO pNprNotifyInfo, PVOID* pProfile);
    int LoggedOnSAS(DWORD dwSasType,PVOID pReserved);
    int WkstaLockedSAS(DWORD dwSasType);

    BOOL ActivateUserShell(PWSTR pszDesktopName, PWSTR pszMprLogonScript, PVOID pEnvironment);

    void DisplaySASNotice();
    void DisplayLockedNotice();

    BOOL IsLockOk();
    BOOL IsLogoffOk();

    void Logoff();
    void Shutdown(DWORD ShutdownType);
	BOOL ScreenSaverNotify(BOOL *pSecure);
	BOOL StartApplication(PWSTR pszDesktopName, PVOID pEnvironment, PWSTR pszCmdLine);
    BOOL NetworkProviderLoad(PWLX_MPR_NOTIFY_INFO pNprNotifyInfo);

    BOOL DisplayStatusMessage(HDESK hDesktop, DWORD dwOptions, PWSTR pTitle, PWSTR pMessage);
    BOOL GetStatusMessage(DWORD* pdwOptions, PWSTR pMessage, DWORD dwBufferSize);
    BOOL RemoveStatusMessage();

    BOOL GetConsoleSwitchCredentials(PVOID pCredInfo);
    void DisconnectNotify();
    void ReconnectNotify();
	~CGina();
protected:
	CGina(CWinLogon* pWinLogon);
	static VOID SetWinLogonVersion(DWORD dwWlxVersion){_WlxVersion = dwWlxVersion;}
	static DWORD GetWinLogonVersion(){return _WlxVersion;}
	PVOID pMsGinaContext;
	CWinLogon* _pWinLogon;
private:
	static DWORD _WlxVersion;
};
