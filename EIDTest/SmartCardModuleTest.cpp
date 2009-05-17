#include <windows.h>
#include "../EIDCardLibrary/CertificateUtilities.h"
#include "../EIDCardLibrary/SmartCardModule.h"
#include "EIDTestUIUtil.h"

void test_SmartCardModule()
{
	TCHAR szReader[256];
	TCHAR szCard[256];
	TCHAR szPin[256];
	MGSC_CONTEXT pContext = {0};
	SCARDCONTEXT hSCardContext = NULL;
	SCARDHANDLE hSCardHandle = NULL;
	BYTE bAtr[32];
	DWORD cbAtr = ARRAYSIZE(bAtr);
	LONG lReturn;
	DWORD dwSize, dwState, dwProtocol, dwAttempts = 0xFFFFFFFF;
	DWORD dwError = 0;
	if (AskForCard(szReader,ARRAYSIZE(szReader),szCard,ARRAYSIZE(szCard)))
	{
		if (AskPin(szPin))
		{
			__try
			{
				lReturn = SCardEstablishContext(SCARD_SCOPE_USER,
										NULL,
										NULL,
										&hSCardContext );
				if ( SCARD_S_SUCCESS != lReturn )
				{
					__leave;
				}
				lReturn = SCardConnect(hSCardContext,szReader,SCARD_SHARE_SHARED,SCARD_PROTOCOL_T1|SCARD_PROTOCOL_T0, &hSCardHandle, &dwProtocol);
				if ( SCARD_S_SUCCESS != lReturn )
				{
					__leave;
				}
				dwSize = ARRAYSIZE(szReader);
				lReturn = SCardStatus(hSCardHandle, szReader, &dwSize, &dwState, &dwProtocol, bAtr,&cbAtr);
				if ( SCARD_S_SUCCESS != lReturn )
				{
					__leave;
				}
				lReturn = SCardBeginTransaction(hSCardHandle);
				if ( SCARD_S_SUCCESS != lReturn )
				{
					__leave;
				}
				dwError = MgScCardAcquireContext(&pContext,hSCardContext,hSCardHandle,szCard,bAtr,cbAtr,0);
				if ( dwError )
				{
					__leave;
				}
				dwError = MgScCardAuthenticatePin(&pContext,L"user",szPin,&dwAttempts);
				if ( dwError )
				{
					__leave;
				}
			}
			__finally
			{
				if (pContext.pvContext)
					MgScCardDeleteContext(&pContext);
				if (hSCardHandle)
				{
					SCardEndTransaction(hSCardHandle,SCARD_LEAVE_CARD);
					SCardDisconnect(hSCardHandle,0);
				}
				if (hSCardContext)
					SCardReleaseContext(hSCardContext);
			}
		}
	}
}