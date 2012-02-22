#include <Windows.h>
#include "../EIDCardLibrary/OnlineDatabase.h"
#include "../EIDCardLibrary/Tracing.h"

void menu_Wizard_CommunicateTestOK()
{
	if (!CommunicateTestOK())
	{
		MessageBoxWin32(GetLastError());
	}
	else
	{
		MessageBoxWin32(0);
	}
}