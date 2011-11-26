
#include <windows.h>
#include <tchar.h>
#include <credentialProvider.h>
#include "../EIDCardLibrary/CContainer.h"
#include "CContainerHolder.h"


CContainerHolderTest::CContainerHolderTest(CContainer* pContainer)
{
	_pContainer = pContainer;

}

CContainerHolderTest::~CContainerHolderTest()
{
	if (_pContainer)
	{
		delete _pContainer;
	}
}
void CContainerHolderTest::Release()
{
	delete this;
}


CContainer* CContainerHolderTest::GetContainer()
{
	return _pContainer;
}

