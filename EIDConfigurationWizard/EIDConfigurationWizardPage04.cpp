#include <windows.h>
#include <tchar.h>
#include <commctrl.h>
#include <Winuser.h>
#include "global.h"
#include "EIDConfigurationWizard.h"
#include "ElevatedActions.h"

#include "Checks.h"

PTSTR Columns[] = {TEXT("Name"),TEXT("Comment"), TEXT("Action")};
#define COLUMN_NUM ARRAYSIZE(Columns)

void DoChecks();

BOOL InitListViewColumns(HWND hWndListView) 
{ 
    LVCOLUMN lvc; 
    int iCol; 

    // Initialize the LVCOLUMN structure.
    // The mask specifies that the format, width, text, and subitem members
    // of the structure are valid. 
    lvc.mask = LVCF_FMT | LVCF_TEXT | LVCF_SUBITEM; 
	  
    // Add the columns
    for (iCol = 0; iCol < COLUMN_NUM; iCol++) 
    { 
        lvc.iSubItem = iCol;
        lvc.pszText = Columns[iCol];	
        lvc.fmt = LVCFMT_LEFT;

        if (ListView_InsertColumn(hWndListView, iCol, &lvc) == -1) 
            return FALSE; 
    } 
    return TRUE; 
} 

BOOL InitListViewData(HWND hWndListView)
{
	LVITEM lvI;
	UINT ColumnsToDisplay[] = {1,2,3};
	// Some code to create the list-view control.
	// Initialize LVITEM members that are common to all items.
	lvI.mask = LVIF_TEXT | LVIF_IMAGE | LVIF_PARAM | LVIF_STATE | LVIF_COLUMNS; 
	lvI.state = 0; 
	lvI.stateMask = 0; 

	// Initialize LVITEM members that are different for each item. 
	for (DWORD index = 0; index < dwCheckInfoNum; index++)
	{
		lvI.iItem = index;
		lvI.iImage = rgCheckInfo[index].dwStatus;
		lvI.iSubItem = 0;
		lvI.lParam = (LPARAM) &rgCheckInfo[index];
		lvI.pszText = LPSTR_TEXTCALLBACK; // sends an LVN_GETDISP message.
		lvI.cColumns = ARRAYSIZE(ColumnsToDisplay);
		lvI.puColumns = ColumnsToDisplay;
		ListView_InsertItem(hWndListView, &lvI);
	}
	return TRUE;
}

BOOL InitListViewIcon(HWND hWndListView)
{
	HICON hiconItem;     // icon for list-view items 
    HIMAGELIST hLarge;   // image list for icon view 
    HIMAGELIST hSmall;   // image list for other views 

    // Create the full-sized icon image lists. 

	hLarge = ImageList_Create(GetSystemMetrics(SM_CXICON), 
                              GetSystemMetrics(SM_CYICON), 
                              ILC_COLOR32, 3, 3); 

    hSmall = ImageList_Create(GetSystemMetrics(SM_CXSMICON), 
                              GetSystemMetrics(SM_CYSMICON), 
                              ILC_COLOR32, 3, 3); 
	
    ImageList_SetBkColor(hLarge, GetSysColor(COLOR_WINDOW));
	ImageList_SetBkColor(hSmall, GetSysColor(COLOR_WINDOW));

	// Add an icon to each image list.  
	HMODULE hDll = LoadLibrary(TEXT("imageres.dll") );
//Check if hIcon is valid
    hiconItem = LoadIcon(hDll, MAKEINTRESOURCE(105)); 
    ImageList_AddIcon(hLarge, hiconItem); 
    ImageList_AddIcon(hSmall, hiconItem); 
	DestroyIcon(hiconItem); 
    
	hiconItem = LoadIcon(hDll, MAKEINTRESOURCE(107)); 
    ImageList_AddIcon(hLarge, hiconItem); 
    ImageList_AddIcon(hSmall, hiconItem); 
    DestroyIcon(hiconItem); 
    
	hiconItem = LoadIcon(hDll, MAKEINTRESOURCE(106)); 
    ImageList_AddIcon(hLarge, hiconItem); 
    ImageList_AddIcon(hSmall, hiconItem); 
    DestroyIcon(hiconItem); 

	hiconItem = LoadIcon(hDll, MAKEINTRESOURCE(81)); 
    ImageList_AddIcon(hLarge, hiconItem); 
    ImageList_AddIcon(hSmall, hiconItem); 
    DestroyIcon(hiconItem);
	FreeLibrary(hDll) ;

	// Assign the image lists to the list-view control. 
    ListView_SetImageList(hWndListView, hLarge, LVSIL_NORMAL); 
    ListView_SetImageList(hWndListView, hSmall, LVSIL_SMALL); 
	return TRUE;
}

BOOL InitListViewView(HWND hWndListView)
{
	LVTILEVIEWINFO tileViewInfo;
	tileViewInfo.cbSize = sizeof(LVTILEVIEWINFO);
	tileViewInfo.dwFlags = LVTVIF_FIXEDSIZE;  
	tileViewInfo.dwMask = LVTVIM_COLUMNS | LVTVIF_FIXEDSIZE ;
	tileViewInfo.cLines = 3;
	tileViewInfo.sizeTile.cx = 400;
	tileViewInfo.sizeTile.cy = 50;
	ListView_SetTileViewInfo(hWndListView, &tileViewInfo);
	ListView_SetView(hWndListView, LV_VIEW_TILE);
	//ListView_SetExtendedListViewStyle(hWndListView, LVS_EX_AUTOCHECKSELECT );
	return TRUE;
}

BOOL CALLBACK	WndProc_04CHECKS(HWND hWnd, UINT message, WPARAM wParam, LPARAM lParam)
{
	HWND hwndList;
	BOOL fDisplayNext;
	NMLVDISPINFO* plvdi = (NMLVDISPINFO*)lParam; 
	switch(message)
	{
	case WM_INITDIALOG:
		hwndList = GetDlgItem(hWnd, IDC_04CHECKS);
		InitListViewColumns(hwndList);
		InitListViewData(hwndList);		
		InitListViewIcon(hwndList);
		InitListViewView(hwndList);
		break;
		case WM_WINDOWPOSCHANGED:
			break;
    case WM_SIZE:
        hwndList = GetDlgItem(hWnd, IDC_04CHECKS);
		MoveWindow(hwndList, 
           5, 100,                  // starting x- and y-coordinates 
           LOWORD(lParam)-5,        // width of client area 
           HIWORD(lParam)-100,        // height of client area 
           TRUE); 
		break;
	case WM_NOTIFY :
        LPNMHDR pnmh = (LPNMHDR)lParam;
        switch(pnmh->code)
        {
			case PSN_SETACTIVE :
				// list view
				hwndList = GetDlgItem(hWnd, IDC_04CHECKS);
				ListView_DeleteAllItems(hwndList);
				DoChecks();
				InitListViewData(hwndList);	
				fDisplayNext = TRUE;
				for (DWORD dwI = 0; dwI < dwCheckInfoNum; dwI++)
				{
					if (rgCheckInfo[dwI].dwStatus == CHECK_FAILED)
					{
						fDisplayNext = FALSE;
						break;
					}
				}
				//this is an interior page
				if (fDisplayNext)
				{
					PropSheet_SetWizButtons(hWnd, PSWIZB_NEXT |	PSWIZB_BACK);
				}
				else
				{
					PropSheet_SetWizButtons(hWnd, PSWIZB_BACK);
				}
				
				break;
			case PSN_WIZBACK:
				if (!fShowNewCertificatePanel)
				{
					PropSheet_PressButton(hWnd, PSBTN_BACK);
				}
		    case LVN_GETDISPINFO:
				switch (plvdi->item.iSubItem)
				{
					case 0:
						plvdi->item.pszText = rgCheckInfo[plvdi->item.iItem].szName;
						break;
	            	  
					case 1:
						plvdi->item.pszText = rgCheckInfo[plvdi->item.iItem].szComment;
						break;
					case 2:
						plvdi->item.pszText = rgCheckInfo[plvdi->item.iItem].szAction;
						break;
	            
					default:
						break;
				}
			break;
			case NM_DBLCLK:
				LPNMITEMACTIVATE lpnmitem = (LPNMITEMACTIVATE) lParam;
				if (lpnmitem->iItem == CHECK_USERNAME && rgCheckInfo[CHECK_USERNAME].szAction)
				{
					RenameAccount(NULL,(PTSTR) rgCheckInfo[CHECK_USERNAME].pCustomInfo);
				}
				break;
		}
    }
	return FALSE;
}