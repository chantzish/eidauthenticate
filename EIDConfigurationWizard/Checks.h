
#define CHECK_FAILED 0
#define CHECK_WARNING 1
#define CHECK_SUCCESS 2
#define CHECK_INFO 3

#define CHECK_CONTAINSCERT 0
#define CHECK_USERNAME 1
#define CHECK_VALIDATION 2
#define CHECK_CRYPTO 3
#define CHECK_HASPASSWORD 4
#define CHECK_REMOVEPOLICY 5

typedef struct tagCHECKINFO
{
    TCHAR szName[50];
    PTSTR szComment;
	DWORD dwStatus;
	PTSTR szAction;
	PVOID pCustomInfo;
}CHECKINFO;


extern CHECKINFO rgCheckInfo[ ];
extern DWORD dwCheckInfoNum;