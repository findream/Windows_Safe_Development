/*------------------------------------------------------------------------
注意点：
1.进行IAT_HOOK的时候只能HOOK本进程的，所以可以选择与DLL注入连用
2.变量类型
PULONG_PTR   --->unsigned _int64*
ULONG_PTR    --->unsigned _int64
LPCTSTR      --->STR类型的const指针(unicode)
LPCVOID      --->void类型的const指针(unicode)
PBYTE        --->byte*
PVOID        --->void*
ULONG32      --->usigned int 
https://www.cnblogs.com/goed/archive/2011/11/11/2245702.html
-------------------------------------------------------------------------*/




#include "IatHook.h"
#include <imagehlp.h>   //ImageDirectoryEntryToData函数
#pragma comment(lib,"imagehlp.lib")


//保存原来的函数地址和IAT地址
//两个作用，第一:在Detour函数里面调用Target函数需要用到
//第二，在卸载HOOK的时候，恢复原数据时候需要用到
PFN_MessageBoxA OldMessageBox=NULL;
#ifdef _WIN64
	PULONG_PTR g_PointerToIATThunk = NULL;
#else
	PULONG32 g_PointerToIATThunk = NULL;
#endif


int main(int agrc, char* agrv[])
{
	MessageBox(NULL, "Before", "warning", MB_OK);
	if (!IAT_InstallHook())
	{
		printf("InstallHook Failed\n");
		getchar();
		return FALSE;
	}
	MessageBox(NULL, "After", "warning", MB_OK);
	IAT_UnInstallHook();
	MessageBox(NULL, "Before", "warning", MB_OK);
	getchar();
	return 0;
}

BOOL IsWow64()
{
	BOOL bIsWow64 = FALSE;
	LPFUN_ISWOW64PROCESS fnIsWow64Process=NULL;
	fnIsWow64Process = (LPFUN_ISWOW64PROCESS)GetProcAddress(GetModuleHandle("Kernel32.dll"),
		"IsWow64Process");

	if (NULL != fnIsWow64Process)
	{
		if (!fnIsWow64Process(GetCurrentProcess(), &bIsWow64))
		{
			printf("fnIsWow64Process:%d\n", GetLastError());
		}
	}
	return bIsWow64;
}


BOOL IAT_InstallHook()
{
	//设置IAT_HOOK
	BOOL bResult = FALSE;

	HMODULE hCurExe = GetModuleHandle(NULL);   //当前模块的句柄
#ifdef _WIN64
	PULONG_PTR pt;                             //需要保存的IAT地址
	ULONG_PTR OrginalAddr;                     //需要保存的IAT数值
#else
	PULONG32 pt;
	ULONG32 OrginalAddr;
#endif
	


	//安装HOOK
	bResult = InstallModuleIATHook(hCurExe, "user32.dll", "MessageBoxA", (PVOID)My_MessageBoxA, &pt, &OrginalAddr);

	//安装成功，保存Target函数地址和IAT地址，以便后期使用
	if (bResult)
	{
		printf("[*]Hook安装完毕! pThunk=0x%p  OriginalAddr = 0x%p\n", pt, OrginalAddr);

		//保存Target函数地址和IAT地址，以便后期使用
		OldMessageBox = (PFN_MessageBoxA)OrginalAddr;
		g_PointerToIATThunk = pt;
	}
	return bResult;
}


//卸载HOOK
VOID IAT_UnInstallHook()
{
	DWORD dwOldProtect;
	SIZE_T size = 0;
#ifdef _WIN64
	size = sizeof(PULONG_PTR);
#else
	size=sizeof(PULONG32);
#endif

	if (g_PointerToIATThunk)
	{
		VirtualProtect(g_PointerToIATThunk, size, PAGE_EXECUTE_READWRITE, &dwOldProtect);

#ifdef _WIN64
		*g_PointerToIATThunk = (ULONG64)OldMessageBox;
#else
		*g_PointerToIATThunk = (ULONG32)OldMessageBox;
#endif

		printf("[*]Uninstall--->*g_PointerToIATThunk：%p,OldMessageBox：%p", *g_PointerToIATThunk, OldMessageBox);
		VirtualProtect(g_PointerToIATThunk, size, dwOldProtect, 0);
	}
}


//安装HOOK
BOOL InstallModuleIATHook(
	HMODULE hModToHook,   //待HOOK 的模块句柄
	char* szModuleName,   //待HOOK的模块名
	char* szFuncName,     //目标函数名称
	PVOID DetourFunc,     //Detour函数地址
#ifdef _WIN64
	PULONG_PTR *pThunkPointer,  //用以接收指向修改的位置的指针
	ULONG_PTR *pOriginalFuncAddr   //用以接收原始函数地址
#else
	PULONG32 *pThunkPointer,
	ULONG32  *pOriginalFuncAddr
#endif
	//ULONG_PRT和ULONG的关系是ULONG_PRT是为了X64兼容X32，，这些_PTR类型只是在32位应用程序上为32位宽，在64位应用程序上为64位宽的类型。就这么简单。
)
{
	//1.获取目标函数地址
	BOOL Status = FALSE;
	HMODULE hModule = LoadLibrary(szModuleName);


#ifdef _WIN64
	ULONG_PTR TargetFunAddr = (ULONG_PTR)GetProcAddress(hModule, szFuncName);
	PULONG_PTR lpAddr = NULL;
	SIZE_T size = sizeof(PULONG_PTR);
#else
	ULONG32  TargetFunAddr = (ULONG32)GetProcAddress(hModule, szFuncName);
	PULONG32 lpAddr = NULL;
	SIZE_T size = sizeof(PULONG32);
#endif

	printf("[*]Address of %s:0x%p\n", szFuncName, TargetFunAddr);
	printf("[*]Module To Hook at Base:0x%p\n", hModToHook);
	
	
	//2.获取导入表
	ULONG ulSize=0;
	PIMAGE_IMPORT_DESCRIPTOR pImportDescriptor = (PIMAGE_IMPORT_DESCRIPTOR)ImageDirectoryEntryToData(hModToHook,
		TRUE,
		IMAGE_DIRECTORY_ENTRY_IMPORT,
		&ulSize);
	printf("[*]Find ImportTable,Address:0x%p\n", pImportDescriptor);
	
	//3.寻找目标函数的ADDRESS
	char *szModName=NULL;
	while (pImportDescriptor->FirstThunk)
	{
		//存放DllName
		szModName = (char*)((PBYTE)hModToHook + pImportDescriptor->Name);
		printf("[*]Cur Module Name:%s\n", szModName);

		//比较DLLName与目标DLL是否相同  使用stricmp函数是不区分大小写的
		if (stricmp(szModName, szModuleName) != 0)
		{
			pImportDescriptor++;
			continue;
		}

		//当初始化IAT后，双链变成单链，只能使用FirstThunk进行查找.根据函数地址直接判断，所以这也是需要提前知道目标函数地址的原因
		PIMAGE_THUNK_DATA pThunkData = (PIMAGE_THUNK_DATA)((BYTE*)hModToHook + pImportDescriptor->FirstThunk);
		while (pThunkData->u1.Function)
		{
			/*------------------------------------
			typedef struct _IMAGE_THUNK_DATA32
			{
				union {
					DWORD ForwarderString;          // 一个RVA地址，指向forwarder string
					DWORD Function;                 // PDWORD，被导入的函数的入口地址
					DWORD Ordinal;                  // 该函数的序数
					DWORD AddressOfData;            // 一个RVA地址，指向IMAGE_IMPORT_BY_NAME
				}u1;
			} IMAGE_THUNK_DATA32;
			----------------------------------*/

			//此时IAT已经被填充成函数地址,可以使用*pThunkData作为目标函数地址
#ifdef  _WIN64
			lpAddr = (ULONG_PTR*)pThunkData;    
#else
			lpAddr = (ULONG32*)pThunkData;
#endif
			if ((*lpAddr) == TargetFunAddr)
			{
				printf("[*]Find target address!\n");
				DWORD dwOldProtect = NULL;
				if (VirtualProtect(lpAddr,size, PAGE_EXECUTE_READWRITE, &dwOldProtect))
				{
					if (pThunkPointer != NULL)   //保存修改内存的地址
					{
						*pThunkPointer = lpAddr;
					}
					if (pOriginalFuncAddr != NULL)   //保存修改内存的数据，也就是Target函数的地址
					{
						*pOriginalFuncAddr = *lpAddr;
					}

					//修改IAT数据
#ifdef  _WIN64
					*lpAddr = (ULONG_PTR)DetourFunc;
#else
					*lpAddr = (ULONG32)DetourFunc;
#endif

					
					Status = TRUE;
					printf("[*]lpAddr:%p,DetourFunc:%p", *lpAddr, DetourFunc);
					VirtualProtect(lpAddr, size, dwOldProtect, 0);
					printf("[*]Hook ok-->NewMessageBox:%x\n", *lpAddr);
				}
				break;
			}
			pThunkData++;   //下一个FirstThunk(函数)
		}
		if (Status)
			break;
		pImportDescriptor++;   //下一个IID(DLL)
	}

	FreeLibrary(hModule);
	return TRUE;
}

//DetourFun
int WINAPI My_MessageBoxA(
	HWND hWnd,
	LPCTSTR lpText,
	LPCTSTR lpCaption,
	UINT uType
)
{
	//1.你可以执行你指定的操作
	BOOL bReturn = FALSE;
	bReturn = OldMessageBox(NULL, "You Are Hooked", "Warning", MB_OK);
	
	//2.你可以控制API函数的返回值
	BOOL bReturn = FALSE;
	return bReturn;
}


