# include "EAT_Hook.h"

int main(void)
{
	HMODULE hUser32 = LoadLibrary("user32.dll");
	PULONG_PTR pEATPionter = NULL;
	ULONG_PTR uOldRVA = NULL;
	MessageBox(NULL, "HookBefore", "warning", MB_OK);
	if (InstallModuleEATHook(hUser32, "MessageBoxA", DetourFunc, &pEATPionter, &uOldRVA))
	{
		printf("pEATPointer = 0x%X OldRVA = 0x%X\n", pEATPionter, uOldRVA);
		printf("Now Test the EAT Hook.\n");
	}
	//假装执行一次调用
	PFN_MessageBox pMsgBox = (PFN_MessageBox)GetProcAddress(GetModuleHandle("user32.dll"), "MessageBoxA");
	pMsgBox(NULL, "Test", "Warning", MB_OK);

}


BOOL InstallModuleEATHook(
	HMODULE hModToHook,   //HOOK的模块地址
	char* szFuncName,     //TargetFunName
	PVOID DetourFunc,     //HOOK处理函数
	PULONG_PTR *pAddrPointer,   //EAT地址
	ULONG_PTR *pOriginalFuncAddr  //Target函数地址
)
{
	//1.获取目标函数地址
	ULONG_PTR TargetFunAddr = NULL;
	TargetFunAddr = (ULONG_PTR)GetProcAddress(hModToHook, szFuncName);
	
	//2.获取Target函数在HookModule上的RVA
	ULONG_PTR TargetFunRVA = NULL;
	TargetFunRVA = (ULONG_PTR)(TargetFunAddr - (ULONG_PTR)hModToHook);

	printf("[*]Address of %s:0x%p  RVA = 0x%X\n", szFuncName, TargetFunAddr, TargetFunRVA);
	printf("[*]Module To Hook at Base:0x%p\n", hModToHook);

	//3.获取导出表RVA 
	PIMAGE_EXPORT_DIRECTORY pExportDir = NULL;
	ULONG ulSize;
	pExportDir = (PIMAGE_EXPORT_DIRECTORY)ImageDirectoryEntryToData(hModToHook,//BaseAddress
		TRUE,
		IMAGE_DIRECTORY_ENTRY_EXPORT,   //Type
		&ulSize);                       //接收数据的大小
	if (NULL == pExportDir)
	{
		printf("[*]pExportDir False:%d\n", GetLastError());
		return FALSE;
	}
	printf("[*]Address of ExportTable %p\n", pExportDir);
	
	//4.需要TargetFunc的EAT地址
	ULONG nFuncCnt = 0;
	nFuncCnt = pExportDir->NumberOfFunctions;  //函数个数
	
	ULONG* FuncAddr = NULL;
	FuncAddr = (ULONG*)((BYTE*)hModToHook + pExportDir->AddressOfFunctions);  //导出函数数组

	DWORD i = 0;
	BOOL bResult = FALSE;   //修改结果
	//5.遍历导出函数地址数组
	for (i = 0; i < nFuncCnt; i++)
	{
		//找到Target函数
		if (FuncAddr[i] == TargetFunRVA)
		{
			//修改内存保护属性
			DWORD OldProtect = NULL;
			if (VirtualProtect(&FuncAddr[i], sizeof(ULONG*), PAGE_EXECUTE_READWRITE, &OldProtect))
			{
				//6.切记在修改函数地址之前，需要保存EAT地址和原函数地址、
				*pAddrPointer = (PULONG_PTR)&FuncAddr[i];
				*pOriginalFuncAddr = FuncAddr[i];

				//7.将Detour函数地址写入EAT
				//因为EAT里面保存的是函数地址RVA值，所以在写入Detour函数地址需要减去BaseAddress
				FuncAddr[i] = (ULONG)((ULONG_PTR)DetourFunc-(ULONG_PTR)hModToHook);
				bResult = TRUE;
				VirtualProtect(&FuncAddr[i], sizeof(ULONG*), OldProtect, 0);
				printf("[*]HOOK OK,DetourFunAddress %p\n",FuncAddr[i]);
			}
		}
		if (bResult == TRUE)   //修改完成提前结束
			break;
	}
	return bResult;
}

BOOL WINAPI DetourFunc(
	HWND hWnd,          // handle of owner window
	LPCTSTR lpText,     // address of text in message box
	LPCTSTR lpCaption,  // address of title of message box
	UINT uType          // style of message box
)
{
	MessageBox(NULL, "Hooked", "warning", MB_OK);
	return TRUE;
}