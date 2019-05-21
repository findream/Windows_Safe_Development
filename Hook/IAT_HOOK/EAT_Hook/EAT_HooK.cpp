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
	//��װִ��һ�ε���
	PFN_MessageBox pMsgBox = (PFN_MessageBox)GetProcAddress(GetModuleHandle("user32.dll"), "MessageBoxA");
	pMsgBox(NULL, "Test", "Warning", MB_OK);

}


BOOL InstallModuleEATHook(
	HMODULE hModToHook,   //HOOK��ģ���ַ
	char* szFuncName,     //TargetFunName
	PVOID DetourFunc,     //HOOK������
	PULONG_PTR *pAddrPointer,   //EAT��ַ
	ULONG_PTR *pOriginalFuncAddr  //Target������ַ
)
{
	//1.��ȡĿ�꺯����ַ
	ULONG_PTR TargetFunAddr = NULL;
	TargetFunAddr = (ULONG_PTR)GetProcAddress(hModToHook, szFuncName);
	
	//2.��ȡTarget������HookModule�ϵ�RVA
	ULONG_PTR TargetFunRVA = NULL;
	TargetFunRVA = (ULONG_PTR)(TargetFunAddr - (ULONG_PTR)hModToHook);

	printf("[*]Address of %s:0x%p  RVA = 0x%X\n", szFuncName, TargetFunAddr, TargetFunRVA);
	printf("[*]Module To Hook at Base:0x%p\n", hModToHook);

	//3.��ȡ������RVA 
	PIMAGE_EXPORT_DIRECTORY pExportDir = NULL;
	ULONG ulSize;
	pExportDir = (PIMAGE_EXPORT_DIRECTORY)ImageDirectoryEntryToData(hModToHook,//BaseAddress
		TRUE,
		IMAGE_DIRECTORY_ENTRY_EXPORT,   //Type
		&ulSize);                       //�������ݵĴ�С
	if (NULL == pExportDir)
	{
		printf("[*]pExportDir False:%d\n", GetLastError());
		return FALSE;
	}
	printf("[*]Address of ExportTable %p\n", pExportDir);
	
	//4.��ҪTargetFunc��EAT��ַ
	ULONG nFuncCnt = 0;
	nFuncCnt = pExportDir->NumberOfFunctions;  //��������
	
	ULONG* FuncAddr = NULL;
	FuncAddr = (ULONG*)((BYTE*)hModToHook + pExportDir->AddressOfFunctions);  //������������

	DWORD i = 0;
	BOOL bResult = FALSE;   //�޸Ľ��
	//5.��������������ַ����
	for (i = 0; i < nFuncCnt; i++)
	{
		//�ҵ�Target����
		if (FuncAddr[i] == TargetFunRVA)
		{
			//�޸��ڴ汣������
			DWORD OldProtect = NULL;
			if (VirtualProtect(&FuncAddr[i], sizeof(ULONG*), PAGE_EXECUTE_READWRITE, &OldProtect))
			{
				//6.�м����޸ĺ�����ַ֮ǰ����Ҫ����EAT��ַ��ԭ������ַ��
				*pAddrPointer = (PULONG_PTR)&FuncAddr[i];
				*pOriginalFuncAddr = FuncAddr[i];

				//7.��Detour������ַд��EAT
				//��ΪEAT���汣����Ǻ�����ַRVAֵ��������д��Detour������ַ��Ҫ��ȥBaseAddress
				FuncAddr[i] = (ULONG)((ULONG_PTR)DetourFunc-(ULONG_PTR)hModToHook);
				bResult = TRUE;
				VirtualProtect(&FuncAddr[i], sizeof(ULONG*), OldProtect, 0);
				printf("[*]HOOK OK,DetourFunAddress %p\n",FuncAddr[i]);
			}
		}
		if (bResult == TRUE)   //�޸������ǰ����
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