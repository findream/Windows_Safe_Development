# include "InlineHookMsgBox_x64.h"

HOOK_DATA MsgBoxHookData;

int main(int argc, char* agrv[])
{
	MessageBoxA(NULL, "Before Inline Hook", "Test", MB_OK);
	if (!Inline_InstallHook())
	{
		printf("InstallHook Failed\n");
		return FALSE;
	}
	MessageBoxA(NULL, "Before Inline Hook", "Test", MB_OK);
	if (!Inline_UnInstallHook())
	{
		printf("UninstallHook Failed\n");
		return FALSE;
	}
	MessageBoxA(NULL, "Before Inline Hook", "Test", MB_OK);
	getchar();
	return 0;
}

//��һ������Detour����
//Detour�����ĺ���������Ҫ��Target��������һ�£����������ػ��쳣
int WINAPI My_MessageBoxA(HWND hWnd, LPCTSTR lpText, LPCTSTR lpCaption, UINT uType)
{
	int ret;
	char newText[1024] ="Hook";
	char newCaption[256] = "warning";
	PFN_MessageBoxA OriginalMessageBox = (PFN_MessageBoxA)MsgBoxHookData.pfnTrampolineFun;
	printf("���˵���MessageBox!\n");
	uType = MB_OK;
	ret = OriginalMessageBox(hWnd, newText, newCaption, uType);//����ԭMessageBox�������淵��ֵ
	//����ԭ����֮�󣬿��Լ�����OUT(�����)�������и���,�������纯����recv�����Ը��淵�ص�����
	return ret;//�����㻹���Ը���ԭʼ�����ķ���ֵ
}


BOOL Inline_InstallHook()
{
	ZeroMemory(&MsgBoxHookData, sizeof(HOOK_DATA));
	strcpy(MsgBoxHookData.szApiName, "MessageBoxA");
	strcpy(MsgBoxHookData.szModuleName, "user32.dll");
	MsgBoxHookData.HookCodeLen = 14;   //64Ϊ����ϵͳ���޸ĵ�ָ��ȱ��
	MsgBoxHookData.HookPoint = (ULONG_PTR)GetAddress(MsgBoxHookData.szModuleName, MsgBoxHookData.szApiName);//HOOK�ĵ�ַ

	//TrampolineFun
	//x64�²�����������ˣ���������һ���ڴ�����TrampolineFun��shellcode
	MsgBoxHookData.pfnTrampolineFun = (ULONG_PTR)VirtualAlloc(NULL, 128, MEM_COMMIT, PAGE_EXECUTE_READWRITE);

	//DetourFun
	MsgBoxHookData.pfnDetourFun = (ULONG_PTR)My_MessageBoxA;

	//HOOK
	return  InstallHookData(&MsgBoxHookData);
}

LPVOID GetAddress(char *dllname, char *funname)
{
	HMODULE hMod = 0;
	if (hMod = GetModuleHandle(dllname))
	{
		return GetProcAddress(hMod, funname);
	}
	else
	{
		hMod = LoadLibrary(dllname);
		return GetProcAddress(hMod, funname);
	}
}

BOOL InstallHookData(PHOOK_DATA pHookData)
{
	//�Ϸ������
	if (pHookData == NULL
		|| pHookData->HookPoint == 0
		|| pHookData->pfnDetourFun == NULL
		|| pHookData->pfnTrampolineFun == NULL)
	{
		return FALSE;
	}

//	pHookData->HookPoint = SkipJmpAddress(pHookData->HookPoint); //���������ͷ����ת����ô��������
	pHookData->JmpBackAddr = pHookData->HookPoint + pHookData->HookCodeLen;

	//���HookEntry
	//64λjmp
	memset(pHookData->newEntry, 0, 14);
	pHookData->newEntry[0] = 0xFF;
	pHookData->newEntry[1] = 0x25;
	//2-5��ȫ0
	*(ULONG_PTR*)(pHookData->newEntry + 6) = (ULONG_PTR)pHookData->pfnDetourFun;

	//���Trampoline
		//����ǰ14���ֽ�
	PBYTE pFun = (PBYTE)pHookData->pfnTrampolineFun;
	memcpy(pFun, (PVOID)(pHookData->HookPoint), 14);

	//���ڵ�����ָ�������ض�λ���ݣ�����������Ҫ�޸�һ��
	//���õİ취��ʹ�÷�����������ж��Ƿ����ض�λ����
//////////////////////////////////////////////////////
//����                                              //
//////////////////////////////////////////////////////
	/*ULONG DataOffset = 0;
	ULONG_PTR pData = (ULONG_PTR)pHookData->HookPoint + 7 + 7 + *(ULONG*)(pHookData->HookPoint + 10);
	printf("pData = 0x%p\n", pData);
	DataOffset = (ULONG)(pData - ((ULONG_PTR)pFun + 14));
	*(ULONG*)(pFun + 10) = DataOffset;*/

	//��Trampoline�����ĵص�����ΪFun+14�����Ա��ƹ�HookPoint
	pFun += 14;
	pFun[0] =0xFF;
	pFun[1] = 0x25;
	*(ULONG_PTR*)(pFun + 6) = pHookData->JmpBackAddr;

	//�޸�HookPoint
	SIZE_T dwBytesReturned = 0;
	BOOL bResult = FALSE;
	if (ReadProcessMemory(GetCurrentProcess(),(LPCVOID) pHookData->HookPoint, pHookData->oldEntry, pHookData->HookCodeLen, &dwBytesReturned))
	{
		if (WriteProcessMemory(GetCurrentProcess(), (LPVOID)pHookData->HookPoint, pHookData->newEntry, pHookData->HookCodeLen, &dwBytesReturned))
		{
			printf("Install Hook write OK! WrittenCnt=%d\n", dwBytesReturned);
			bResult = TRUE;
		}
	}
	return bResult;

}


BOOL Inline_UnInstallHook()
{
	return UninstallCodeHook(&MsgBoxHookData);
}

BOOL UninstallCodeHook(PHOOK_DATA HookData)
{
	SIZE_T dwBytesReturned = 0;
	BOOL bResult = FALSE;
	LPVOID OriginalAddr;
	if (HookData == NULL
		|| HookData->HookPoint == 0
		|| HookData->oldEntry[0] == 0)
	{
		return FALSE;
	}
	bResult = WriteProcessMemory(GetCurrentProcess(), (LPVOID)HookData->HookPoint, HookData->oldEntry, HookData->HookCodeLen, &dwBytesReturned);
	return bResult;
}


ULONG_PTR SkipJmpAddress(ULONG_PTR uAddress)
{
	ULONG_PTR TrueAddress = 0;
	PBYTE pFn = (PBYTE)uAddress;

	if (memcmp(pFn, "\xFF\x25", 2) == 0)
	{
		TrueAddress = *(ULONG_PTR*)(pFn + 2);
		return TrueAddress;
	}

	if (pFn[0] == 0xE9)
	{
		TrueAddress = (ULONG_PTR)pFn + *(ULONG_PTR*)(pFn + 1) + 5;
		return TrueAddress;
	}

	if (pFn[0] == 0xEB)
	{
		TrueAddress = (ULONG_PTR)pFn + pFn[1] + 2;
		return TrueAddress;
	}

	return (ULONG_PTR)uAddress;
}

