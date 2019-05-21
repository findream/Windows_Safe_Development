//���ֻ���ڱ������е�ʵ������Ҫ����̣�����ʹ��DLLע�룬��InlineHookд��DLL��Ȼ��dllע�����

#include "InlineHook_Jmp_MessageBox.h"

HOOK_DATA MsgBoxHookData;

int main(int agrc, char* argv[])
{
	MessageBoxA(NULL, "Before Inline Hook", "Test", MB_OK);
	if (!Inline_InstallHook())
	{
		printf("[*]Inline_InstallHook Failed\n");
		return FALSE;
	}
	//ʵ����HOOK
	MessageBoxA(NULL, "Before Inline Hook", "Test", MB_OK);
	if (!Inline_UninstallHook())
	{
		printf("[*]Inline_UnInstallHook Failed\n");
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
	//�޸Ĳ���
	int iResult = 0;
	lpText = "Hooked";
	iResult = OriginalMessageBox(hWnd, lpText, lpCaption, uType);
	
	//�޸ķ���ֵ
	iResult = 0;
	return iResult;
}

//����OriginalMessageBox
//ʹ������������ʽ
//Ϊ�˱�֤HOOK�ĳ����������Խ�����õ���HOOK�����
/*
MessageBoxA�Ĵ��뿪ͷ:
77D5050B >  8BFF                   mov edi,edi
77D5050D    55                     push ebp
77D5050E    8BEC                   mov ebp,esp
77D50510    833D 1C04D777 00       cmp dword ptr ds:[gfEMIEnable],0
*/

__declspec( naked )
int WINAPI OriginalMessageBox(HWND hWnd, LPCTSTR lpText, LPCTSTR lpCaption, UINT uType)
{
	_asm
	{
		//�ٴ�ִ��֮ǰ���޸ĵ�����ָ������ջ�쳣
		mov edi,edi
		push ebp
		mov ebp,esp
		jmp MsgBoxHookData.JmpBackAddr  //��ת��Hook֮��ĵط��������Լ���װ��HOOK,ʵ�ֳ�����
	}
}

BOOL Inline_InstallHook()
{
	ZeroMemory(&MsgBoxHookData, sizeof(HOOK_DATA));
	strcpy(MsgBoxHookData.szApiName, "MessageBoxA");
	strcpy(MsgBoxHookData.szModuleName, "user32.dll");
	MsgBoxHookData.HookCodelen = 5;
	//HOOK�ĵ�ַ
	MsgBoxHookData.HookPoint = (ULONG_PTR)GetAddress(MsgBoxHookData.szModuleName, MsgBoxHookData.szApiName);
	
	//TrampolineFun��ּ����ת��ԭ����
	//pfnTrampolineFun����jmp�ķ�ʽ���е���
	MsgBoxHookData.pfnTrampolineFun = (ULONG_PTR)OriginalMessageBox;

	//Detourfun
	MsgBoxHookData.pfnDetourFun = (ULONG_PTR)My_MessageBoxA;
	
	//��װHOOK
	BOOL bResult = FALSE;
	bResult = InstallCodeHook(&MsgBoxHookData);
	return bResult;
}

//��ȡ������ַ
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

//��װHOOK
BOOL InstallCodeHook(PHOOK_DATA pHookData)
{
	DWORD  dwBtyeReturned = 0;

	HANDLE hProcess = GetCurrentProcess();
	
	BOOL bResult = FALSE;
	if (pHookData == NULL
		|| pHookData->HookPoint == NULL
		|| pHookData->pfnDetourFun == NULL
		|| pHookData->pfnTrampolineFun == NULL)
	{
		return FALSE;
	}

	//�������תָ���ȡ��תָ�����ĵ�ַ
	//���������תָ�ֱ�ӷ��ز���
	pHookData->pfnTrampolineFun = SkipJmpAddress(pHookData->pfnTrampolineFun);

	//HOOK�㣬��movָ��
	pHookData->HookPoint = SkipJmpAddress(pHookData->HookPoint);

	//���ص�λ���Ѿ��޸ĵĵ�ַ֮��HookPoint+HookCodelen��
	pHookData->JmpBackAddr = pHookData->HookPoint + pHookData->HookCodelen;
	
	//�����Ҫ�޸ĵ�����
	pHookData->newEntry[0] = 0xE9;    //jmp
	*(ULONG*)(pHookData->newEntry + 1) = (ULONG)pHookData->pfnDetourFun - (ULONG)pHookData->HookPoint - 5;

	//����ԭʼ���ݵ�pHookData->oldEntry
	if (!ReadProcessMemory(hProcess, (LPCVOID)pHookData->HookPoint, pHookData->oleEntry, pHookData->HookCodelen, &dwBtyeReturned))
	{
		printf("[*]ReadProcessMemory:%d\n", GetLastError());
		return FALSE;
	}

	//�޸�HOOK���ݵ�pHookData->newEntry
	//������޸�������Ҫ�޸��ڴ汣��
	printf("[*]%p\n", pHookData->HookPoint);
	DWORD dwOldProtect = NULL;

	if (!WriteProcessMemory(hProcess, (LPVOID)pHookData->HookPoint, pHookData->newEntry, pHookData->HookCodelen, &dwBtyeReturned))
	{
		printf("[*]WriteProcessMemory:%d\n", GetLastError());
		return FALSE;
	}

	return TRUE;
}

//////////////////////////////////////
//����ǻ�ȡ��ַ������û������//
//////////////////////////////////////
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
		//Ŀ���ַ-��ǰ��ַ-5 = ƫ����
		//(ULONG_PTR)pFnΪ��ǰ��ַ
		//*(ULONG_PTR*)(pFn + 1)Ϊƫ����
		TrueAddress = (ULONG_PTR)pFn + *(ULONG_PTR*)(pFn + 1) + 5;
		return TrueAddress;
	}

	if (pFn[0] == 0xE8)
	{
		TrueAddress = (ULONG_PTR)pFn + pFn[1] + 2;
		return TrueAddress;
	}

	return (ULONG_PTR)uAddress;
}





BOOL Inline_UninstallHook()
{
	return UninstallCodeHook(&MsgBoxHookData);
}

BOOL UninstallCodeHook(PHOOK_DATA HookData)
{
	//���ǽ�HOOKʱ��������ݻָ���ԭ��ַ
	DWORD dwBytesReturn = 0;
	HANDLE hProcess = GetCurrentProcess();
	BOOL bResult = FALSE;
	if (HookData == NULL
		|| HookData->HookPoint == NULL
		|| HookData->oleEntry[0] == 0)
	{
		return bResult;
	}
	bResult = WriteProcessMemory(hProcess, (LPVOID)HookData->HookPoint, HookData->oleEntry, HookData->HookCodelen, &dwBytesReturn);
	if (!bResult)
	{
		printf("[*]WriteProcessMemory:%d\n", GetLastError());
		return bResult;
	}
	return bResult;
}


DWORD GetProcessIdByName(char *ProcessName)
{
	HANDLE hSnapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
	if (INVALID_HANDLE_VALUE == hSnapshot) {
		return NULL;
	}
	PROCESSENTRY32 pe = { sizeof(pe) };
	if (Process32First(hSnapshot, &pe))
	{
		do
		{
			if (!lstrcmp(pe.szExeFile, ProcessName))
			{
				CloseHandle(hSnapshot);
				printf("ProcessId:%d\n", pe.th32ProcessID);
				return pe.th32ProcessID;
			}
		} while (Process32Next(hSnapshot, &pe));
	}
	CloseHandle(hSnapshot);
	return 0;
}
