//这个只是在本进程中的实例，需要跨进程，可以使用DLL注入，将InlineHook写入DLL，然后将dll注入进程

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
	//实际上HOOK
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




//第一步设置Detour函数
//Detour函数的函数声明需要和Target函数保持一致，否则函数返回会异常
int WINAPI My_MessageBoxA(HWND hWnd, LPCTSTR lpText, LPCTSTR lpCaption, UINT uType)
{
	//修改操作
	int iResult = 0;
	lpText = "Hooked";
	iResult = OriginalMessageBox(hWnd, lpText, lpCaption, uType);
	
	//修改返回值
	iResult = 0;
	return iResult;
}

//调用OriginalMessageBox
//使用内联汇编的形式
//为了保证HOOK的持续化，可以将会调用点在HOOK点后面
/*
MessageBoxA的代码开头:
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
		//再次执行之前被修改的三条指令，避免堆栈异常
		mov edi,edi
		push ebp
		mov ebp,esp
		jmp MsgBoxHookData.JmpBackAddr  //跳转到Hook之后的地方，跳过自己安装的HOOK,实现持续化
	}
}

BOOL Inline_InstallHook()
{
	ZeroMemory(&MsgBoxHookData, sizeof(HOOK_DATA));
	strcpy(MsgBoxHookData.szApiName, "MessageBoxA");
	strcpy(MsgBoxHookData.szModuleName, "user32.dll");
	MsgBoxHookData.HookCodelen = 5;
	//HOOK的地址
	MsgBoxHookData.HookPoint = (ULONG_PTR)GetAddress(MsgBoxHookData.szModuleName, MsgBoxHookData.szApiName);
	
	//TrampolineFun，旨在跳转回原函数
	//pfnTrampolineFun采用jmp的方式进行调用
	MsgBoxHookData.pfnTrampolineFun = (ULONG_PTR)OriginalMessageBox;

	//Detourfun
	MsgBoxHookData.pfnDetourFun = (ULONG_PTR)My_MessageBoxA;
	
	//安装HOOK
	BOOL bResult = FALSE;
	bResult = InstallCodeHook(&MsgBoxHookData);
	return bResult;
}

//获取函数地址
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

//安装HOOK
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

	//如果是跳转指令，获取跳转指令跟随的地址
	//如果不是跳转指令，直接返回参数
	pHookData->pfnTrampolineFun = SkipJmpAddress(pHookData->pfnTrampolineFun);

	//HOOK点，是mov指令
	pHookData->HookPoint = SkipJmpAddress(pHookData->HookPoint);

	//返回点位于已经修改的地址之后（HookPoint+HookCodelen）
	pHookData->JmpBackAddr = pHookData->HookPoint + pHookData->HookCodelen;
	
	//填充需要修改的内容
	pHookData->newEntry[0] = 0xE9;    //jmp
	*(ULONG*)(pHookData->newEntry + 1) = (ULONG)pHookData->pfnDetourFun - (ULONG)pHookData->HookPoint - 5;

	//保存原始数据到pHookData->oldEntry
	if (!ReadProcessMemory(hProcess, (LPCVOID)pHookData->HookPoint, pHookData->oleEntry, pHookData->HookCodelen, &dwBtyeReturned))
	{
		printf("[*]ReadProcessMemory:%d\n", GetLastError());
		return FALSE;
	}

	//修改HOOK数据到pHookData->newEntry
	//跨进程修改数据需要修改内存保护
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
//这块是获取地址，代码没看明白//
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
		//目标地址-当前地址-5 = 偏移量
		//(ULONG_PTR)pFn为当前地址
		//*(ULONG_PTR*)(pFn + 1)为偏移量
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
	//就是将HOOK时保存的数据恢复到原地址
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
