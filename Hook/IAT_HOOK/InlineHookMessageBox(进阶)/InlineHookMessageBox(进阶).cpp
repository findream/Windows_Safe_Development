//������̺���һ��������һ����
//�ص���Hotpatch��ʹ��

#include "InlineHookMessageBox(����).h"

HOOK_DATA MsgBoxHookData;
#define HOOKCODELEN 2

int main(int agrc, char* argv[])
{
	MessageBox(NULL, "Before", "warning", MB_OK);
	if (!Inline_InstallHook())
	{
		printf("[*]InstallHook failed\n");
		return FALSE;
	}
	MessageBox(NULL, "Before", "warning", MB_OK);
	if (!Inline_UninstallHook())
	{
		printf("[*]UnInstallHook failed\n");
	}
	MessageBox(NULL, "Before", "warning", MB_OK);
}


//Step1 ����Detour����
int WINAPI My_MessageBoxA(HWND hWnd, LPCTSTR lpText, LPCTSTR lpCaption, UINT uType)
{
	int iResult = 0;

	//ִ���Զ���Ĳ���
	lpText = "Hooked";
	lpCaption = "warning";

	//����TrampolineFun
	iResult = TrampolineMessageBox(hWnd, lpText, lpCaption, uType);

	//�޸ķ��ؽ��
	iResult = 0;
	printf("iResult is %p...\n", iResult);
	return iResult;
}

//TrampolineFun
__declspec(naked)
int WINAPI TrampolineMessageBox(HWND hWnd, LPCTSTR lpText, LPCTSTR lpCaption, UINT uType)
{
	//���7���ֽڣ������߸�
	_asm
	{
		nop
		nop
		nop
		nop
		nop
		nop
		nop
		jmp MsgBoxHookData.JmpBackAddr
	}
}


BOOL Inline_InstallHook()
{
	//��ʼ��HOOK_DATA�ṹ��
	ZeroMemory(&MsgBoxHookData, sizeof(HOOK_DATA));
	strcpy(MsgBoxHookData.szApiName, "MessageBoxA");
	strcpy(MsgBoxHookData.szModuleName, "user32.dll");
	MsgBoxHookData.HookPoint = (ULONG_PTR)GetAddress(MsgBoxHookData.szModuleName, MsgBoxHookData.szApiName);
	MsgBoxHookData.pfnDetourFun = (ULONG_PTR)My_MessageBoxA;
	MsgBoxHookData.pfnTrampolineFun = (ULONG_PTR)TrampolineMessageBox;
	MsgBoxHookData.HookCodeLen = HOOKCODELEN;
	return InstallCodeHook(&MsgBoxHookData);


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

BOOL InstallCodeHook(PHOOK_DATA MsgBoxHookData)
{
	//�������Ϸ���
	if (MsgBoxHookData == NULL
		|| MsgBoxHookData->pfnTrampolineFun == NULL
		|| MsgBoxHookData->pfnDetourFun == NULL)
	{
		return FALSE;
	}

	//�������תָ���ȡ��תָ�����ĵ�ַ
	//���������תָ�ֱ�ӷ��ز���
	//MsgBoxHookData->pfnTrampolineFun = SkipJmpAddress(MsgBoxHookData->pfnTrampolineFun);

	//HOOK�㣬��movָ��
	//MsgBoxHookData->HookPoint = SkipJmpAddress(MsgBoxHookData->HookPoint);

	//���÷��ص�
	MsgBoxHookData->JmpBackAddr = MsgBoxHookData->HookPoint + MsgBoxHookData->HookCodeLen;

	//����Ƿ�HOOK��
	PBYTE pfnHead = (PBYTE)MsgBoxHookData->HookPoint;
	printf("%p   %p",pfnHead, MsgBoxHookData->HookPoint);
	if (!memcmp(pfnHead, "\x8B\xFF\x55\x8B\xEC", 5)
		|| (pfnHead[0] == 0x6A && pfnHead[5] != 0x68))
	{
		//Step2 ����޸�����
		InitHookEntry(MsgBoxHookData);

	}
	else
	{
		printf("[*]%p has already Hooked\n", pfnHead);
		return FALSE;
	}

	//Step3 ����ԭʼ����
	//jmp mov-jmp��push-ret���ַ�����HotPatch���в�ͬ���ֿ�����
	SIZE_T lpNumberOfBytesRead = 0;
	if (!ReadProcessMemory(GetCurrentProcess(), (LPCVOID)MsgBoxHookData->HookPoint, MsgBoxHookData->oldEntry, 8, &lpNumberOfBytesRead))
	{
		printf("[*]ReadProcessMemory:%d", GetLastError());
		return FALSE;
	}

	//Step4 ���TrampolineFun������
	//���ݲ�ͬ��ָ��
	if (MsgBoxHookData->HookCodeLen != 2)
	{
		SIZE_T lpNumberOfBytesWrite = 0;
		if (!WriteProcessMemory(GetCurrentProcess(), (LPVOID)MsgBoxHookData->pfnTrampolineFun, MsgBoxHookData->oldEntry, MsgBoxHookData->HookCodeLen, &lpNumberOfBytesWrite))
		{
			printf("[*]WriteProcessMemory:%d", GetLastError());
			return FALSE;
		}
	}

	/*����һ��HotPatch�����ڱ�׼�������ô���������ʽ���ֱ��ǲ�����SEH���ʹ���SEH��
	1.������SEH
		mov edi,edi
		push ebp
		mov ebp,esp��5���ֽڣ�
	2.����SEH
		push 10
		push xxxx
		call xxx��2+5+5��
	ͬʱҲ����ʹ��HotPathch���ַ�����
	ԭ�����£�
	     ��Ϊ��API�������nop����int3����Щָ��ͨ����΢������ʵ��HotPatch�ġ�
		 ����ʹ�ó�������ϵķ�ʽռ���Ϸ���nopʵ��Hook��
		 1.ʹ�ö�����HookPoint����5���ֽ�HotPatchCode��
		 2.Ȼ��ʹ�ó�����DetourFun
	*/

	// Step 5 ��HookPointд������
	PBYTE pAddrToWrite = NULL;
	SIZE_T lpNumberOfBytesWrite = 0;
	if (MsgBoxHookData->HookCodeLen == 2)   //[�ص�]HotPatch
	{
		pAddrToWrite = (PBYTE)MsgBoxHookData->HookPoint - 5;
		if (!WriteProcessMemory(GetCurrentProcess(), pAddrToWrite, MsgBoxHookData->HotPatchCode, 5, &lpNumberOfBytesWrite))
		{
			printf("[*]WriteProcessMemory:%d", GetLastError());
			return FALSE;
		}
		//�ﵽ��Ҫд��ĵ�ַ
		pAddrToWrite += 5;
		if (!WriteProcessMemory(GetCurrentProcess(), pAddrToWrite, MsgBoxHookData->newEntry, MsgBoxHookData->HookCodeLen, &lpNumberOfBytesWrite))
		{
			printf("[*]WriteProcessMemory:%d", GetLastError());
			return FALSE;
		}

	}
	else                                    //else
	{
		pAddrToWrite = (PBYTE)MsgBoxHookData->HookPoint;

		if (!WriteProcessMemory(GetCurrentProcess(), pAddrToWrite, MsgBoxHookData->newEntry, MsgBoxHookData->HookCodeLen, &lpNumberOfBytesWrite))
		{
			printf("[*]WriteProcessMemory:%d", GetLastError());
			return FALSE;
		}
	}


	return TRUE;
}

void InitHookEntry(PHOOK_DATA MsgBoxHookData)
{
	//����HookCodeLen��������ͬ�ķ���
	switch (MsgBoxHookData->HookCodeLen)
	{
		case 2:   //HOTPATCH
		{
			
			/*
			77D507E5   >-/E9 66086B88      jmp InlineHo.00401050
			77D507EA > $^\EB F9            jmp short USER32.77D507E5
			*/
			MsgBoxHookData->newEntry[0] = 0xEB; //Jmp -5
			MsgBoxHookData->newEntry[1] = 0xF9;
			MsgBoxHookData->HotPatchCode[0] = 0xE9; //Jmp
			*(ULONG*)(MsgBoxHookData->HotPatchCode + 1) = (ULONG)MsgBoxHookData->pfnDetourFun - ((ULONG)MsgBoxHookData->HookPoint - 5) - 5;//0xE9 ʽjmp�ļ���
			break;
		}
		case 5:   //jmp
		{
			MsgBoxHookData->newEntry[0] = '\xE9';
			*(ULONG_PTR*)(MsgBoxHookData->newEntry + 1) = (ULONG_PTR)MsgBoxHookData->pfnDetourFun - (ULONG_PTR)MsgBoxHookData->HookPoint - 5;
			break;

		}
		case 6:    //push-retn
		{
			/*
			0040E9D1 >    68 44332211      push 112230344
			0040E9D6      C3               retn
			*/
			//�������Ƚ�����Ҫ�޸ĵ�6���ֽ�ȫ�����ƣ�Ȼ�󽫵ڶ����ֽڵ�Detourhan������ַ�޸�
			//Ҳ��������
			/*
			MsgBoxHookData->newEntry[0]='\x68';
			*(LONG_PTR*)(MsgBoxHookData->newEntry + 1) = (ULONG)MsgBoxHookData->pfnDetourFun;
			MsgBoxHookData->newEntry[5]='\xC3';
			*/
			memcpy(MsgBoxHookData->newEntry, "\x68\x44\x33\x22\x11\xC3",5);
			*(LONG_PTR*)(MsgBoxHookData->newEntry + 1) = (ULONG)MsgBoxHookData->pfnDetourFun;
			break;
		}
		case 7:   //mov-jmp
		{   
			/*
			B8 44332211        mov eax, 11223344
			FFE0               jmp eax
			*/
			memcpy(MsgBoxHookData->newEntry, "\xB8\x44\x33\x22\x11\xFF\xE0 ", 7);
			*(LONG_PTR*)(MsgBoxHookData->newEntry + 1) = (ULONG)MsgBoxHookData->pfnDetourFun;
			break;
		}	
		default:
			break;

	}
}

BOOL Inline_UninstallHook()
{
	return UninstallCodeHook(&MsgBoxHookData);
}

BOOL UninstallCodeHook(PHOOK_DATA MsgBoxHookData)
{
	SIZE_T lpNumberOfBytesWritten = NULL;
	BOOL bReturn = FALSE;
	bReturn = WriteProcessMemory(GetCurrentProcess(), (LPVOID)MsgBoxHookData->HookPoint, MsgBoxHookData->oldEntry, MsgBoxHookData->HookCodeLen, &lpNumberOfBytesWritten);
	if (!bReturn)
	{
		printf("[*]WriteProcessMemory:%d\n", GetLastError());
		return bReturn;
	}
	return bReturn;

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