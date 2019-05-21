//这个例程和上一个基本是一样的
//重点在Hotpatch的使用

#include "InlineHookMessageBox(进阶).h"

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


//Step1 构造Detour函数
int WINAPI My_MessageBoxA(HWND hWnd, LPCTSTR lpText, LPCTSTR lpCaption, UINT uType)
{
	int iResult = 0;

	//执行自定义的操作
	lpText = "Hooked";
	lpCaption = "warning";

	//调用TrampolineFun
	iResult = TrampolineMessageBox(hWnd, lpText, lpCaption, uType);

	//修改返回结果
	iResult = 0;
	printf("iResult is %p...\n", iResult);
	return iResult;
}

//TrampolineFun
__declspec(naked)
int WINAPI TrampolineMessageBox(HWND hWnd, LPCTSTR lpText, LPCTSTR lpCaption, UINT uType)
{
	//最长是7个字节，留足七个
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
	//初始化HOOK_DATA结构体
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
	//检查参数合法性
	if (MsgBoxHookData == NULL
		|| MsgBoxHookData->pfnTrampolineFun == NULL
		|| MsgBoxHookData->pfnDetourFun == NULL)
	{
		return FALSE;
	}

	//如果是跳转指令，获取跳转指令跟随的地址
	//如果不是跳转指令，直接返回参数
	//MsgBoxHookData->pfnTrampolineFun = SkipJmpAddress(MsgBoxHookData->pfnTrampolineFun);

	//HOOK点，是mov指令
	//MsgBoxHookData->HookPoint = SkipJmpAddress(MsgBoxHookData->HookPoint);

	//设置返回点
	MsgBoxHookData->JmpBackAddr = MsgBoxHookData->HookPoint + MsgBoxHookData->HookCodeLen;

	//检查是否被HOOK过
	PBYTE pfnHead = (PBYTE)MsgBoxHookData->HookPoint;
	printf("%p   %p",pfnHead, MsgBoxHookData->HookPoint);
	if (!memcmp(pfnHead, "\x8B\xFF\x55\x8B\xEC", 5)
		|| (pfnHead[0] == 0x6A && pfnHead[5] != 0x68))
	{
		//Step2 填充修改数据
		InitHookEntry(MsgBoxHookData);

	}
	else
	{
		printf("[*]%p has already Hooked\n", pfnHead);
		return FALSE;
	}

	//Step3 保存原始数据
	//jmp mov-jmp，push-ret三种方法和HotPatch大有不同，分开讨论
	SIZE_T lpNumberOfBytesRead = 0;
	if (!ReadProcessMemory(GetCurrentProcess(), (LPCVOID)MsgBoxHookData->HookPoint, MsgBoxHookData->oldEntry, 8, &lpNumberOfBytesRead))
	{
		printf("[*]ReadProcessMemory:%d", GetLastError());
		return FALSE;
	}

	//Step4 填充TrampolineFun函数。
	//根据不同的指令
	if (MsgBoxHookData->HookCodeLen != 2)
	{
		SIZE_T lpNumberOfBytesWrite = 0;
		if (!WriteProcessMemory(GetCurrentProcess(), (LPVOID)MsgBoxHookData->pfnTrampolineFun, MsgBoxHookData->oldEntry, MsgBoxHookData->HookCodeLen, &lpNumberOfBytesWrite))
		{
			printf("[*]WriteProcessMemory:%d", GetLastError());
			return FALSE;
		}
	}

	/*讲解一下HotPatch：由于标准函数调用存在两种形式，分别是不存在SEH，和存在SEH的
	1.不存在SEH
		mov edi,edi
		push ebp
		mov ebp,esp（5个字节）
	2.存在SEH
		push 10
		push xxxx
		call xxx（2+5+5）
	同时也可以使用HotPathch这种方法。
	原理如下：
	     因为在API上面存在nop或者int3，这些指令通常是微软用于实现HotPatch的。
		 可以使用长短跳结合的方式占用上方的nop实现Hook，
		 1.使用短跳到HookPoint上面5个字节HotPatchCode处
		 2.然后使用长跳到DetourFun
	*/

	// Step 5 向HookPoint写入数据
	PBYTE pAddrToWrite = NULL;
	SIZE_T lpNumberOfBytesWrite = 0;
	if (MsgBoxHookData->HookCodeLen == 2)   //[重点]HotPatch
	{
		pAddrToWrite = (PBYTE)MsgBoxHookData->HookPoint - 5;
		if (!WriteProcessMemory(GetCurrentProcess(), pAddrToWrite, MsgBoxHookData->HotPatchCode, 5, &lpNumberOfBytesWrite))
		{
			printf("[*]WriteProcessMemory:%d", GetLastError());
			return FALSE;
		}
		//达到需要写入的地址
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
	//根据HookCodeLen来决定不同的方法
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
			*(ULONG*)(MsgBoxHookData->HotPatchCode + 1) = (ULONG)MsgBoxHookData->pfnDetourFun - ((ULONG)MsgBoxHookData->HookPoint - 5) - 5;//0xE9 式jmp的计算
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
			//本样例先将所需要修改的6个字节全部复制，然后将第二个字节的Detourhan函数地址修改
			//也可以这样
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