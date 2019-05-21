#include "InlineHookInjectVirtalAlloc.h"


LPVOID WINAPI DetourVirtualAllocEx(
	HANDLE hProcess,
	LPVOID lpAddress,
	SIZE_T dwSize,
	DWORD  flAllocationType,
	DWORD  flProtect
);

ULONG g_PointerToRawData = NULL;
ULONG g_RawOffset = NULL;

int main(int argc, char* argv[])
{
	TestHook();
	if(Inline_InstallHook())
		printf("[*]installHook Success\n");
	TestHook();
	if (Inline_UninstallHook())
		printf("[*]UninstallHook Success\n");
	TestHook();
}


void TestHook()
{
	LPVOID lpAddr = NULL;
	lpAddr=VirtualAlloc(NULL, 0x1000, MEM_COMMIT, PAGE_READWRITE);
	if (NULL != lpAddr)
	{
		MessageBox(NULL, "Before Hook", "Warning", MB_OK);
	}
}


LPVOID WINAPI DetourVirtualAllocEx(
	HANDLE hProcess,
	LPVOID lpAddress,
	SIZE_T dwSize,
	DWORD  flAllocationType,
	DWORD  flProtect
)
{
	//需要执行的操作
	MessageBox(NULL, "Hooked", "warning", MB_OK);

	LPVOID lpAddr = NULL;
	lpAddr = VirtualAllocEx(hProcess, lpAddress, dwSize, flAllocationType, flProtect);
	if (NULL == lpAddr)
	{
		printf("[*]VirtuallAllocEx Successed\n");
	}

	//控制返回值,这样不显示Before Hook
	lpAddr = NULL;

	return lpAddr;
}

BOOL Inline_InstallHook()
{
	ULONG addrTargetFun = (ULONG)GetProcAddress(LoadLibrary("kernel32.dll"), "VirtualAllocEx");
	//这个需要挨个遍历字节，所以使用PBYTE变量
	PBYTE pTargetFun = (PBYTE)GetProcAddress(LoadLibrary("kernel32.dll"), "VirtualAlloc");
	printf("[*]pTargetFun:%p", pTargetFun);
	//保存临时地址
	ULONG addrTemp = NULL;
	DWORD i = 0;
	BOOL bResult = FALSE;
	do
	{
		if (pTargetFun[0] == 0xE8)
		{
			//获取VirtualAllocEx地址
			addrTemp = (ULONG)pTargetFun + 5 + *(LONG*)(pTargetFun + 1);
			if (addrTemp == addrTargetFun)
			{
				bResult = TRUE;
				break;
			}
		}
		i++;
		pTargetFun++;

	} while (i < 0x30);
	//确定这是VirtualAlloc的地址
	if (bResult)
	{
		//保存修改的地址
		g_PointerToRawData = (ULONG)(pTargetFun + 1);
		//保存修改的内容
		g_RawOffset = *(ULONG*)(pTargetFun + 1);
		//保存Detour函数到Target函数的偏移量
		addrTemp= (LONG)DetourVirtualAllocEx - (LONG)pTargetFun - 5;

		//修改
		bResult = WriteProcessMemory(GetCurrentProcess(), pTargetFun + 1, &addrTemp, sizeof(LONG), NULL);
	}
	return bResult;
}

BOOL Inline_UninstallHook()
{
	return WriteProcessMemory(GetCurrentProcess(), (LPVOID)(g_PointerToRawData), &g_RawOffset, sizeof(LONG), NULL);
}