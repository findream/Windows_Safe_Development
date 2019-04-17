#pragma once
#include <stdio.h>
#include <windows.h>
#include <string.h>


//函数定义
typedef BOOL(WINAPI *LPFUN_ISWOW64PROCESS)(HANDLE, PBOOL);
typedef int(WINAPI *PFN_MessageBoxA)(HWND hWnd, LPCTSTR lpText, LPCTSTR lpCaption, UINT uType);



BOOL IsWow64();
BOOL IAT_InstallHook();
VOID IAT_UnInstallHook();

BOOL InstallModuleIATHook(
	HMODULE hModToHook,   //待HOOK 的模块句柄
	char* szModuleName,   //待HOOK的模块名
	char* szFuncName,     //目标函数名称
	PVOID DetourFunc,     //Detour函数地址
	PULONG_PTR *pThunkPointer,  //用以接收指向修改的位置的指针
	ULONG_PTR *pOriginalFuncAddr   //用以接收原始函数地址
	//ULONG_PRT和ULONG的关系是ULONG_PRT是为了X64兼容X32，，这些_PTR类型只是在32位应用程序上为32位宽，在64位应用程序上为64位宽的类型。就这么简单。
);

//DetourFun
int WINAPI My_MessageBoxA(
	HWND hWnd,
	LPCTSTR lpText,
	LPCTSTR lpCaption,
	UINT uType
);

