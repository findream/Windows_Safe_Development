#pragma once
#include <stdio.h>
#include <windows.h>
#include <imagehlp.h>

#pragma comment(lib,"imagehlp.lib")


typedef int
(WINAPI *PFN_MessageBox)(
	HWND hWnd,          // handle of owner window
	LPCTSTR lpText,     // address of text in message box
	LPCTSTR lpCaption,  // address of title of message box
	UINT uType          // style of message box
	);

BOOL WINAPI DetourFunc(
	HWND hWnd,          // handle of owner window
	LPCTSTR lpText,     // address of text in message box
	LPCTSTR lpCaption,  // address of title of message box
	UINT uType          // style of message box
);

BOOL InstallModuleEATHook(
	HMODULE hModToHook,   //HOOK的模块地址
	char* szFuncName,     //TargetFunName
	PVOID DetourFunc,     //HOOK处理函数
	PULONG_PTR *pAddrPointer,   //EAT地址
	ULONG_PTR *pOriginalFuncAddr  //Target函数地址
);

BOOL WINAPI DetourFunc(
	HWND hWnd,          // handle of owner window
	LPCTSTR lpText,     // address of text in message box
	LPCTSTR lpCaption,  // address of title of message box
	UINT uType          // style of message box
);



