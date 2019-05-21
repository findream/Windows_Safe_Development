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
	HMODULE hModToHook,   //HOOK��ģ���ַ
	char* szFuncName,     //TargetFunName
	PVOID DetourFunc,     //HOOK������
	PULONG_PTR *pAddrPointer,   //EAT��ַ
	ULONG_PTR *pOriginalFuncAddr  //Target������ַ
);

BOOL WINAPI DetourFunc(
	HWND hWnd,          // handle of owner window
	LPCTSTR lpText,     // address of text in message box
	LPCTSTR lpCaption,  // address of title of message box
	UINT uType          // style of message box
);



