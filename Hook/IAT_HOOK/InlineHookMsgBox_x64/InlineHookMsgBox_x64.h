#pragma once
#include <stdio.h>
#include <windows.h>
#include <string.h>

typedef struct _HOOK_DATA {
	char szApiName[128];	//待Hook的API名字
	char szModuleName[128];	//待Hook的API所属模块的名字
	int  HookCodeLen;		//Hook长度
	BYTE oldEntry[16];		//保存Hook位置的原始指令
	BYTE newEntry[16];		//保存要写入Hook位置的新指令
	ULONG_PTR HookPoint;		//待HOOK的位置
	ULONG_PTR JmpBackAddr;		//回跳到原函数中的地址
	ULONG_PTR pfnTrampolineFun;	//调用原始函数的通道
	ULONG_PTR pfnDetourFun;		//HOOK过滤函数
}HOOK_DATA, *PHOOK_DATA;

typedef int
(WINAPI *PFN_MessageBoxA)(
	HWND hWnd,
	LPCTSTR lpText,
	LPCTSTR lpCaption,
	UINT uType
	);

//DetorFun
int WINAPI My_MessageBoxA(HWND hWnd, LPCTSTR lpText, LPCTSTR lpCaption, UINT uType);

//TrampolineFun
int WINAPI OriginalMessageBox(HWND hWnd, LPCTSTR lpText, LPCTSTR lpCaption, UINT uType);

LPVOID GetAddress(char *dllname, char *funname);

BOOL InstallHookData(PHOOK_DATA MsgBoxHookData);

BOOL Inline_InstallHook();

BOOL Inline_UnInstallHook();
BOOL UninstallCodeHook(PHOOK_DATA HookData);

ULONG_PTR SkipJmpAddress(ULONG_PTR uAddress);
