#pragma once
#include <stdio.h>
#include <windows.h>
#include <string.h>

//定义如下结构，保存一次InlineHook所需要的信息
typedef struct _HOOK_DATA {
	char szApiName[128];	//待Hook的API名字
	char szModuleName[128];	//待Hook的API所属模块的名字
	int  HookCodeLen;		//Hook长度
	BYTE oldEntry[8];		//保存Hook位置的原始指令
	BYTE newEntry[8];		//保存要写入Hook位置的新指令
	BYTE HotPatchCode[8];	//用于HotPatch式Hook
	ULONG_PTR HookPoint;		//待HOOK的位置
	ULONG_PTR JmpBackAddr;		//回跳到原函数中的地址
	ULONG_PTR pfnTrampolineFun;	//调用原始函数的通道
	ULONG_PTR pfnDetourFun;		//HOOK过滤函数
}HOOK_DATA, *PHOOK_DATA;

int WINAPI My_MessageBoxA(HWND hWnd, LPCTSTR lpText, LPCTSTR lpCaption, UINT uType);

int WINAPI TrampolineMessageBox(HWND hWnd, LPCTSTR lpText, LPCTSTR lpCaption, UINT uType);

BOOL Inline_InstallHook();

BOOL UninstallCodeHook(PHOOK_DATA pHookData);

void InitHookEntry(PHOOK_DATA pHookData);
BOOL Inline_UninstallHook();


LPVOID GetAddress(char *dllname, char *funname);

BOOL UninstallCodeHook(PHOOK_DATA MsgBoxHookData);

BOOL InstallCodeHook(PHOOK_DATA MsgBoxHookData);

ULONG_PTR SkipJmpAddress(ULONG_PTR uAddress);