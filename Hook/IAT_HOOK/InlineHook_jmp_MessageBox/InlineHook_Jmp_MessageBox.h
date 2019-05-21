#pragma once
#include <stdio.h>
#include <windows.h>
#include <string.h>
#include <tlhelp32.h>


typedef struct _HOOK_DATA
{
	char szApiName[128];   //TargetFun
	char szModuleName[64]; //TargetModule
	int HookCodelen;       //HOOK长度
	BYTE oleEntry[16];     //保存HOOK原始指令
	BYTE newEntry[16];     //保存HOOK新指令
	ULONG_PTR HookPoint;   //被HOOK的地址
	ULONG_PTR JmpBackAddr; //回跳的地址，可以多次使用
	ULONG_PTR pfnTrampolineFun;    //跳转到原函数执行的函数
	ULONG_PTR pfnDetourFun;   //Detour函数
}HOOK_DATA,*PHOOK_DATA;


//函数声明
int WINAPI My_MessageBoxA(HWND hWnd, LPCTSTR lpText, LPCTSTR lpCaption, UINT uType);

int WINAPI OriginalMessageBox(HWND hWnd, LPCTSTR lpText, LPCTSTR lpCaption, UINT uType);

BOOL Inline_InstallHook();

LPVOID GetAddress(char *dllname, char *funname);

BOOL InstallCodeHook(PHOOK_DATA pHookData);

ULONG_PTR SkipJmpAddress(ULONG_PTR uAddress);

BOOL Inline_UninstallHook();

BOOL UninstallCodeHook(PHOOK_DATA HookData);

DWORD GetProcessIdByName(char *ProcessName);
