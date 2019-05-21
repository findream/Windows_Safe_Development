#pragma once
#include <stdio.h>
#include <windows.h>
#include <string.h>
#include <tlhelp32.h>


typedef struct _HOOK_DATA
{
	char szApiName[128];   //TargetFun
	char szModuleName[64]; //TargetModule
	int HookCodelen;       //HOOK����
	BYTE oleEntry[16];     //����HOOKԭʼָ��
	BYTE newEntry[16];     //����HOOK��ָ��
	ULONG_PTR HookPoint;   //��HOOK�ĵ�ַ
	ULONG_PTR JmpBackAddr; //�����ĵ�ַ�����Զ��ʹ��
	ULONG_PTR pfnTrampolineFun;    //��ת��ԭ����ִ�еĺ���
	ULONG_PTR pfnDetourFun;   //Detour����
}HOOK_DATA,*PHOOK_DATA;


//��������
int WINAPI My_MessageBoxA(HWND hWnd, LPCTSTR lpText, LPCTSTR lpCaption, UINT uType);

int WINAPI OriginalMessageBox(HWND hWnd, LPCTSTR lpText, LPCTSTR lpCaption, UINT uType);

BOOL Inline_InstallHook();

LPVOID GetAddress(char *dllname, char *funname);

BOOL InstallCodeHook(PHOOK_DATA pHookData);

ULONG_PTR SkipJmpAddress(ULONG_PTR uAddress);

BOOL Inline_UninstallHook();

BOOL UninstallCodeHook(PHOOK_DATA HookData);

DWORD GetProcessIdByName(char *ProcessName);
