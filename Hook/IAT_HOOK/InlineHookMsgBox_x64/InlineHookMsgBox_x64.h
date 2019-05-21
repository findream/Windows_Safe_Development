#pragma once
#include <stdio.h>
#include <windows.h>
#include <string.h>

typedef struct _HOOK_DATA {
	char szApiName[128];	//��Hook��API����
	char szModuleName[128];	//��Hook��API����ģ�������
	int  HookCodeLen;		//Hook����
	BYTE oldEntry[16];		//����Hookλ�õ�ԭʼָ��
	BYTE newEntry[16];		//����Ҫд��Hookλ�õ���ָ��
	ULONG_PTR HookPoint;		//��HOOK��λ��
	ULONG_PTR JmpBackAddr;		//������ԭ�����еĵ�ַ
	ULONG_PTR pfnTrampolineFun;	//����ԭʼ������ͨ��
	ULONG_PTR pfnDetourFun;		//HOOK���˺���
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
