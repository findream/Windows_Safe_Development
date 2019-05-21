#pragma once
#include <stdio.h>
#include <windows.h>
#include <string.h>

//�������½ṹ������һ��InlineHook����Ҫ����Ϣ
typedef struct _HOOK_DATA {
	char szApiName[128];	//��Hook��API����
	char szModuleName[128];	//��Hook��API����ģ�������
	int  HookCodeLen;		//Hook����
	BYTE oldEntry[8];		//����Hookλ�õ�ԭʼָ��
	BYTE newEntry[8];		//����Ҫд��Hookλ�õ���ָ��
	BYTE HotPatchCode[8];	//����HotPatchʽHook
	ULONG_PTR HookPoint;		//��HOOK��λ��
	ULONG_PTR JmpBackAddr;		//������ԭ�����еĵ�ַ
	ULONG_PTR pfnTrampolineFun;	//����ԭʼ������ͨ��
	ULONG_PTR pfnDetourFun;		//HOOK���˺���
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