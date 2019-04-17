#pragma once
#include <stdio.h>
#include <windows.h>
#include <string.h>


//��������
typedef BOOL(WINAPI *LPFUN_ISWOW64PROCESS)(HANDLE, PBOOL);
typedef int(WINAPI *PFN_MessageBoxA)(HWND hWnd, LPCTSTR lpText, LPCTSTR lpCaption, UINT uType);



BOOL IsWow64();
BOOL IAT_InstallHook();
VOID IAT_UnInstallHook();

BOOL InstallModuleIATHook(
	HMODULE hModToHook,   //��HOOK ��ģ����
	char* szModuleName,   //��HOOK��ģ����
	char* szFuncName,     //Ŀ�꺯������
	PVOID DetourFunc,     //Detour������ַ
	PULONG_PTR *pThunkPointer,  //���Խ���ָ���޸ĵ�λ�õ�ָ��
	ULONG_PTR *pOriginalFuncAddr   //���Խ���ԭʼ������ַ
	//ULONG_PRT��ULONG�Ĺ�ϵ��ULONG_PRT��Ϊ��X64����X32������Щ_PTR����ֻ����32λӦ�ó�����Ϊ32λ����64λӦ�ó�����Ϊ64λ������͡�����ô�򵥡�
);

//DetourFun
int WINAPI My_MessageBoxA(
	HWND hWnd,
	LPCTSTR lpText,
	LPCTSTR lpCaption,
	UINT uType
);

