#include <stdio.h>
#include <windows.h>

//ȫ�ֱ���
HHOOK g_hHook = NULL;

//��������
LRESULT CALLBACK HookProc(int ncode, WPARAM wParam, LPARAM lParam);

//DllMain
BOOL WINAPI DllMain(HINSTANCE hinstDll, DWORD dwreason, LPVOID lpvReserved)
{
	switch (dwreason)
	{

	case DLL_PROCESS_ATTACH:
	{
		HINSTANCE hInstance = hinstDll;   //���뵱ǰ���
		break;
	}

	case DLL_THREAD_ATTACH:
	case DLL_THREAD_DETACH:
	case DLL_PROCESS_DETACH:
		break;
	}
	return TRUE;
}

//extern��C/C++�����б���������ȫ�ֱ������÷�Χ���ɼ��ԣ��Ĺؼ���

//��extern "C"���εı����ͺ����ǰ���C���Է�ʽ��������ӵ�
//����ʹ�����أ�Ҳ����˵�������Ʋ�����������

//_declspec:����������
extern "C" _declspec(dllexport) void HookStart()
{
//	HHOOK hHook = NULL;
	g_hHook=SetWindowsHookEx(WH_KEYBOARD, HookProc, 
		GetModuleHandle("E://Viusal Studio//kanxue//ע�뼼��//SetWindowsHookEx//Inject_dll//Debug//Inject_dll.dll"), 0);
	if (NULL == g_hHook)
	{
		MessageBox(NULL, "��װ����ʧ��", "��ʾ", MB_OKCANCEL);
	}
}

extern "C" _declspec(dllexport) void HookEnd()
{
	if (g_hHook)
	{
		UnhookWindowsHookEx(g_hHook);
		g_hHook = NULL;
	}
}


LRESULT CALLBACK HookProc(int ncode, WPARAM wParam, LPARAM lParam)
{
	MessageBox(NULL, "���Ѿ�ע��ɹ�", "�ɹ�", MB_OKCANCEL);
	return CallNextHookEx(g_hHook, ncode, wParam, lParam);
}