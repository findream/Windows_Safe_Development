#include <stdio.h>
#include <windows.h>

//全局变量
HHOOK g_hHook = NULL;

//函数声明
LRESULT CALLBACK HookProc(int ncode, WPARAM wParam, LPARAM lParam);

//DllMain
BOOL WINAPI DllMain(HINSTANCE hinstDll, DWORD dwreason, LPVOID lpvReserved)
{
	switch (dwreason)
	{

	case DLL_PROCESS_ATTACH:
	{
		HINSTANCE hInstance = hinstDll;   //传入当前句柄
		break;
	}

	case DLL_THREAD_ATTACH:
	case DLL_THREAD_DETACH:
	case DLL_PROCESS_DETACH:
		break;
	}
	return TRUE;
}

//extern是C/C++语言中表明函数和全局变量作用范围（可见性）的关键字

//被extern "C"修饰的变量和函数是按照C语言方式编译和链接的
//即不使用重载，也就是说函数名称不经过重命名

//_declspec:函数到导出
extern "C" _declspec(dllexport) void HookStart()
{
//	HHOOK hHook = NULL;
	g_hHook=SetWindowsHookEx(WH_KEYBOARD, HookProc, 
		GetModuleHandle("E://Viusal Studio//kanxue//注入技术//SetWindowsHookEx//Inject_dll//Debug//Inject_dll.dll"), 0);
	if (NULL == g_hHook)
	{
		MessageBox(NULL, "安装钩子失败", "提示", MB_OKCANCEL);
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
	MessageBox(NULL, "你已经注入成功", "成功", MB_OKCANCEL);
	return CallNextHookEx(g_hHook, ncode, wParam, lParam);
}