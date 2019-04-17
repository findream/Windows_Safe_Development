#include <stdio.h>
#include <windows.h>

#define IBD_ONE 3301
#define IBD_TWO 3302


//全局变量
HINSTANCE hg_app;

//函数声明
LRESULT CALLBACK WndProc(HWND hwnd, UINT message, WPARAM wParam, LPARAM lParam);

//函数定义
typedef void(*pFunHookStart)();
typedef void(*pFunHookEnd)();



int WINAPI WinMain(HINSTANCE hInstance, HINSTANCE hPrevInstance, PSTR szCmdLine, int iCmdShow)
{
	static TCHAR szAppName[] = TEXT("MyWindows");
	HWND hwnd;
	MSG msg;
	WNDCLASS wndclass;
	wndclass.style = CS_HREDRAW | CS_VREDRAW;
	wndclass.lpfnWndProc = WndProc;    //设置回调函数
	wndclass.cbClsExtra = 0;
	wndclass.cbWndExtra = 0;
	wndclass.hInstance = hInstance;
	wndclass.hIcon = LoadIcon(NULL, IDI_APPLICATION);
	wndclass.hCursor = LoadCursor(NULL, IDC_ARROW);
	wndclass.hbrBackground = (HBRUSH)GetStockObject(WHITE_BRUSH);
	wndclass.lpszMenuName = NULL;
	wndclass.lpszClassName = szAppName;

	if (!RegisterClass(&wndclass))
	{
		MessageBox(NULL, TEXT("这个程序需要在 Windows NT 才能执行！"), szAppName, MB_ICONERROR);
		return 0;
	}

	hwnd = CreateWindow(szAppName,
		TEXT("消息钩取工具V1.0"),
		WS_OVERLAPPEDWINDOW,
		CW_USEDEFAULT,
		CW_USEDEFAULT,
		CW_USEDEFAULT,
		CW_USEDEFAULT,
		NULL,
		NULL,
		hInstance,
		NULL);

	ShowWindow(hwnd, iCmdShow);
	UpdateWindow(hwnd);
	while (GetMessage(&msg, NULL, 0, 0))
	{
		TranslateMessage(&msg);
		DispatchMessage(&msg);
	}
	return msg.wParam;
}

LRESULT CALLBACK WndProc(HWND hwnd, UINT message, WPARAM wParam, LPARAM lParam)
{
	HDC hdc;
	PAINTSTRUCT ps;
	RECT rect;

	//加载需要注入的dll，因为涉及的是全局HOOK，所以将DLL先加载到当前进程
	HMODULE hDll = LoadLibrary("E://Viusal Studio//kanxue//注入技术//SetWindowsHookEx//Inject_dll//Debug//Inject_dll.dll");
	if (NULL == hDll)
	{
		MessageBox(NULL, "DLL加载失败", "警告", MB_OKCANCEL);
		return NULL;
	}

	//处理不同的消息机制
	switch (message)   //message是消息ID
	{

	case WM_PAINT:    //绘制窗口
	{
		hdc = BeginPaint(hwnd, &ps);
		GetClientRect(hwnd, &rect);
		DrawText(hdc, NULL, -1, &rect,
			DT_SINGLELINE | DT_CENTER | DT_VCENTER);
		EndPaint(hwnd, &ps);
		return 0;
	}

	case WM_CREATE:   //绘制子窗口
	{
		HWND StartHookButton = CreateWindow(TEXT("Button"), TEXT("开始钩取"),
			WS_VISIBLE | WS_CHILD | BS_PUSHBUTTON,
			300, 200, 160, 65, hwnd, (HMENU)IBD_ONE, hg_app, NULL);
		HWND EndHookButton = CreateWindow(TEXT("Button"), TEXT("结束钩取"),
			WS_VISIBLE | WS_CHILD | BS_PUSHBUTTON,
			580, 200, 160, 65, hwnd, (HMENU)IBD_TWO, hg_app, NULL);
		return 0;
	}


	//获取导出函数地址
	case WM_COMMAND:
	{
		switch (LOWORD(wParam))
		{
		case IBD_ONE:    //获取dll中HookStart导出函数地址
		{
			pFunHookStart HookStart = NULL;
			HookStart = (pFunHookStart)GetProcAddress(hDll, "HookStart");
			if (NULL == HookStart)
			{
				MessageBox(NULL, "GetProcAddress_StartHook", "警告", MB_OKCANCEL);
				return NULL;
			}
			HookStart();
			break;
		}
		case IBD_TWO:    //获取dll中HookEnd导出函数地址
		{
			pFunHookEnd HookEnd = NULL;
			HookEnd = (pFunHookEnd)GetProcAddress(hDll, "HookEnd");
			if (NULL == HookEnd)
			{
				MessageBox(NULL, "GetProcAddress_StartEnd", "警告", MB_OKCANCEL);
				return NULL;
			}
			HookEnd();
			FreeLibrary(hDll);  //卸载dll
			break;
		}
		default:
			break;
		}
		return NULL;
	}

	case WM_DESTROY:
	{
		PostQuitMessage(0);
		return 0;
	}
	}
	return DefWindowProc(hwnd, message, wParam, lParam);
}
