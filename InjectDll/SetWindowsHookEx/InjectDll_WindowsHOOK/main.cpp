#include <stdio.h>
#include <windows.h>

#define IBD_ONE 3301
#define IBD_TWO 3302


//ȫ�ֱ���
HINSTANCE hg_app;

//��������
LRESULT CALLBACK WndProc(HWND hwnd, UINT message, WPARAM wParam, LPARAM lParam);

//��������
typedef void(*pFunHookStart)();
typedef void(*pFunHookEnd)();



int WINAPI WinMain(HINSTANCE hInstance, HINSTANCE hPrevInstance, PSTR szCmdLine, int iCmdShow)
{
	static TCHAR szAppName[] = TEXT("MyWindows");
	HWND hwnd;
	MSG msg;
	WNDCLASS wndclass;
	wndclass.style = CS_HREDRAW | CS_VREDRAW;
	wndclass.lpfnWndProc = WndProc;    //���ûص�����
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
		MessageBox(NULL, TEXT("���������Ҫ�� Windows NT ����ִ�У�"), szAppName, MB_ICONERROR);
		return 0;
	}

	hwnd = CreateWindow(szAppName,
		TEXT("��Ϣ��ȡ����V1.0"),
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

	//������Ҫע���dll����Ϊ�漰����ȫ��HOOK�����Խ�DLL�ȼ��ص���ǰ����
	HMODULE hDll = LoadLibrary("E://Viusal Studio//kanxue//ע�뼼��//SetWindowsHookEx//Inject_dll//Debug//Inject_dll.dll");
	if (NULL == hDll)
	{
		MessageBox(NULL, "DLL����ʧ��", "����", MB_OKCANCEL);
		return NULL;
	}

	//����ͬ����Ϣ����
	switch (message)   //message����ϢID
	{

	case WM_PAINT:    //���ƴ���
	{
		hdc = BeginPaint(hwnd, &ps);
		GetClientRect(hwnd, &rect);
		DrawText(hdc, NULL, -1, &rect,
			DT_SINGLELINE | DT_CENTER | DT_VCENTER);
		EndPaint(hwnd, &ps);
		return 0;
	}

	case WM_CREATE:   //�����Ӵ���
	{
		HWND StartHookButton = CreateWindow(TEXT("Button"), TEXT("��ʼ��ȡ"),
			WS_VISIBLE | WS_CHILD | BS_PUSHBUTTON,
			300, 200, 160, 65, hwnd, (HMENU)IBD_ONE, hg_app, NULL);
		HWND EndHookButton = CreateWindow(TEXT("Button"), TEXT("������ȡ"),
			WS_VISIBLE | WS_CHILD | BS_PUSHBUTTON,
			580, 200, 160, 65, hwnd, (HMENU)IBD_TWO, hg_app, NULL);
		return 0;
	}


	//��ȡ����������ַ
	case WM_COMMAND:
	{
		switch (LOWORD(wParam))
		{
		case IBD_ONE:    //��ȡdll��HookStart����������ַ
		{
			pFunHookStart HookStart = NULL;
			HookStart = (pFunHookStart)GetProcAddress(hDll, "HookStart");
			if (NULL == HookStart)
			{
				MessageBox(NULL, "GetProcAddress_StartHook", "����", MB_OKCANCEL);
				return NULL;
			}
			HookStart();
			break;
		}
		case IBD_TWO:    //��ȡdll��HookEnd����������ַ
		{
			pFunHookEnd HookEnd = NULL;
			HookEnd = (pFunHookEnd)GetProcAddress(hDll, "HookEnd");
			if (NULL == HookEnd)
			{
				MessageBox(NULL, "GetProcAddress_StartEnd", "����", MB_OKCANCEL);
				return NULL;
			}
			HookEnd();
			FreeLibrary(hDll);  //ж��dll
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
