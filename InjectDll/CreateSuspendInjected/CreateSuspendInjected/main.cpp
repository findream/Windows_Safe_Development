#include <stdio.h>
#include <windows.h>
#include<iostream>
using namespace std;


void CreateShellCode(int ret, int str, unsigned char** shellcode, int* shellcodeSize);

int main(int agrc, char* argv[])
{
	char DllPath[] = "D:\\MsgDll.dll";

	//Shellcode
	unsigned char* ShellCode;
	int ShellCodeLength;

	//线程上下文
	CONTEXT ctx;
	/*------------------------
	typedef struct _WOW64_CONTEXT {
	  DWORD                    ContextFlags;
	  DWORD                    Dr0;
	  DWORD                    Dr1;
	  DWORD                    Dr2;
	  DWORD                    Dr3;
	  DWORD                    Dr6;
	  DWORD                    Dr7;
	  WOW64_FLOATING_SAVE_AREA FloatSave;
	  DWORD                    SegGs;
	  DWORD                    SegFs;
	  DWORD                    SegEs;
	  DWORD                    SegDs;
	  DWORD                    Edi;
	  DWORD                    Esi;
	  DWORD                    Ebx;
	  DWORD                    Edx;
	  DWORD                    Ecx;
	  DWORD                    Eax;
	  DWORD                    Ebp;
	  DWORD                    Eip;
	  DWORD                    SegCs;
	  DWORD                    EFlags;
	  DWORD                    Esp;
	  DWORD                    SegSs;
	  BYTE                     ExtendedRegisters[WOW64_MAXIMUM_SUPPORTED_EXTENSION];
	} WOW64_CONTEXT;
	---------------------------------------*/



	//创建进程
	PROCESS_INFORMATION pi;
	/*--------------------------------------
	typedef struct _PROCESS_INFORMATION {
	  HANDLE hProcess;
	  HANDLE hThread;
	  DWORD  dwProcessId;
	  DWORD  dwThreadId;
	} PROCESS_INFORMATION, *PPROCESS_INFORMATION, *LPPROCESS_INFORMATION;
	-----------------------------------------*/
	STARTUPINFO Startup;
	/*-------------------------------------
	typedef struct _STARTUPINFOA {
	  DWORD  cb;
	  LPSTR  lpReserved;
	  LPSTR  lpDesktop;
	  LPSTR  lpTitle;
	  DWORD  dwX;
	  DWORD  dwY;
	  DWORD  dwXSize;
	  DWORD  dwYSize;
	  DWORD  dwXCountChars;
	  DWORD  dwYCountChars;
	  DWORD  dwFillAttribute;
	  DWORD  dwFlags;
	  WORD   wShowWindow;
	  WORD   cbReserved2;
	  LPBYTE lpReserved2;
	  HANDLE hStdInput;
	  HANDLE hStdOutput;
	  HANDLE hStdError;
	} STARTUPINFOA, *LPSTARTUPINFOA;
	-----------------------------------------*/
	ZeroMemory(&pi, sizeof(pi));
	ZeroMemory(&Startup, sizeof(Startup));
	BOOL bRetProcess = FALSE;
	bRetProcess = CreateProcess("D:\\HostProc.exe",
		NULL,
		NULL,
		NULL,
		NULL,
		CREATE_SUSPENDED,       //挂起创建进程
		NULL,
		NULL,
		&Startup,
		&pi);
	if (FALSE == bRetProcess)
	{
		printf("CreateProcess:%d", GetLastError());
		return FALSE;
	}

	//为DllPath写入目标进程
	LPVOID Remote_DllStringPtr = NULL;
	Remote_DllStringPtr = VirtualAllocEx(pi.hProcess,
		NULL,
		lstrlen(DllPath) + 1,
		MEM_COMMIT,
		PAGE_READWRITE);
	if (Remote_DllStringPtr == NULL)
	{
		printf("VirtualAllocEx:%d", GetLastError());
		return FALSE;
	}

	//获取CONTEXT
	ctx.ContextFlags = CONTEXT_CONTROL;
	GetThreadContext(pi.hThread, &ctx);


	//构造shellcode
	BOOL bRet = FALSE;
	CreateShellCode(ctx.Eip, (int)Remote_DllStringPtr, &ShellCode, &ShellCodeLength);
	//写入shellcode和Dllpath
	LPVOID Remote_ShellCodePtr = NULL;
	Remote_ShellCodePtr = VirtualAllocEx(pi.hProcess,
		NULL,
		ShellCodeLength,
		MEM_COMMIT,
		PAGE_EXECUTE_READWRITE);
	if (Remote_ShellCodePtr == NULL)
	{
		printf("VirtualAllocEx:%d\n", GetLastError());
		return FALSE;
	}

	bRet = FALSE;
	WriteProcessMemory(pi.hProcess,
		Remote_DllStringPtr,
		DllPath,
		lstrlen(DllPath) + 1,
		NULL
		);
	bRet=WriteProcessMemory(pi.hProcess,
		Remote_ShellCodePtr,
		ShellCode,
		ShellCodeLength,
		NULL
	);
	if (FALSE == bRet)
	{
		printf("WriteProcessMemory:%d\n", GetLastError());
		return FALSE;
	}
	


	//将RIP设置为shellcode入口
	ctx.Eip =(DWORD) Remote_ShellCodePtr;
	ctx.ContextFlags = CONTEXT_CONTROL;
	SetThreadContext(pi.hThread, &ctx);

	//重启线程
	ResumeThread(pi.hThread);

	Sleep(8000);

	VirtualFreeEx(pi.hProcess, Remote_DllStringPtr, strlen(DllPath) + 1, MEM_DECOMMIT);
	VirtualFreeEx(pi.hProcess, Remote_ShellCodePtr, ShellCodeLength, MEM_DECOMMIT);
	return TRUE;
}

void CreateShellCode(int ret, int str, unsigned char** shellcode, int* shellcodeSize)
{
	unsigned char* retChar = (unsigned char*)&ret;    //转化为unsigned char
	unsigned char* strChar = (unsigned char*)&str;
	int api = (int)GetProcAddress(LoadLibraryA("kernel32.dll"), "LoadLibraryA");
	unsigned char* apiChar = (unsigned char*)&api;

	unsigned char sc[] = {
		//push ret
		0x68,retChar[0],retChar[1],retChar[2],retChar[3],

		//push flags
		0x9C,

		//pushad
		0x60,

		//push DllPath
		0x68, strChar[0], strChar[1],strChar[2],strChar[3],

		//mov eax,AddressOfLoadLibrary
		0xB8, apiChar[0],apiChar[1],apiChar[2],apiChar[3],

		//call eax
		0xFF,0xD0,

		//popad
		0x61,

		//popfd
		0x9D,

		//ret
		0xC3 };
	*shellcodeSize = 22;
	*shellcode = (unsigned char*)malloc(22);
	memcpy(*shellcode, sc, 22);
}

