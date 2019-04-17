# include <stdio.h>
#include <windows.h>
#include <TLHELP32.H>
#include <string.h>

#define STATUS_SUCCESS                      ((NTSTATUS) 0x00000000L)

typedef struct _INJECT_DATA                 //定义shellcode等一些参数
{
	BYTE ShellCode[0x30];              //shellcode
	LPVOID lpThreadStartRoutine;       //LoadLibrary
	LPVOID lpParameter;                //DllPath
	LPVOID AddrOfZwTerminateThread;    //ZwTerminateThread
}INJECT_DATA;

typedef struct _CLIENT_ID {
	HANDLE UniqueProcess;
	HANDLE UniqueThread;
} CLIENT_ID;
typedef CLIENT_ID *PCLIENT_ID;

typedef PVOID PUSER_THREAD_START_ROUTINE;

/*----------------------------------
//typedef  返回类型(*新类型)(参数表)
typedef char (*PTRFUN)(int);
PTRFUN pFun;
char pFun(int a);   //函数声明
----------------------------------*/

typedef NTSTATUS(__stdcall *PCreateThread)(      //定义了一种函数类型
	//IN HANDLE Process,                           //句柄
	HANDLE Process,
	//IN PSECURITY_DESCRIPTOR ThreadSecurityDescriptor OPTIONAL,   //线程安全描述符
	PSECURITY_DESCRIPTOR ThreadSecurityDescriptor,
	//IN BOOLEAN CreateSuspended,                  //创建挂起标志
	BOOLEAN CreateSuspended,
	//IN ULONG ZeroBits OPTIONAL,                  //
	ULONG ZeroBits,
	//IN SIZE_T MaximumStackSize OPTIONAL,
	SIZE_T MaximumStackSize,
	//IN SIZE_T CommittedStackSize OPTIONAL,
	SIZE_T CommittedStackSize,
	//IN PUSER_THREAD_START_ROUTINE StartAddress,
	PUSER_THREAD_START_ROUTINE StartAddress,
	//IN PVOID Parameter OPTIONAL,
	PVOID Parameter OPTIONAL,
	//OUT PHANDLE Thread OPTIONAL,
	PHANDLE Thread OPTIONAL,
	//OUT PCLIENT_ID ClientId OPTIONAL
	PCLIENT_ID ClientId OPTIONAL
	);
PCreateThread RtlCreateUserThread;                //函数声明

//函数声明
DWORD ProcesstoPid(char *Processname);
BOOL WINAPI InjectDllToProcess(DWORD dwTargetPid, LPCTSTR DllPath);
HANDLE RtlCreateRemoteThread(
	IN  HANDLE hProcess,
	IN  LPSECURITY_ATTRIBUTES lpThreadAttributes,
	IN  DWORD dwStackSize,
	IN  LPTHREAD_START_ROUTINE lpStartAddress,
	IN  LPVOID lpParameter,
	IN  DWORD dwCreationFlags,
	OUT LPDWORD lpThreadId
);
VOID ShellCodeFun(VOID);
VOID PrepareShellCode(BYTE *pOutShellCode);
  

int main(void)
{
	char szDllPath[] = "c://MsgDll.dll";
	char szProcName[] = "notepad.exe";

	//获取目标进程的PID
	DWORD dwPid = ProcesstoPid(szProcName);
	if (dwPid == 0)
	{
		printf("ProcesstoPid:%d\n", GetLastError());
		return FALSE;
	}

	//远程线程注入
	InjectDllToProcess(dwPid, szDllPath);
}

DWORD ProcesstoPid(char *Processname) //查找指定进程的PID(Process ID)
{
	HANDLE hProcessSnap = NULL;
	DWORD ProcessId = 0;
	PROCESSENTRY32 pe32 = { 0 };
	hProcessSnap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0); //打开进程快照
	if (hProcessSnap == (HANDLE)-1)
	{
		printf("\nCreateToolhelp32Snapshot() Error: %d", GetLastError());
		return 0;
	}
	pe32.dwSize = sizeof(PROCESSENTRY32);
	if (Process32First(hProcessSnap, &pe32)) //开始枚举进程
	{
		do
		{
			if (!strcmp(Processname, pe32.szExeFile)) //判断是否和提供的进程名相等，是，返回进程的ID
			{
				ProcessId = pe32.th32ProcessID;
				break;
			}
		} while (Process32Next(hProcessSnap, &pe32)); //继续枚举进程
	}
	else
	{
		printf("\nProcess32First() Error: %d", GetLastError());
		return 0;
	}
	CloseHandle(hProcessSnap); //关闭系统进程快照的句柄
	return ProcessId;
}

BOOL WINAPI InjectDllToProcess(DWORD dwTargetPid, LPCTSTR DllPath)
{
	//获取目标进程的句柄
	HANDLE hProc = NULL;
	hProc = OpenProcess(PROCESS_ALL_ACCESS,
		FALSE,
		dwTargetPid);
	if (hProc == NULL)
	{
		printf("OpenProcess:%d\n", GetLastError());
		return FALSE;
	}

	//为dll路径开辟内存空间
	LPTSTR psLibFileRemote = NULL;
	psLibFileRemote = (LPSTR)VirtualAllocEx(hProc,
		NULL,
		lstrlen(DllPath) + 1,
		MEM_COMMIT,
		PAGE_READWRITE);
	if (psLibFileRemote == NULL)
	{
		printf("VirtualAllocEx:%d\n", GetLastError());
		return FALSE;
	}

	//将DLL路径写入进程
	int bRet = WriteProcessMemory(hProc,
		psLibFileRemote,     //开辟的内存空间
		(LPCVOID)DllPath,
		lstrlen(DllPath) + 1,
		NULL
	);
	if (bRet == NULL)
	{
		printf("WriteProcessMemory:%d\n", GetLastError());
		return FALSE;
	}


	//获取LoadLibrary地址
	PTHREAD_START_ROUTINE pfnStartAddr = (PTHREAD_START_ROUTINE)
		GetProcAddress(GetModuleHandle("Kernel32"), "LoadLibraryA");
	if (pfnStartAddr == NULL)
	{
		printf("GetProcAddress %d\n",GetLastError());
		return FALSE;
	}

	HANDLE hThread = RtlCreateRemoteThread(hProc,
		NULL,
		0,
		pfnStartAddr,     //LoadLibrary
		psLibFileRemote,  //Dllpath
		0, 
		NULL);
}

HANDLE RtlCreateRemoteThread(
	IN  HANDLE hProcess,
	IN  LPSECURITY_ATTRIBUTES lpThreadAttributes,
	IN  DWORD dwStackSize,     //栈大小
	IN  LPTHREAD_START_ROUTINE lpStartAddress,
	IN  LPVOID lpParameter,
	IN  DWORD dwCreationFlags,
	OUT LPDWORD lpThreadId
)
{
	//RtlCreateUserThread函数的状态
	NTSTATUS status = STATUS_SUCCESS;   //预定义数据(NTSTATUS) 0x00000000L

	CLIENT_ID Cid;                      //
	HANDLE hThread = NULL;              //
	SIZE_T dwIoCnt = 0;                 //

	//可选:认证进程信息的合法性
	if (hProcess == NULL || lpStartAddress == NULL)
	{
		return NULL;
	}

	//获取Native API函数地址
	RtlCreateUserThread = (PCreateThread)GetProcAddress(GetModuleHandle("ntdll"),
		"RtlCreateUserThread");
	if (RtlCreateRemoteThread == NULL)
	{
		return NULL;
	}

	//申请1000h的缓冲区
	PBYTE pMem = (PBYTE)VirtualAllocEx(hProcess,
		NULL,
		0x1000,
		MEM_COMMIT,
		PAGE_READWRITE);
	if (NULL == pMem)
	{
		printf("VirtualAllocEx %d\n", GetLastError());
		return FALSE;
	}

	//构造shellcode
	INJECT_DATA Data;
	ZeroMemory(&Data, sizeof(INJECT_DATA));
	PrepareShellCode(Data.ShellCode);
	Data.lpParameter = lpParameter;
	Data.lpThreadStartRoutine = lpStartAddress;
	Data.AddrOfZwTerminateThread = GetProcAddress(GetModuleHandle("ntdll.dll"), "ZwTerminateThread");

	//写入shellcode
	int bRet = WriteProcessMemory(hProcess, pMem, &Data, sizeof(INJECT_DATA), &dwIoCnt);
	if (bRet == 0)
	{
		printf(" WriteProcessMemory:%d\n", GetLastError());
		return FALSE;
	}

	status = RtlCreateUserThread(hProcess,    //进程句柄
		lpThreadAttributes,                   //线程安全符
		TRUE,                                 //创建挂起标志
		0,                                    //ZeroBit
		dwStackSize,                          //栈大小
		0,
		(PUSER_THREAD_START_ROUTINE)pMem,    //StartAddress，包含了shellcode和数据(StartAddress)
		NULL,                                //参数
		&hThread,                            //远程线程句柄
		&Cid                                 //ClientID
	);
	if (status >= 0)    //创建成功
	{
		if (lpThreadId != NULL)
		{
			*lpThreadId = (DWORD)Cid.UniqueThread;    //
		}
		if (!(dwCreationFlags & CREATE_SUSPENDED))
		{
			ResumeThread(hThread);
		}
	}
	return hThread;
}

//构造shellcode
VOID PrepareShellCode(BYTE *pOutShellCode)
{
#ifdef _WIN64
	BYTE *ShellcodeStart = (PYTE*)ShellCodeFun64;
#else
	BYTE *pShellcodeStart = (BYTE*)ShellCodeFun;   //ShellCodeFun函数的地址
#endif
	BYTE *pShellcodeEnd = 0;
	SIZE_T ShellCodeSize = 0;

	//定位shellcode起始部分
	if (pShellcodeStart[0] == 0xE9)
	{
		pShellcodeStart = pShellcodeStart+ *(ULONG*)(pShellcodeStart + 1) + 5;

	}


	//定位shellcode末端
	pShellcodeEnd = pShellcodeStart;
	while (memcmp(pShellcodeEnd, "\x90\x90\x90\x90\x90", 5) != 0)
	{
		pShellcodeEnd++;
	}

	//进行shellcode的复制
	ShellCodeSize = pShellcodeEnd - pShellcodeStart;
	memcpy(pOutShellCode, pShellcodeStart, ShellCodeSize);
}

#ifndef _WIN64
__declspec (naked)
VOID ShellCodeFun(VOID)
{
	_asm
	{
		call L001
L001:
		pop ebx
		sub ebx,5
		push dword ptr ds : [ebx]INJECT_DATA.lpParameter //lpParameter
		call dword ptr ds : [ebx]INJECT_DATA.lpThreadStartRoutine //ThreadProc
		xor ebx,ebx
		push ebx
		push -2
		call dword ptr ds : [ebx]INJECT_DATA.AddrOfZwTerminateThread //ZwTerminateThread
		nop
		nop
		nop
		nop
		nop
	}
}
#endif