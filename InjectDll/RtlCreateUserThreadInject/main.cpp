# include <stdio.h>
#include <windows.h>
#include <TLHELP32.H>
#include <string.h>

#define STATUS_SUCCESS                      ((NTSTATUS) 0x00000000L)

typedef struct _INJECT_DATA                 //����shellcode��һЩ����
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
//typedef  ��������(*������)(������)
typedef char (*PTRFUN)(int);
PTRFUN pFun;
char pFun(int a);   //��������
----------------------------------*/

typedef NTSTATUS(__stdcall *PCreateThread)(      //������һ�ֺ�������
	//IN HANDLE Process,                           //���
	HANDLE Process,
	//IN PSECURITY_DESCRIPTOR ThreadSecurityDescriptor OPTIONAL,   //�̰߳�ȫ������
	PSECURITY_DESCRIPTOR ThreadSecurityDescriptor,
	//IN BOOLEAN CreateSuspended,                  //���������־
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
PCreateThread RtlCreateUserThread;                //��������

//��������
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

	//��ȡĿ����̵�PID
	DWORD dwPid = ProcesstoPid(szProcName);
	if (dwPid == 0)
	{
		printf("ProcesstoPid:%d\n", GetLastError());
		return FALSE;
	}

	//Զ���߳�ע��
	InjectDllToProcess(dwPid, szDllPath);
}

DWORD ProcesstoPid(char *Processname) //����ָ�����̵�PID(Process ID)
{
	HANDLE hProcessSnap = NULL;
	DWORD ProcessId = 0;
	PROCESSENTRY32 pe32 = { 0 };
	hProcessSnap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0); //�򿪽��̿���
	if (hProcessSnap == (HANDLE)-1)
	{
		printf("\nCreateToolhelp32Snapshot() Error: %d", GetLastError());
		return 0;
	}
	pe32.dwSize = sizeof(PROCESSENTRY32);
	if (Process32First(hProcessSnap, &pe32)) //��ʼö�ٽ���
	{
		do
		{
			if (!strcmp(Processname, pe32.szExeFile)) //�ж��Ƿ���ṩ�Ľ�������ȣ��ǣ����ؽ��̵�ID
			{
				ProcessId = pe32.th32ProcessID;
				break;
			}
		} while (Process32Next(hProcessSnap, &pe32)); //����ö�ٽ���
	}
	else
	{
		printf("\nProcess32First() Error: %d", GetLastError());
		return 0;
	}
	CloseHandle(hProcessSnap); //�ر�ϵͳ���̿��յľ��
	return ProcessId;
}

BOOL WINAPI InjectDllToProcess(DWORD dwTargetPid, LPCTSTR DllPath)
{
	//��ȡĿ����̵ľ��
	HANDLE hProc = NULL;
	hProc = OpenProcess(PROCESS_ALL_ACCESS,
		FALSE,
		dwTargetPid);
	if (hProc == NULL)
	{
		printf("OpenProcess:%d\n", GetLastError());
		return FALSE;
	}

	//Ϊdll·�������ڴ�ռ�
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

	//��DLL·��д�����
	int bRet = WriteProcessMemory(hProc,
		psLibFileRemote,     //���ٵ��ڴ�ռ�
		(LPCVOID)DllPath,
		lstrlen(DllPath) + 1,
		NULL
	);
	if (bRet == NULL)
	{
		printf("WriteProcessMemory:%d\n", GetLastError());
		return FALSE;
	}


	//��ȡLoadLibrary��ַ
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
	IN  DWORD dwStackSize,     //ջ��С
	IN  LPTHREAD_START_ROUTINE lpStartAddress,
	IN  LPVOID lpParameter,
	IN  DWORD dwCreationFlags,
	OUT LPDWORD lpThreadId
)
{
	//RtlCreateUserThread������״̬
	NTSTATUS status = STATUS_SUCCESS;   //Ԥ��������(NTSTATUS) 0x00000000L

	CLIENT_ID Cid;                      //
	HANDLE hThread = NULL;              //
	SIZE_T dwIoCnt = 0;                 //

	//��ѡ:��֤������Ϣ�ĺϷ���
	if (hProcess == NULL || lpStartAddress == NULL)
	{
		return NULL;
	}

	//��ȡNative API������ַ
	RtlCreateUserThread = (PCreateThread)GetProcAddress(GetModuleHandle("ntdll"),
		"RtlCreateUserThread");
	if (RtlCreateRemoteThread == NULL)
	{
		return NULL;
	}

	//����1000h�Ļ�����
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

	//����shellcode
	INJECT_DATA Data;
	ZeroMemory(&Data, sizeof(INJECT_DATA));
	PrepareShellCode(Data.ShellCode);
	Data.lpParameter = lpParameter;
	Data.lpThreadStartRoutine = lpStartAddress;
	Data.AddrOfZwTerminateThread = GetProcAddress(GetModuleHandle("ntdll.dll"), "ZwTerminateThread");

	//д��shellcode
	int bRet = WriteProcessMemory(hProcess, pMem, &Data, sizeof(INJECT_DATA), &dwIoCnt);
	if (bRet == 0)
	{
		printf(" WriteProcessMemory:%d\n", GetLastError());
		return FALSE;
	}

	status = RtlCreateUserThread(hProcess,    //���̾��
		lpThreadAttributes,                   //�̰߳�ȫ��
		TRUE,                                 //���������־
		0,                                    //ZeroBit
		dwStackSize,                          //ջ��С
		0,
		(PUSER_THREAD_START_ROUTINE)pMem,    //StartAddress��������shellcode������(StartAddress)
		NULL,                                //����
		&hThread,                            //Զ���߳̾��
		&Cid                                 //ClientID
	);
	if (status >= 0)    //�����ɹ�
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

//����shellcode
VOID PrepareShellCode(BYTE *pOutShellCode)
{
#ifdef _WIN64
	BYTE *ShellcodeStart = (PYTE*)ShellCodeFun64;
#else
	BYTE *pShellcodeStart = (BYTE*)ShellCodeFun;   //ShellCodeFun�����ĵ�ַ
#endif
	BYTE *pShellcodeEnd = 0;
	SIZE_T ShellCodeSize = 0;

	//��λshellcode��ʼ����
	if (pShellcodeStart[0] == 0xE9)
	{
		pShellcodeStart = pShellcodeStart+ *(ULONG*)(pShellcodeStart + 1) + 5;

	}


	//��λshellcodeĩ��
	pShellcodeEnd = pShellcodeStart;
	while (memcmp(pShellcodeEnd, "\x90\x90\x90\x90\x90", 5) != 0)
	{
		pShellcodeEnd++;
	}

	//����shellcode�ĸ���
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