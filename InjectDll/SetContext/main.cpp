#include <stdio.h>
#include <windows.h>
#include <TlHelp32.h>
#include <Psapi.h>
#include <string.h>

#pragma comment(lib,"psapi.lib")

//����shellcode�ṹ��
typedef struct _INJECT_DATA
{
	BYTE ShellCode[0x30];                //offset 0x00
	ULONG_PTR AddrofLoadLibraryA;        //offset 0x30
	PBYTE lpDllPath;                     //offset 0x34
	ULONG_PTR OriginalEIP;               //offset 0x38
	char szDllPath[MAX_PATH];            //offset 0x3C
}INJECT_DATA;

#ifdef _WIN64
EXTERN_C VOID ShellCodeFun64(VOID);
#else
VOID ShellCodeFun(VOID);
#endif



//��������
ULONG_PTR GetModuleHandleInProc(DWORD dwPid, char* ModuleName);    //��ȡKernel32��Ŀ�꺯���Ļ���ַ
DWORD ProcesstoPid(char *szProcessname);
void PrepareShellCode(BYTE *pOutShellCode);
BOOL InjectModuleToProcessBySetContext(DWORD dwPid, char* szDllPath);

int main(int argc, char* argv[])
{
	DWORD dwPid = 0;
	BOOL bRet = FALSE;
#ifdef _WIN64
	char szDllPath[MAX_PATH] = "C://MsgDll64.dll";
	dwPid = ProcesstoPid("HostProc64.exe");
#else
	char szDllPath[MAX_PATH] = "D://MsgDll.dll";
	dwPid = ProcesstoPid("notepad.exe");
#endif
	if (dwPid == 0)
	{
		printf("ProcesstoPid:%d\n", GetLastError());
		return 0;
	}
	bRet = InjectModuleToProcessBySetContext(dwPid, szDllPath);
	if (FALSE == bRet)
	{
		printf("InjectModuleToProcessBySetContext:%d\n", GetLastError());
		return 0;
	}
	getchar();
	return 0;
}


//ע�뺯��
BOOL InjectModuleToProcessBySetContext(DWORD dwPid, char* szDllPath)
{

	//1.��ȡĿ�������LoadLibrary�ĵ�ַ
	//Ϊ�˱���ASLR��Ӱ�죬ʹ��BaseAddressOfTargeProcess+(LoadLibraryAddressOfCurrentProcesss-BaseAddressOfCurrentProcess)

	//Ŀ�����Kernel32.dll�Ļ���ַ
	ULONG_PTR uKernelBaseInTargetProc = GetModuleHandleInProc(dwPid, "KERNEL32.DLL");

	//��ǰ���̵Ļ���ַ
	ULONG_PTR uKernelBaseInCurProc = (ULONG_PTR)GetModuleHandle("kernel32.dll");
	

	//��ǰ����LoadLibrary������ַ
	//ULONG_PTR uLoadLibraryAddrInCurProc = (ULONG_PTR)GetProcAddress(GetModuleHandle("Kernel32.dll"), "LoadLibraryA");
	ULONG_PTR uLoadLibraryAddrInCurProc = (ULONG_PTR)GetProcAddress((HMODULE)uKernelBaseInTargetProc, "LoadLibraryA");
	
	//Ŀ�����LoadLibrary��ַ
	ULONG_PTR uLoadLibraryAddrInTargetProc = (ULONG_PTR)(uKernelBaseInTargetProc + (uLoadLibraryAddrInCurProc - uKernelBaseInCurProc));

	//ULONG_PTR uLoadLibraryAddrInTargetProc= (ULONG_PTR)GetProcAddress(GetModuleHandle("Kernel32.dll"), "LoadLibraryA");

	//2.��ȡ�߳��б�
	THREADENTRY32 te32 = { sizeof(THREADENTRY32) };
	DWORD dwTidList[10254] = { 0 };
	DWORD Index = 0;
	BOOL bStatus = FALSE;
	HANDLE hThreadSnap = CreateToolhelp32Snapshot(TH32CS_SNAPTHREAD, 0);
	if ((HANDLE)-1 == hThreadSnap)
	{
		printf("CreateToolhelp32Snapshot:%d\n", GetLastError());
		return 0;
	}
	if (Thread32First(hThreadSnap, &te32))
	{
		do
		{
			if (te32.th32OwnerProcessID == dwPid)
			{
				bStatus = TRUE;
				dwTidList[Index++] = te32.th32ThreadID;
			}
		} while (Thread32Next(hThreadSnap, &te32));
	}
	CloseHandle(hThreadSnap);
	if (FALSE == bStatus)
	{
		printf("Thread32Next:%d\n", GetLastError());
		return FALSE;
	}

	//3.���δ��߳�
	bStatus = FALSE;
	CONTEXT Context;
	unsigned int i;
	ULONG_PTR uEIP = 0;
	HANDLE hThread;
	HANDLE hProcess = OpenProcess(PROCESS_ALL_ACCESS, FALSE, dwPid);
	if (NULL == hProcess)
	{
		printf("OpenProcess:%d\n", GetLastError());
		return FALSE;
	}

	//4.д��shellcode���޸�context
	for (i = 0; i < Index; i++)
	{
		//��ȡ�߳̾��
		hThread = OpenThread(THREAD_ALL_ACCESS,FALSE,dwTidList[i]);
		if (NULL == hThread)
		{
			printf("OpenThread:%d\n", GetLastError());
			continue;
		}

		//��ͣ�߳�
		DWORD dwSuspendCnt = SuspendThread(hThread);
		if ((DWORD)-1 == dwSuspendCnt)
		{
			printf("SuspendThread:%d\n", GetLastError());
			continue;
		}

		//��ȡContext
		ZeroMemory(&Context, sizeof(CONTEXT));
		Context.ContextFlags = CONTEXT_FULL;
		if (!GetThreadContext(hThread, &Context))
		{
			printf("GetThreadContext:%d\n", GetLastError());
			CloseHandle(hThread);
			continue;
		}
#ifdef _WIN64
		uEIP = Context.Rip;//����EIP
#else
		uEIP = Context.Eip;   //����EIP
#endif
		
							  
	    //����ռ�
		PBYTE lpData = (PBYTE)VirtualAllocEx(hProcess, NULL, 0x1000, MEM_COMMIT, PAGE_EXECUTE_READWRITE);
		if (NULL == lpData)
		{
			printf("VirtualAllocEx:%d\n", GetLastError());
			CloseHandle(hThread);
			continue;
		}

		//����Shellcode
		INJECT_DATA Data;
		ZeroMemory(&Data,sizeof(INJECT_DATA));
		PrepareShellCode(Data.ShellCode);     //��shellcodeд��INJECT_DATA.shellcode����
		lstrcpy(Data.szDllPath, szDllPath);   //��szDllPathд��INJECT_DATA.szDllPath����
		Data.AddrofLoadLibraryA = uLoadLibraryAddrInTargetProc;   //Ŀ�������LoadLibrary��ַ
		Data.OriginalEIP = uEIP;           //ԭʼEIP
		Data.lpDllPath= lpData + FIELD_OFFSET(INJECT_DATA, szDllPath); //szDllPath��Ŀ������е�λ��


		//��Ŀ�������д��INJECT_DATA
		SIZE_T dwRet = 0;  
		if (!WriteProcessMemory(hProcess, lpData, &Data, sizeof(INJECT_DATA), &dwRet))
		{
			printf("WriteProcessMemory:%d\n", GetLastError());
			continue;
		}

		//����EIP,ʹ��EIPָ��Shellcode����ʼ��ַ
#ifdef _WIN64
		Context.Rip = (ULONG_PTR)lpData;
#else
		Context.Eip = (ULONG_PTR)lpData;
#endif

		//SetConText�����õ�ConTextд���߳�
		if (!SetThreadContext(hThread, &Context))
		{
			printf("SetThreadContext:%d\n", GetLastError());
			CloseHandle(hThread);
			return FALSE;
		}

		//�ָ��߳�ִ��
		DWORD dwResumeRet = ResumeThread(hThread);
		if (dwResumeRet == (DWORD)-1)
		{
			printf("ResumeThread:%d\n", GetLastError());
			CloseHandle(hThread);
			continue;
		}
		CloseHandle(hThread);
		Sleep(1000);
	}
	CloseHandle(hProcess);
	return TRUE;
}


//Ѱ��ָ����Procname��PID
DWORD ProcesstoPid(char *szProcessname)
{
	HANDLE hProcessSnap = NULL;
	DWORD ProcessId = 0;
	PROCESSENTRY32 pe32 = { sizeof(PROCESSENTRY32) };

	hProcessSnap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
	if ((HANDLE)-1 == hProcessSnap)
	{
		printf("CreateToolhelp32Snapshot:%d", GetLastError());
		return 0;
	}
	if (Process32First(hProcessSnap, &pe32))
	{
		do
		{
			if (!lstrcmp(pe32.szExeFile, szProcessname))
			{
				ProcessId = pe32.th32ProcessID;
				break;
			}


		} while (Process32Next(hProcessSnap, &pe32));
	}
	else
	{
		printf("Process32First:%d", GetLastError());
		return 0;
	}
	CloseHandle(hProcessSnap);
	return ProcessId;
}


//��ȡKernel32��Ŀ�꺯���Ļ���ַ
ULONG_PTR GetModuleHandleInProc(DWORD dwPid, char* szModuleNameToFind)
{
	HMODULE hMods[1024];    //���Module���������
	DWORD cbNeeded;
	unsigned int i = 0;
	char *pCompare = NULL;   //�ݴ�Աȵ�Dll����
	ULONG_PTR uRet=NULL;


	HANDLE hProcess = OpenProcess(PROCESS_QUERY_INFORMATION | PROCESS_VM_READ,  //��ȡ�����ڴ���Ϣ���ռ�������Ϣ
		FALSE,
		dwPid);
	if (NULL == hProcess)
		return 0;

	//���������е�����ģ�飬�����hMods������
	BOOL bRet = FALSE;
	//bRet = EnumProcessModulesEx(hProcess, hMods, sizeof(hMods), &cbNeeded, LIST_MODULES_32BIT);
	bRet = EnumProcessModules(hProcess, hMods, sizeof(hMods), &cbNeeded);
	//���64λ����ϵͳ�����32λ���򣬻ᱨ299�Ĵ�����������¿���ʹ��EnumProcessModulesEx
	if (TRUE==bRet)
	{
		for (i = 0; i < cbNeeded / sizeof(HANDLE); i++)
		{
			char szModName[MAX_PATH];
			//��ȡָ��ģ�����ĵ��ļ���
			if (GetModuleFileNameEx(hProcess, hMods[i], szModName, sizeof(szModName) / sizeof(char)))
			{
				//�Ӻ���ǰ��ȡ'\\'���ַ�
				pCompare = strrchr(szModName, '\\');
				//���˽�ȡʧ�ܵ����
				pCompare = (pCompare == NULL) ? szModName : (pCompare + 1);
				if (lstrcmp(pCompare, szModuleNameToFind)==0)
				{
					uRet = (ULONG_PTR)hMods[i];
					break;
				}
			}
		}
	}
	else
	{
		printf("EnumProcessModules:%d", GetLastError());
		return NULL;
	}
	CloseHandle(hProcess);
	return uRet;
}

void PrepareShellCode(BYTE *pOutShellCode)
{

#ifdef _WIN64
	BYTE *pShellcodeStart = (BYTE*)ShellCodeFun64;
#else
	BYTE *pShellcodeStart = (BYTE*)ShellCodeFun;
#endif

	BYTE *pShellcodeEnd = 0;
	SIZE_T ShellcodeSize = 0;
	if (pShellcodeStart[0] == 0xE9)
	{
		//Debug ������ͷ��һ����תָ��������ȡ����������ַ
		pShellcodeStart = pShellcodeStart + *(ULONG*)(pShellcodeStart + 1) + 5;
	}

	//����ShellCode������־
	pShellcodeEnd = pShellcodeStart;
	while (memcmp(pShellcodeEnd, "\x90\x90\x90\x90\x90", 5)!=0)
	{
		pShellcodeEnd++;
	}
	ShellcodeSize = pShellcodeEnd - pShellcodeStart;
	memcpy(pOutShellCode, pShellcodeStart, ShellcodeSize);
}

#ifndef _WIN64
_declspec(naked)
VOID ShellCodeFun(VOID)
{
	_asm
	{
		push eax    //ռλ������ת��ַʹ��,eax���ᱻԭʼEIP���
		pushad 
		pushfd
		call L001
L001:
		pop ebx       //�Զ�λ��ebx��ŵ��ǵ�ǰָ���EIP
		sub ebx,8     //��ǰָ���������λ��INJECT_DATA��ʼ����
		push dword ptr ds:[ebx+0x34]    //szDllPath
		call dword ptr ds:[ebx+30]      //LoadLibrary
		mov eax, dword ptr ds : [ebx + 0x38] //OriginalEIP
		xchg eax,[esp+0x24]              //��ԭ����EIP������ջ��
		popfd
		popad
		retn          //��ת��ԭʼEIP
		nop
		nop
		nop
		nop
		nop


	}
}
#endif




/*
-----------------------------------------------------------------------
��12��  ע�뼼��
����������ܣ����İ棩��
(c)  ��ѩѧԺ www.kanxue.com 2000-2018
-----------------------------------------------------------------------

// SetContextInject.cpp : Defines the entry point for the console application.
//

#include <stdio.h>
#include <windows.h>
#include <TLHELP32.H>
#include <Psapi.h>

#pragma comment(lib,"psapi.lib")

typedef struct _INJECT_DATA
{
	BYTE ShellCode[0x30];           //offset 0x00
	ULONG_PTR AddrofLoadLibraryA;   //offset 0x30
	PBYTE lpDllPath;                //offset 0x34
	ULONG_PTR OriginalEIP;          //offset 0x38
	char szDllPath[MAX_PATH];       //offset 0x3C
}INJECT_DATA;

#ifdef _WIN64
EXTERN_C VOID ShellCodeFun64(VOID);
#else
VOID ShellCodeFun(VOID);
#endif

ULONG_PTR GetModuleHandleInProcess(DWORD processID, char *szModuleName);
DWORD ProcesstoPid(char *Processname);
BOOL InjectModuleToProcessBySetContext(DWORD dwPid, char *szDllFullPath);
VOID PrepareShellCode(BYTE *pShellCode);

int main(int argc, char* argv[])
{
#ifdef _WIN64
	char szDllPath[MAX_PATH] = "D://MsgDll64.dll";
	DWORD dwPid = ProcesstoPid("notepad.exe");
#else
	char szDllPath[MAX_PATH] = "F:\\Program2016\\DllInjection\\MsgDll.dll";
	DWORD dwPid = ProcesstoPid("notepad.exe");
#endif
	if (dwPid == 0)
	{
		printf("[-] Target Process Not Found!\n");
		return 0;
	}
	printf("[*] Target Process Pid = %d\n", dwPid);
	BOOL bResult = InjectModuleToProcessBySetContext(dwPid, szDllPath);
	printf("[*] Result = %d\n", bResult);
	return 0;
}


#ifndef _WIN64
__declspec (naked)
VOID ShellCodeFun(VOID)
{
	__asm
	{
		push eax //ռλ,һ���������ת��ַ
		pushad   //��С0x20
		pushfd   //��С0x04
		call L001
		L001 :
		pop ebx
			sub ebx, 8
			push dword ptr ds : [ebx + 0x34] //szDllPath
			call dword ptr ds : [ebx + 0x30] //LoadLibraryA
			mov eax, dword ptr ds : [ebx + 0x38] //OriginalEIP
			xchg eax, [esp + 0x24] //��ԭ����EIP������ջ��
			popfd
			popad
			retn //jmp to OriginalEIP
			nop
			nop
			nop
			nop
			nop
	}
}
#endif


VOID PrepareShellCode(BYTE *pOutShellCode)
{
#ifdef _WIN64
	BYTE *pShellcodeStart = (BYTE*)ShellCodeFun64;
#else
	BYTE *pShellcodeStart = (BYTE*)ShellCodeFun;
#endif

	BYTE *pShellcodeEnd = 0;
	SIZE_T ShellCodeSize = 0;
	if (pShellcodeStart[0] == 0xE9)
	{
		//Debugģʽ�£�������ͷ��һ����תָ�����ȡ����������ַ
		pShellcodeStart = pShellcodeStart + *(ULONG*)(pShellcodeStart + 1) + 5;
	}

	//����Shellcode������־
	pShellcodeEnd = pShellcodeStart;
	while (memcmp(pShellcodeEnd, "\x90\x90\x90\x90\x90", 5) != 0)
	{
		pShellcodeEnd++;
	}

	ShellCodeSize = pShellcodeEnd - pShellcodeStart;
	printf("[*] Shellcode Len = %d\n", ShellCodeSize);
	memcpy(pOutShellCode, pShellcodeStart, ShellCodeSize);


}
BOOL InjectModuleToProcessBySetContext(DWORD dwPid, char *szDllFullPath)
{
	SIZE_T   dwRet = 0;
	BOOL    bStatus = FALSE;
	PBYTE   lpData = NULL;
	SIZE_T  uLen = 0x1000;
	INJECT_DATA Data;
	HANDLE hProcess, hThread;
	DWORD i = 0;


	//1.��ȡĿ�������LoadLibraryA�ĵ�ַ
	//֮������ô��ȡ���ǿ�����ASLR��Ӱ�죬��ʱĿ�������kernel32.dll�ļ���λ�ò�һ���뱾������ͬ
	ULONG_PTR uKernelBaseInTargetProc = GetModuleHandleInProcess(dwPid, "kernel32.dll");
	ULONG_PTR uKernelBaseInCurProc = (ULONG_PTR)GetModuleHandle("kernel32.dll");
	ULONG_PTR uLoadLibraryAddrInCurProc = (ULONG_PTR)GetProcAddress((HMODULE)uKernelBaseInTargetProc, "LoadLibraryA");
	ULONG_PTR uLoadLibraryAddrInTargetProc = uLoadLibraryAddrInCurProc - uKernelBaseInCurProc + uKernelBaseInTargetProc;
	printf("[*] Ŀ������� LoadLibraryA Addr = 0x%p\n", uLoadLibraryAddrInTargetProc);

	//2.��ȡĿ������е��߳��б�
	THREADENTRY32 te32 = { sizeof(THREADENTRY32) };
	DWORD dwTidList[1024] = { 0 };
	DWORD Index = 0;
	HANDLE hThreadSnap = CreateToolhelp32Snapshot(TH32CS_SNAPTHREAD, 0);
	if (hThreadSnap == INVALID_HANDLE_VALUE)
		return FALSE;

	bStatus = FALSE;
	printf("[*] ��ʼö��Ŀ������е��߳�.\n");
	// ö�������߳�  
	if (Thread32First(hThreadSnap, &te32))
	{
		do {
			// �ж��Ƿ�Ŀ������е��߳�  
			if (te32.th32OwnerProcessID == dwPid)
			{
				bStatus = TRUE;
				dwTidList[Index++] = te32.th32ThreadID;
			}

		} while (Thread32Next(hThreadSnap, &te32));
	}

	CloseHandle(hThreadSnap);

	if (!bStatus)
	{
		printf("[-] �޷��õ�Ŀ����̵��߳��б�!\n");
		return FALSE;
	}
	printf("[*] �߳�ö����ϣ����� %d ���߳�.\n", Index);

	//3. ��Ŀ�����  �������ڴ棬д��Shellcode�Ͳ���
	ULONG_PTR uDllPathAddr = 0;
	hProcess = OpenProcess(PROCESS_ALL_ACCESS, FALSE, dwPid);
	if (hProcess == NULL)
	{
		printf("[-] �޷���Ŀ�����!\n");
		return FALSE;
	}

	//3.���δ��̣߳���ȡContext
	bStatus = FALSE;
	CONTEXT Context;
	ULONG_PTR uEIP = 0;
	for (i = 0; i < Index; i++)
	{
		hThread = OpenThread(THREAD_ALL_ACCESS, FALSE, dwTidList[i]);
		if (hThread == NULL)
		{
			printf("[-] ���߳� %d ʧ��!\n", dwTidList[i]);
			continue;
		}

		printf("[*] ���߳� %d �ɹ�.\n", dwTidList[i]);

		//��ͣ�߳�
		DWORD dwSuspendCnt = SuspendThread(hThread);
		if (dwSuspendCnt == (DWORD)-1)
		{
			printf("[-] ��ͣ�߳� %d ʧ��!\n", dwTidList[i]);
			CloseHandle(hThread);
			continue;
		}

		printf("[*] ��ͣ�߳� %d �ɹ� Cnt = %d.\n", dwTidList[i], dwSuspendCnt);
		//��ȡContext
		ZeroMemory(&Context, sizeof(CONTEXT));
		Context.ContextFlags = CONTEXT_FULL;
		if (!GetThreadContext(hThread, &Context))
		{
			printf("[-] �޷���ȡ�߳� %d ��Context!\n", dwTidList[i]);
			CloseHandle(hThread);
			continue;
		}

#ifdef _WIN64
		uEIP = Context.Rip;
#else
		uEIP = Context.Eip;
#endif
		printf("[*] ��ȡ�߳� %d ��Context�ɹ� EIP = 0x%p\n", dwTidList[i], uEIP);

		// ����ռ�  
		lpData = (PBYTE)VirtualAllocEx(hProcess, NULL, 0x1000, MEM_COMMIT, PAGE_EXECUTE_READWRITE);
		if (lpData == NULL)
		{
			printf("[-] ��Ŀ����������ڴ�ʧ��!\n");
			CloseHandle(hThread);
			continue;
		}

		printf("[*] ��Ŀ������������ڴ�ɹ�, lpData = 0x%p\n", lpData);

		//����ShellCode
		ZeroMemory(&Data, sizeof(INJECT_DATA));
		PrepareShellCode(Data.ShellCode);
		lstrcpy(Data.szDllPath, szDllFullPath); //Dll·��
		Data.AddrofLoadLibraryA = uLoadLibraryAddrInTargetProc; //LoadLibraryA�ĵ�ַ
		Data.OriginalEIP = uEIP; //ԭʼ��EIP��ַ
		Data.lpDllPath = lpData + FIELD_OFFSET(INJECT_DATA, szDllPath); //szDllPath��Ŀ������е�λ��
		printf("[*] ShellCode������.\n");

		//��Ŀ�����д��ShellCode
		if (!WriteProcessMemory(hProcess, lpData, &Data, sizeof(INJECT_DATA), &dwRet))
		{
			printf("[-] ��Ŀ�����д��ShellCodeʧ��!\n");
			CloseHandle(hThread);
			CloseHandle(hProcess);
			return FALSE;
		}

		printf("[*] ��Ŀ�����д��ShellCode�ɹ�.\n");

		//�����̵߳�Context,ʹEIPָ��ShellCode��ʼ��ַ
#ifdef _WIN64
		Context.Rip = (ULONG_PTR)lpData;
#else
		Context.Eip = (ULONG_PTR)lpData;
#endif
		//����Context
		if (!SetThreadContext(hThread, &Context))
		{
			printf("[-] �޷������߳� %d ��Context!\n", dwTidList[i]);
			CloseHandle(hThread);
			continue;
		}

		printf("[*] �����߳� %d ��Context�ɹ�.\n", dwTidList[i]);

		//�ָ��߳�ִ��
		dwSuspendCnt = ResumeThread(hThread);
		if (dwSuspendCnt == (DWORD)-1)
		{
			printf("[-] �ָ��߳� %d ʧ��!\n", dwTidList[i]);
			CloseHandle(hThread);
			continue;
		}

		printf("[*] �ָ��߳� %d �ɹ�. Cnt = %d\n", dwTidList[i], dwSuspendCnt);

		bStatus = TRUE;
		CloseHandle(hThread);

		//Sleepһ��ʱ�䣬��������һ�̲߳�������ȷ���ɹ���
		Sleep(1000);


	}

	CloseHandle(hProcess);
	printf("[*] ����ȫ�����.\n");

	return bStatus;
}

ULONG_PTR GetModuleHandleInProcess(DWORD processID, char *szModuleNameToFind)
{
	HMODULE hMods[1024];
	HANDLE hProcess;
	DWORD cbNeeded;
	unsigned int i;
	char *pCompare = NULL;
	ULONG_PTR uResult = 0;

	// Print the process identifier.

	printf("\nProcess ID: %u\n", processID);

	// Get a list of all the modules in this process.

	hProcess = OpenProcess(
		PROCESS_QUERY_INFORMATION | PROCESS_VM_READ,
		FALSE,
		processID
	);
	if (NULL == hProcess)
		return 0;

	if (EnumProcessModules(hProcess, hMods, sizeof(hMods), &cbNeeded))
	{
		for (i = 0; i < (cbNeeded / sizeof(HMODULE)); i++)
		{
			char szModName[MAX_PATH];

			// Get the full path to the module's file.

			if (GetModuleFileNameEx(hProcess, hMods[i], szModName,
				sizeof(szModName) / sizeof(char)))
			{
				// Print the module name and handle value.
				pCompare = strrchr(szModName, '\\');
				pCompare = (pCompare == NULL) ? szModName : (pCompare + 1);
				if (lstrcmp(pCompare, szModuleNameToFind) == 0)
				{
					uResult = (ULONG_PTR)hMods[i];
					break;
				}
			}
		}
	}

	CloseHandle(hProcess);

	return uResult;
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
			if (!lstrcmp(Processname, pe32.szExeFile)) //�ж��Ƿ���ṩ�Ľ�������ȣ��ǣ����ؽ��̵�ID
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
*/