#include <stdio.h>
#include <windows.h>
#include <TlHelp32.h>
#include <Psapi.h>
#include <string.h>

#pragma comment(lib,"psapi.lib")

//定义shellcode结构体
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



//函数声明
ULONG_PTR GetModuleHandleInProc(DWORD dwPid, char* ModuleName);    //获取Kernel32在目标函数的基地址
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


//注入函数
BOOL InjectModuleToProcessBySetContext(DWORD dwPid, char* szDllPath)
{

	//1.获取目标进程中LoadLibrary的地址
	//为了避免ASLR的影响，使用BaseAddressOfTargeProcess+(LoadLibraryAddressOfCurrentProcesss-BaseAddressOfCurrentProcess)

	//目标进程Kernel32.dll的基地址
	ULONG_PTR uKernelBaseInTargetProc = GetModuleHandleInProc(dwPid, "KERNEL32.DLL");

	//当前进程的基地址
	ULONG_PTR uKernelBaseInCurProc = (ULONG_PTR)GetModuleHandle("kernel32.dll");
	

	//当前进程LoadLibrary函数地址
	//ULONG_PTR uLoadLibraryAddrInCurProc = (ULONG_PTR)GetProcAddress(GetModuleHandle("Kernel32.dll"), "LoadLibraryA");
	ULONG_PTR uLoadLibraryAddrInCurProc = (ULONG_PTR)GetProcAddress((HMODULE)uKernelBaseInTargetProc, "LoadLibraryA");
	
	//目标进程LoadLibrary地址
	ULONG_PTR uLoadLibraryAddrInTargetProc = (ULONG_PTR)(uKernelBaseInTargetProc + (uLoadLibraryAddrInCurProc - uKernelBaseInCurProc));

	//ULONG_PTR uLoadLibraryAddrInTargetProc= (ULONG_PTR)GetProcAddress(GetModuleHandle("Kernel32.dll"), "LoadLibraryA");

	//2.获取线程列表
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

	//3.依次打开线程
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

	//4.写入shellcode，修改context
	for (i = 0; i < Index; i++)
	{
		//获取线程句柄
		hThread = OpenThread(THREAD_ALL_ACCESS,FALSE,dwTidList[i]);
		if (NULL == hThread)
		{
			printf("OpenThread:%d\n", GetLastError());
			continue;
		}

		//暂停线程
		DWORD dwSuspendCnt = SuspendThread(hThread);
		if ((DWORD)-1 == dwSuspendCnt)
		{
			printf("SuspendThread:%d\n", GetLastError());
			continue;
		}

		//获取Context
		ZeroMemory(&Context, sizeof(CONTEXT));
		Context.ContextFlags = CONTEXT_FULL;
		if (!GetThreadContext(hThread, &Context))
		{
			printf("GetThreadContext:%d\n", GetLastError());
			CloseHandle(hThread);
			continue;
		}
#ifdef _WIN64
		uEIP = Context.Rip;//保存EIP
#else
		uEIP = Context.Eip;   //保存EIP
#endif
		
							  
	    //分配空间
		PBYTE lpData = (PBYTE)VirtualAllocEx(hProcess, NULL, 0x1000, MEM_COMMIT, PAGE_EXECUTE_READWRITE);
		if (NULL == lpData)
		{
			printf("VirtualAllocEx:%d\n", GetLastError());
			CloseHandle(hThread);
			continue;
		}

		//构造Shellcode
		INJECT_DATA Data;
		ZeroMemory(&Data,sizeof(INJECT_DATA));
		PrepareShellCode(Data.ShellCode);     //将shellcode写入INJECT_DATA.shellcode区域
		lstrcpy(Data.szDllPath, szDllPath);   //将szDllPath写入INJECT_DATA.szDllPath区域
		Data.AddrofLoadLibraryA = uLoadLibraryAddrInTargetProc;   //目标进程中LoadLibrary地址
		Data.OriginalEIP = uEIP;           //原始EIP
		Data.lpDllPath= lpData + FIELD_OFFSET(INJECT_DATA, szDllPath); //szDllPath在目标进程中的位置


		//向目标进程中写入INJECT_DATA
		SIZE_T dwRet = 0;  
		if (!WriteProcessMemory(hProcess, lpData, &Data, sizeof(INJECT_DATA), &dwRet))
		{
			printf("WriteProcessMemory:%d\n", GetLastError());
			continue;
		}

		//设置EIP,使得EIP指向Shellcode的起始地址
#ifdef _WIN64
		Context.Rip = (ULONG_PTR)lpData;
#else
		Context.Eip = (ULONG_PTR)lpData;
#endif

		//SetConText将设置的ConText写入线程
		if (!SetThreadContext(hThread, &Context))
		{
			printf("SetThreadContext:%d\n", GetLastError());
			CloseHandle(hThread);
			return FALSE;
		}

		//恢复线程执行
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


//寻找指定的Procname的PID
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


//获取Kernel32在目标函数的基地址
ULONG_PTR GetModuleHandleInProc(DWORD dwPid, char* szModuleNameToFind)
{
	HMODULE hMods[1024];    //存放Module句柄的数组
	DWORD cbNeeded;
	unsigned int i = 0;
	char *pCompare = NULL;   //暂存对比的Dll名称
	ULONG_PTR uRet=NULL;


	HANDLE hProcess = OpenProcess(PROCESS_QUERY_INFORMATION | PROCESS_VM_READ,  //读取进程内存信息和收集进程信息
		FALSE,
		dwPid);
	if (NULL == hProcess)
		return 0;

	//检索进程中的所有模块，存放在hMods数组中
	BOOL bRet = FALSE;
	//bRet = EnumProcessModulesEx(hProcess, hMods, sizeof(hMods), &cbNeeded, LIST_MODULES_32BIT);
	bRet = EnumProcessModules(hProcess, hMods, sizeof(hMods), &cbNeeded);
	//如果64位操作系统编译的32位程序，会报299的错误，这种情况下可以使用EnumProcessModulesEx
	if (TRUE==bRet)
	{
		for (i = 0; i < cbNeeded / sizeof(HANDLE); i++)
		{
			char szModName[MAX_PATH];
			//获取指定模块句柄的的文件名
			if (GetModuleFileNameEx(hProcess, hMods[i], szModName, sizeof(szModName) / sizeof(char)))
			{
				//从后向前截取'\\'的字符
				pCompare = strrchr(szModName, '\\');
				//过滤截取失败的情况
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
		//Debug 函数开头是一个跳转指定，这里取它的真正地址
		pShellcodeStart = pShellcodeStart + *(ULONG*)(pShellcodeStart + 1) + 5;
	}

	//搜索ShellCode结束标志
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
		push eax    //占位，做跳转地址使用,eax将会被原始EIP替代
		pushad 
		pushfd
		call L001
L001:
		pop ebx       //自定位，ebx存放的是当前指令的EIP
		sub ebx,8     //当前指令不计数，定位到INJECT_DATA起始部分
		push dword ptr ds:[ebx+0x34]    //szDllPath
		call dword ptr ds:[ebx+30]      //LoadLibrary
		mov eax, dword ptr ds : [ebx + 0x38] //OriginalEIP
		xchg eax,[esp+0x24]              //将原来的EIP交换到栈上
		popfd
		popad
		retn          //跳转到原始EIP
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
第12章  注入技术
《加密与解密（第四版）》
(c)  看雪学院 www.kanxue.com 2000-2018
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
		push eax //占位,一会儿用做跳转地址
		pushad   //大小0x20
		pushfd   //大小0x04
		call L001
		L001 :
		pop ebx
			sub ebx, 8
			push dword ptr ds : [ebx + 0x34] //szDllPath
			call dword ptr ds : [ebx + 0x30] //LoadLibraryA
			mov eax, dword ptr ds : [ebx + 0x38] //OriginalEIP
			xchg eax, [esp + 0x24] //将原来的EIP交换到栈上
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
		//Debug模式下，函数开头是一个跳转指令，这里取它的真正地址
		pShellcodeStart = pShellcodeStart + *(ULONG*)(pShellcodeStart + 1) + 5;
	}

	//搜索Shellcode结束标志
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


	//1.获取目标进程中LoadLibraryA的地址
	//之所以这么获取，是考虑了ASLR的影响，此时目标进程中kernel32.dll的加载位置不一定与本进程相同
	ULONG_PTR uKernelBaseInTargetProc = GetModuleHandleInProcess(dwPid, "kernel32.dll");
	ULONG_PTR uKernelBaseInCurProc = (ULONG_PTR)GetModuleHandle("kernel32.dll");
	ULONG_PTR uLoadLibraryAddrInCurProc = (ULONG_PTR)GetProcAddress((HMODULE)uKernelBaseInTargetProc, "LoadLibraryA");
	ULONG_PTR uLoadLibraryAddrInTargetProc = uLoadLibraryAddrInCurProc - uKernelBaseInCurProc + uKernelBaseInTargetProc;
	printf("[*] 目标进程中 LoadLibraryA Addr = 0x%p\n", uLoadLibraryAddrInTargetProc);

	//2.获取目标进程中的线程列表
	THREADENTRY32 te32 = { sizeof(THREADENTRY32) };
	DWORD dwTidList[1024] = { 0 };
	DWORD Index = 0;
	HANDLE hThreadSnap = CreateToolhelp32Snapshot(TH32CS_SNAPTHREAD, 0);
	if (hThreadSnap == INVALID_HANDLE_VALUE)
		return FALSE;

	bStatus = FALSE;
	printf("[*] 开始枚举目标进程中的线程.\n");
	// 枚举所有线程  
	if (Thread32First(hThreadSnap, &te32))
	{
		do {
			// 判断是否目标进程中的线程  
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
		printf("[-] 无法得到目标进程的线程列表!\n");
		return FALSE;
	}
	printf("[*] 线程枚举完毕，共有 %d 个线程.\n", Index);

	//3. 打开目标进程  ，申请内存，写入Shellcode和参数
	ULONG_PTR uDllPathAddr = 0;
	hProcess = OpenProcess(PROCESS_ALL_ACCESS, FALSE, dwPid);
	if (hProcess == NULL)
	{
		printf("[-] 无法打开目标进程!\n");
		return FALSE;
	}

	//3.依次打开线程，获取Context
	bStatus = FALSE;
	CONTEXT Context;
	ULONG_PTR uEIP = 0;
	for (i = 0; i < Index; i++)
	{
		hThread = OpenThread(THREAD_ALL_ACCESS, FALSE, dwTidList[i]);
		if (hThread == NULL)
		{
			printf("[-] 打开线程 %d 失败!\n", dwTidList[i]);
			continue;
		}

		printf("[*] 打开线程 %d 成功.\n", dwTidList[i]);

		//暂停线程
		DWORD dwSuspendCnt = SuspendThread(hThread);
		if (dwSuspendCnt == (DWORD)-1)
		{
			printf("[-] 暂停线程 %d 失败!\n", dwTidList[i]);
			CloseHandle(hThread);
			continue;
		}

		printf("[*] 暂停线程 %d 成功 Cnt = %d.\n", dwTidList[i], dwSuspendCnt);
		//获取Context
		ZeroMemory(&Context, sizeof(CONTEXT));
		Context.ContextFlags = CONTEXT_FULL;
		if (!GetThreadContext(hThread, &Context))
		{
			printf("[-] 无法获取线程 %d 的Context!\n", dwTidList[i]);
			CloseHandle(hThread);
			continue;
		}

#ifdef _WIN64
		uEIP = Context.Rip;
#else
		uEIP = Context.Eip;
#endif
		printf("[*] 获取线程 %d 的Context成功 EIP = 0x%p\n", dwTidList[i], uEIP);

		// 分配空间  
		lpData = (PBYTE)VirtualAllocEx(hProcess, NULL, 0x1000, MEM_COMMIT, PAGE_EXECUTE_READWRITE);
		if (lpData == NULL)
		{
			printf("[-] 在目标进程申请内存失败!\n");
			CloseHandle(hThread);
			continue;
		}

		printf("[*] 在目标进程中申请内存成功, lpData = 0x%p\n", lpData);

		//构造ShellCode
		ZeroMemory(&Data, sizeof(INJECT_DATA));
		PrepareShellCode(Data.ShellCode);
		lstrcpy(Data.szDllPath, szDllFullPath); //Dll路径
		Data.AddrofLoadLibraryA = uLoadLibraryAddrInTargetProc; //LoadLibraryA的地址
		Data.OriginalEIP = uEIP; //原始的EIP地址
		Data.lpDllPath = lpData + FIELD_OFFSET(INJECT_DATA, szDllPath); //szDllPath在目标进程中的位置
		printf("[*] ShellCode填充完毕.\n");

		//向目标进程写入ShellCode
		if (!WriteProcessMemory(hProcess, lpData, &Data, sizeof(INJECT_DATA), &dwRet))
		{
			printf("[-] 向目标进程写入ShellCode失败!\n");
			CloseHandle(hThread);
			CloseHandle(hProcess);
			return FALSE;
		}

		printf("[*] 向目标进程写入ShellCode成功.\n");

		//设置线程的Context,使EIP指向ShellCode起始地址
#ifdef _WIN64
		Context.Rip = (ULONG_PTR)lpData;
#else
		Context.Eip = (ULONG_PTR)lpData;
#endif
		//设置Context
		if (!SetThreadContext(hThread, &Context))
		{
			printf("[-] 无法设置线程 %d 的Context!\n", dwTidList[i]);
			CloseHandle(hThread);
			continue;
		}

		printf("[*] 设置线程 %d 的Context成功.\n", dwTidList[i]);

		//恢复线程执行
		dwSuspendCnt = ResumeThread(hThread);
		if (dwSuspendCnt == (DWORD)-1)
		{
			printf("[-] 恢复线程 %d 失败!\n", dwTidList[i]);
			CloseHandle(hThread);
			continue;
		}

		printf("[*] 恢复线程 %d 成功. Cnt = %d\n", dwTidList[i], dwSuspendCnt);

		bStatus = TRUE;
		CloseHandle(hThread);

		//Sleep一段时间，继续对下一线程操作，以确保成功率
		Sleep(1000);


	}

	CloseHandle(hProcess);
	printf("[*] 操作全部完毕.\n");

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
			if (!lstrcmp(Processname, pe32.szExeFile)) //判断是否和提供的进程名相等，是，返回进程的ID
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
*/