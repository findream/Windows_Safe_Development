#include <stdio.h>
#include <windows.h>
#include <TLHELP32.H>


#ifdef _WIN64
char g_szDllpath[MAX_PATH] = "D://MsgDll64.dll";
char g_ProcName[MAX_PATH] = "notepad.exe";
#else
char  g_szDllpath[MAX_PATH] = "D://MsgDll.dll";
char g_ProcName[MAX_PATH] = "notepad.exe";
#endif



DWORD ProcesstoPid(char *Processname); 
BOOL InjectModuleToProcessById(DWORD dwPid, char *szDllFullPath);


int main(int argc, char* argv[])
{
	DWORD dwPid = NULL;
	dwPid= ProcesstoPid(g_ProcName);
	if (NULL == dwPid)
	{
		printf("ProcesstoId:%d\n", GetLastError());
		return 0;
	}
	BOOL bRet = FALSE;
	bRet = InjectModuleToProcessById(dwPid, g_szDllpath);
	if (FALSE == bRet)
	{
		printf("InjectModuleToProcessById:%d\n", GetLastError());
		return 0;
	}
	getchar();
	return 0;
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
		printf("Process32First:%d\n", GetLastError());
		return 0;
	}
	CloseHandle(hProcessSnap); //关闭系统进程快照的句柄
	return ProcessId;
}


BOOL InjectModuleToProcessById(DWORD dwPid, char *szDllFullPath)
{
	SIZE_T stSize = 0;
	HANDLE hProcess = NULL;
	LPVOID lpData = NULL;
	BOOL bStatus = FALSE;   //执行状态
	THREADENTRY32 te32 = { sizeof(THREADENTRY32) };    //线程结构体
	HANDLE hThreadSnap = NULL;


	//向目标进程中写入DllFullPath
	hProcess = OpenProcess(PROCESS_ALL_ACCESS, FALSE, dwPid);
	if (hProcess)
	{
		lpData = VirtualAllocEx(hProcess, lpData, lstrlen(szDllFullPath) + 1, MEM_COMMIT, PAGE_READWRITE);
		if (lpData)
		{
			bStatus = WriteProcessMemory(hProcess, lpData, szDllFullPath, lstrlen(szDllFullPath) + 1, &stSize);
			if (FALSE == bStatus)
			{
				printf("WriteProcessMemory:%d\n", GetLastError());
				return NULL;
			}
		}
		else
		{
			printf("VirtualAllocEx:%d\n", GetLastError());
			return NULL;
		}
	}
	else
	{
		printf("OpenProcess:%d\n", GetLastError());
		return NULL;
	}
	CloseHandle(hProcess);

	//向目标进程中所有线程添加APC例程
	hThreadSnap = CreateToolhelp32Snapshot(TH32CS_SNAPTHREAD, 0);
	if (INVALID_HANDLE_VALUE == hThreadSnap)
	{
		printf("CreateToolhelp32Snapshot:%d\n", GetLastError());
		return NULL;
	}
	bStatus = FALSE;
	if (Thread32First(hThreadSnap, &te32))
	{
		do
		{
			//线程所属的进程ID==目标进程ID
			if (te32.th32OwnerProcessID == dwPid)   
			{
				//获取当前线程句柄
				HANDLE hThread = OpenThread(THREAD_ALL_ACCESS,FALSE,te32.th32ThreadID);
				DWORD dwRet = NULL;
				
				//插入APC队列
				dwRet=QueueUserAPC((PAPCFUNC)LoadLibraryA, hThread, (ULONG_PTR)lpData);
				if (NULL == dwRet)
				{
					printf("QueueUserAPC:%d\n", GetLastError());
					return NULL;
				}
				CloseHandle(hThread);

			}

		} while (Thread32Next(hThreadSnap, &te32));
	}
	CloseHandle(hThreadSnap);
	return TRUE;
}