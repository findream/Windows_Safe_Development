#include <stdio.h>
#include <windows.h>
#include <tlhelp32.h>

DWORD GetProcessIdByName(char *ProcessName);
void CreateShellCode(int ret, int str, unsigned char** shellcode, int* shellcodeSize);

int main(int agrc, char* argv)
{
#ifdef _WIN64
	char DllPath[] = "D:\\MsgDll64.dll";
	char ProcessName[] = "HostProc64.exe";
#else
	char DllPath[] = "D:\\MsgDll.dll";
	char ProcessName[] = "HostProc.exe";
#endif

	//shellcode
	unsigned char *ShellCode;
	int ShellCodeLength;
	LPVOID Remote_ShellCodePtr = NULL;

	//1.打开进程，获取目标进程句柄
	DWORD ProcessId = NULL;
	ProcessId = GetProcessIdByName(ProcessName);

	HANDLE hProcess = NULL;
	hProcess = OpenProcess(PROCESS_ALL_ACCESS, FALSE, ProcessId);
	if ((HANDLE)-1 == hProcess)
	{
		printf("OpenProcess:%d\n", GetLastError());
		return FALSE;
	}
	printf("OpenProcess:%X\n", hProcess);

	//2.为写入DLLPATH开辟空间
	LPVOID Remote_DllPath = NULL;
	Remote_DllPath = VirtualAllocEx(hProcess,
		NULL,
		lstrlen(DllPath) + 1,
		MEM_COMMIT,
		PAGE_READWRITE);
	if (Remote_DllPath == NULL)
	{
		printf("VirtualAllocEx_DllPath:%d\n", GetLastError());
		return FALSE;
	}
	printf("VirtualAllocEx_DllPath:%X\n", Remote_DllPath);


	//3.获取线程Context
	CONTEXT ctx;
	ctx.ContextFlags = CONTEXT_CONTROL;

	//3.1遍历线程，并存储TID
	THREADENTRY32 te32 = { sizeof(THREADENTRY32) };
	DWORD dwTidList[1024] = { 0 };
	DWORD  Index = 0;
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
			if (te32.th32OwnerProcessID == ProcessId)
			{
				bStatus = TRUE;
				dwTidList[Index] = te32.th32ThreadID;
			//	printf("%d:%d:%d\n", Index, dwTidList[Index], te32.th32ThreadID);
				Index++;
			}
		} while (Thread32Next(hThreadSnap, &te32));
	}
	CloseHandle(hThreadSnap);
	if (FALSE == bStatus)
	{
		printf("Thread32Next:%d\n", GetLastError());
		return FALSE;
	}

	//3.2 根据dwTidList[1024]数组，获取线程句柄
	DWORD i = 0;
	HANDLE hThread=NULL;
	for (i = 0; i < Index; i++)
	{
		hThread=OpenThread(THREAD_ALL_ACCESS, FALSE, dwTidList[i]);
		if ((HANDLE)-1 == hThread)
		{
			printf("OpenThread:%d\n", GetLastError());
			continue;
		}
		printf("Index[%d]:%X\n", i,hThread);

		//3.3暂停线程
		DWORD dwSuspendRet = 0;
		dwSuspendRet = SuspendThread(hThread);
		if ((DWORD)-1 == dwSuspendRet)
		{
			printf("SuspendThread:%d\n", GetLastError());
			CloseHandle(hThread);
			continue;
		}
		//3.4 获取CONTEXT
		ZeroMemory(&ctx, sizeof(CONTEXT));
		ctx.ContextFlags = CONTEXT_FULL;
		if (!GetThreadContext(hThread, &ctx))
		{
			printf("GetThreadContext:%d\n", GetLastError());
			continue;
		}

		//4.构造shellcode
#ifdef _WIN64
		DWORD Ip = ctx.Rip;
#else
		DWORD Ip = ctx.Eip;
#endif
		CreateShellCode(Ip, (int)Remote_DllPath, &ShellCode, &ShellCodeLength);
		
		//5.写入DllPath和shellcode
		Remote_ShellCodePtr = VirtualAllocEx(hProcess,
			NULL,
			ShellCodeLength,
			MEM_COMMIT,
			PAGE_EXECUTE_READWRITE);
		if (Remote_ShellCodePtr == NULL)
		{
			printf("VirtualAllocEx:%d\n", GetLastError());
			CloseHandle(hThread);
			continue;
		}
		BOOL bRet = FALSE;
		WriteProcessMemory(hProcess,
			Remote_DllPath,
			DllPath,
			lstrlen(DllPath) + 1,
			NULL
		);
		bRet = WriteProcessMemory(hProcess,
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

		//6.将RIP设置为shellcode入口
		ctx.Eip = (DWORD)Remote_ShellCodePtr;
		ctx.ContextFlags = CONTEXT_CONTROL;
		if (!SetThreadContext(hThread, &ctx))
		{
			printf("SetThreadContext:%d\n", GetLastError());
			CloseHandle(hThread);
			continue;
		}


		//重启线程
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
	VirtualFreeEx(hProcess, Remote_DllPath, strlen(DllPath) + 1, MEM_DECOMMIT);
	VirtualFreeEx(hProcess, Remote_ShellCodePtr, ShellCodeLength, MEM_DECOMMIT);
	CloseHandle(hProcess);
	getchar();
	return TRUE;
}

DWORD GetProcessIdByName(char *ProcessName)
{
	HANDLE hSnapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
	if (INVALID_HANDLE_VALUE == hSnapshot) {
		return NULL;
	}
	PROCESSENTRY32 pe = { sizeof(pe) };
	if (Process32First(hSnapshot, &pe))
	{
		do
		{
			if (!lstrcmp(pe.szExeFile, ProcessName))
			{
				CloseHandle(hSnapshot);
				printf("ProcessId:%d\n", pe.th32ProcessID);
				return pe.th32ProcessID;
			}
		} while (Process32Next(hSnapshot, &pe));
	}
	CloseHandle(hSnapshot);
	return 0;
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

