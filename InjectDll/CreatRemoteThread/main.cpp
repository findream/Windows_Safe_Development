# include <stdio.h>
# include <windows.h>
#include <tlhelp32.h>


BOOL WINAPI InjectDllToProcess(DWORD dwTargetPid, LPCTSTR DllPath);
DWORD ProcesstoPid(char *Processname);
BOOL EnableDebugPrivilege();


int main(void)
{
	char szProcName[MAX_PATH] = "notepad.exe";
	char szDllPath[] = "Project1.dll";
	DWORD dwPid = ProcesstoPid(szProcName);    //Ѱ��notepad.exe��PID
	EnableDebugPrivilege();                    //��Ȩ
	InjectDllToProcess(dwPid, szDllPath);
	system("pause");
	return 0;
}

DWORD ProcesstoPid(char *Processname) //����ָ�����̵�PID(Process ID)
{
	HANDLE hProcessSnap = NULL;
	DWORD dwProcessId = 0;
	PROCESSENTRY32 pe32 = { 0 };
	hProcessSnap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
	if (hProcessSnap == INVALID_HANDLE_VALUE)
	{
		printf("CreateToolhelp32Snapshot:%d\n", GetLastError());
		return NULL;
	}
	pe32.dwSize = sizeof(PROCESSENTRY32);   //��ʼ��PROCESSENTRY32�ṹ��
	if (Process32First(hProcessSnap, &pe32))
	{
		do
		{
			if (!lstrcmp(pe32.szExeFile, Processname))
			{
				dwProcessId = pe32.th32ProcessID;
				break;
			}
		} while (Process32Next(hProcessSnap, &pe32));
	}
	else
	{
		printf("Process32First:%d\n", GetLastError());
		return NULL;
	}
	CloseHandle(hProcessSnap);
	return dwProcessId;
}

BOOL EnableDebugPrivilege() //��������������Ȩ�ޣ�������SE_DEBUG_NAME
{
	TOKEN_PRIVILEGES tkp ;
	HANDLE hToken = NULL;
	if (!OpenProcessToken(GetCurrentProcess(), TOKEN_ADJUST_PRIVILEGES | TOKEN_QUERY, &hToken))
	{
		printf("OpenProcessToken:%d\n",GetLastError());
		return 0;
	}
	LookupPrivilegeValue(NULL, SE_DEBUG_NAME, &tkp.Privileges[0].Luid); //�鿴��ǰȨ��
	tkp.PrivilegeCount = 1;
	tkp.Privileges[0].Attributes = SE_PRIVILEGE_ENABLED;
	AdjustTokenPrivileges(hToken, FALSE, &tkp, 0, (PTOKEN_PRIVILEGES)NULL, 0); //����Ȩ�ޣ���������
	return TRUE;
}

BOOL WINAPI InjectDllToProcess(DWORD dwTargetPid, LPCTSTR DllPath)
{
	HANDLE hProc = NULL;  //���̾��

	//��Ŀ�����
	hProc = OpenProcess(PROCESS_ALL_ACCESS,
		FALSE,
		dwTargetPid
	);
	if (hProc == NULL)
	{
		printf("OpenProcess:%d\n", GetLastError());
		return 0;
	}

	//��Ŀ�������д����
	LPTSTR psLibFileRemote = NULL;
	psLibFileRemote = (LPTSTR)VirtualAllocEx(hProc, 
		NULL, 
		lstrlen(DllPath) + 1, 
		MEM_COMMIT,
		PAGE_READWRITE);
	if (psLibFileRemote == NULL)
	{
		printf("VirtualAllocEx:%d\n", GetLastError());
		return FALSE;
	}
	BOOL bRet=WriteProcessMemory(hProc,
		psLibFileRemote,
		(LPCVOID)DllPath,
		//(void *)DllPath
		lstrlen(DllPath) + 1,
		NULL);
	if (bRet == NULL)
	{
		printf("WriteProcessMemory:%d\n", GetLastError());
		return NULL;
	}

	//��ȡLoadLibrary��ַ
	PTHREAD_START_ROUTINE pfnStartAddr = (PTHREAD_START_ROUTINE)GetProcAddress(GetModuleHandle("Kernel32.dll"),
		"LoadLibraryA");
	if (pfnStartAddr == NULL)
	{
		printf("GetProcAddress %d\n",GetLastError());
		return FALSE;
	}

	//CreateThreadThread
	HANDLE hThread = CreateRemoteThread(hProc,
		NULL,
		0,
		pfnStartAddr,
		psLibFileRemote,
		0,
		NULL);
	if (hThread == NULL)
	{
		printf("CreateRemoteThread:%d", GetLastError());
		return FALSE;
	}
	return TRUE;

}

