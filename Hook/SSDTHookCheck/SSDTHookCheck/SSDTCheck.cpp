#include <stdio.h>
#include "ntapi.h"
#include "PELoader.h"

#pragma pack(1)    //SSDT��Ľṹ
typedef struct _ServiceDescriptorEntry {
	DWORD *ServiceTableBase;
	DWORD *ServiceCounterTableBase; //Used only in checked build
	DWORD NumberOfServices;
	BYTE *ParamTableBase;
} ServiceDescriptorTableEntry, *PServiceDescriptorTableEntry;
#pragma pack()

typedef struct _SSDTINFO
{
	DWORD ServiceIndex;//��������
	DWORD CurrentAddr;//��ǰSSDT���еĵ�ַ
	DWORD OriginalAddr;//ԭʼ��ַ
	BOOL bHooked;//�Ƿ�Hook��
	char FuncName[124];//��������
}SSDTINFO, *PSSDTINFO;


//ZwAccessCheckByTypeResultListAndAuditAlarmByHandle

void PrintZwError(char *funcname, NTSTATUS status);
VOID CheckSSDT();
NTSTATUS ReadKernelMemory(LPVOID BaseAddress, LPVOID lpBuffer, DWORD nSize, LPDWORD lpNumberOfBytesRead);
void PrintZwError(char *funcname, NTSTATUS status);
BOOL GetOSKrnlInfo(
	OUT char *szKrnlPath,
	OUT DWORD *pKernelBase
);

BOOL EnableDebugPrivilege();
BOOL BuildServiceNameTable(PELoader *pModule);
VOID ShowSSDT();

//�洢SSDT��Ϣ
SSDTINFO g_SSDTInfo[1000];
//�ܷ�����
DWORD g_dwServiceCnt = 0;
//��Hook�ķ�����
DWORD g_dwHookedCnt = 0;


int main(int argc, char* argv[])
{
	CheckSSDT();
}

//����Ȩ��





void CheckSSDT()
{
	//Step1�������µ�ntdll.dll
	char szNtdllPath[MAX_PATH] = { 0 };
	PELoader *ldNtdll = new PELoader;
	PBYTE pNewLoaderNtdll = NULL;
	GetSystemDirectory(szNtdllPath, MAX_PATH);
	lstrcat(szNtdllPath, "\\ntdll.dll");
	pNewLoaderNtdll = ldNtdll->LoadPE(szNtdllPath, FALSE, 0);
	
	//Step2:��ȡ������������Ϊ����������ַ����ϵͳ��������
	BuildServiceNameTable(ldNtdll);

	//Step3����ȡ��ǰNtdll��·���ͻ���ַ
	char szOskrnlPath[MAX_PATH] = { 0 };
	DWORD TrueKernelBase = 0;
	BOOL bResult = FALSE;
	bResult=GetOSKrnlInfo(szOskrnlPath, &TrueKernelBase);

	//Step4.���ص�ǰ�ں��ļ�ntoskrnl.exe
	PELoader *ldOsKrnl = new PELoader;
	PBYTE pRemapedOsKrnl = ldOsKrnl->LoadPE(szOskrnlPath, TRUE, TrueKernelBase);

	//Step5.��ȡSSDT�ĵ�ַ
	ServiceDescriptorTableEntry *pRemapedSDT, *pOriginalSDT, OriginalSDT;
	pRemapedSDT = (ServiceDescriptorTableEntry*)ldOsKrnl->_GetProcAddress(pRemapedOsKrnl, "KeServiceDescriptorTable");
	//��ȡ�����ؼ��غ��KeServiceDescriptorTable�ṹ�ǿյģ���Ҫ����ƫ�Ƽ�����ʵ��SSDT���ڴ��е�λ��
	pOriginalSDT = (ServiceDescriptorTableEntry*)((DWORD)pRemapedSDT - (DWORD)pRemapedOsKrnl + TrueKernelBase);






}

BOOL BuildServiceNameTable(PELoader *pModule)
{
	DWORD i = 0;
	DWORD nFunCnt = 0;
	char *szFunName = NULL;
	DWORD *namerav, *funrav;
	PBYTE ModuleBase = pModule->m_hModule;
	DWORD dwServiceIndex = 0;
	PBYTE pFunAddr = NULL;
	PIMAGE_EXPORT_DIRECTORY pExportDir = pModule->m_pExportDir;
	namerav = (DWORD*)(ModuleBase + pExportDir->AddressOfNames);
	funrav = (DWORD*)(ModuleBase + pExportDir->AddressOfFunctions);

	//����������
	for (i = 0; i < pExportDir->NumberOfNames; i++)
	{
		szFunName = (char*)pModule + namerav[i];
		if (memcmp(szFunName, "Zw", 2) == 0)
		{
			pFunAddr = ModuleBase + funrav[i];
			//��ȡSSDT����
			dwServiceIndex = *(DWORD*)(pFunAddr + 1);

			//����������Ϣ�����ｫ��������������Ϊ�±��������
			//�����ڱ�����ʱ�򷽱�һ�㡣
			g_SSDTInfo[dwServiceIndex].ServiceIndex = dwServiceIndex;
			lstrcpy(g_SSDTInfo[dwServiceIndex].FuncName, szFunName);
			memcpy(g_SSDTInfo[dwServiceIndex].FuncName, "Nt", 2);//��һ�º�������
			g_dwServiceCnt++;
			
		}


	}
}

BOOL GetOSKrnlInfo(
	OUT char *szKrnlPath,
	OUT DWORD *pKernelBase)
{
	BOOL bResult = FALSE;
	PSYSTEM_MODULE_INFORMATION_ENTRY pSysModuleInfo;
	NTSTATUS status = 0;
	char *pBuf = NULL;
	DWORD needlen = 0, truelen;
	DWORD Modcnt = 0;

	ZwQuerySystemInformation(SystemModuleInformation, NULL, 0, &needlen);
	//printf("Need length:0x%x\n",needlen);
	truelen = needlen;
	status = ZwAllocateVirtualMemory(NtCurrentProcess(), (PVOID*)&pBuf, 0, &truelen, MEM_COMMIT, PAGE_READWRITE);
	if (!NT_SUCCESS(status))
	{
		PrintZwError("ZwAllocateVirtualMemory", status);
		return FALSE;
	}
	//printf("Buf:0x%08x\n",pBuf);
	status = ZwQuerySystemInformation(SystemModuleInformation, (PVOID)pBuf, truelen, &needlen);
	if (!NT_SUCCESS(status))
	{
		PrintZwError("ZwQuerySystemInformation", status);
		return FALSE;
	}
	Modcnt = *(DWORD*)pBuf;
	pSysModuleInfo = (PSYSTEM_MODULE_INFORMATION_ENTRY)(pBuf + sizeof(DWORD));
	if (strstr(
		(strlwr(pSysModuleInfo->ImageName), pSysModuleInfo->ImageName), "nt"))
	{
		*pKernelBase = (DWORD)pSysModuleInfo->Base;
		GetSystemDirectory(szKrnlPath, MAX_PATH);
		lstrcat(szKrnlPath, strrchr(pSysModuleInfo->ImageName, '\\'));
	}
	status = ZwFreeVirtualMemory(NtCurrentProcess(), (PVOID*)&pBuf, &truelen, MEM_RELEASE);

	return TRUE;
}
