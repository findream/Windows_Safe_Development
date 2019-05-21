#include <stdio.h>
#include "ntapi.h"
#include "PELoader.h"

#pragma pack(1)    //SSDT表的结构
typedef struct _ServiceDescriptorEntry {
	DWORD *ServiceTableBase;
	DWORD *ServiceCounterTableBase; //Used only in checked build
	DWORD NumberOfServices;
	BYTE *ParamTableBase;
} ServiceDescriptorTableEntry, *PServiceDescriptorTableEntry;
#pragma pack()

typedef struct _SSDTINFO
{
	DWORD ServiceIndex;//服务索引
	DWORD CurrentAddr;//当前SSDT表中的地址
	DWORD OriginalAddr;//原始地址
	BOOL bHooked;//是否被Hook了
	char FuncName[124];//函数名称
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

//存储SSDT信息
SSDTINFO g_SSDTInfo[1000];
//总服务数
DWORD g_dwServiceCnt = 0;
//被Hook的服务数
DWORD g_dwHookedCnt = 0;


int main(int argc, char* argv[])
{
	CheckSSDT();
}

//提升权限





void CheckSSDT()
{
	//Step1：加载新的ntdll.dll
	char szNtdllPath[MAX_PATH] = { 0 };
	PELoader *ldNtdll = new PELoader;
	PBYTE pNewLoaderNtdll = NULL;
	GetSystemDirectory(szNtdllPath, MAX_PATH);
	lstrcat(szNtdllPath, "\\ntdll.dll");
	pNewLoaderNtdll = ldNtdll->LoadPE(szNtdllPath, FALSE, 0);
	
	//Step2:获取导出函数表，因为导出函数地址决定系统服务索引
	BuildServiceNameTable(ldNtdll);

	//Step3：获取当前Ntdll的路径和基地址
	char szOskrnlPath[MAX_PATH] = { 0 };
	DWORD TrueKernelBase = 0;
	BOOL bResult = FALSE;
	bResult=GetOSKrnlInfo(szOskrnlPath, &TrueKernelBase);

	//Step4.加载当前内核文件ntoskrnl.exe
	PELoader *ldOsKrnl = new PELoader;
	PBYTE pRemapedOsKrnl = ldOsKrnl->LoadPE(szOskrnlPath, TRUE, TrueKernelBase);

	//Step5.获取SSDT的地址
	ServiceDescriptorTableEntry *pRemapedSDT, *pOriginalSDT, OriginalSDT;
	pRemapedSDT = (ServiceDescriptorTableEntry*)ldOsKrnl->_GetProcAddress(pRemapedOsKrnl, "KeServiceDescriptorTable");
	//获取到的重加载后的KeServiceDescriptorTable结构是空的，需要根据偏移计算真实的SSDT在内存中的位置
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

	//遍历导出表
	for (i = 0; i < pExportDir->NumberOfNames; i++)
	{
		szFunName = (char*)pModule + namerav[i];
		if (memcmp(szFunName, "Zw", 2) == 0)
		{
			pFunAddr = ModuleBase + funrav[i];
			//获取SSDT索引
			dwServiceIndex = *(DWORD*)(pFunAddr + 1);

			//保存索引信息，这里将索引保存在索引为下标的数组中
			//这样在遍历的时候方便一点。
			g_SSDTInfo[dwServiceIndex].ServiceIndex = dwServiceIndex;
			lstrcpy(g_SSDTInfo[dwServiceIndex].FuncName, szFunName);
			memcpy(g_SSDTInfo[dwServiceIndex].FuncName, "Nt", 2);//改一下函数名字
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
