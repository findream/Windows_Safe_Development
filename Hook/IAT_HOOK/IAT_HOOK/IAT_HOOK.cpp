/*------------------------------------------------------------------------
ע��㣺
1.����IAT_HOOK��ʱ��ֻ��HOOK�����̵ģ����Կ���ѡ����DLLע������
2.��������
PULONG_PTR   --->unsigned _int64*
ULONG_PTR    --->unsigned _int64*
LPCTSTR      --->STR���͵�constָ��(unicode)
LPCVOID      --->void���͵�constָ��(unicode)
PBYTE        --->byte*
PVOID        --->void*
https://www.cnblogs.com/goed/archive/2011/11/11/2245702.html
-------------------------------------------------------------------------*/




#include "IatHook.h"
#include <imagehlp.h>   //ImageDirectoryEntryToData����
#pragma comment(lib,"imagehlp.lib")


//����ԭ���ĺ�����ַ��IAT��ַ
//�������ã���һ:��Detour�����������Target������Ҫ�õ�
//�ڶ�����ж��HOOK��ʱ�򣬻ָ�ԭ����ʱ����Ҫ�õ�
PFN_MessageBoxA OldMessageBox=NULL;
PULONG_PTR g_PointerToIATThunk = NULL;


int main(int agrc, char* agrv[])
{
	//BOOL bIsWow64 = IsWow64();
	MessageBox(NULL, "Before", "warning", MB_OK);
	if (!IAT_InstallHook())
	{
		printf("InstallHook Failed\n");
		getchar();
		return FALSE;
	}
	MessageBox(NULL, "After", "warning", MB_OK);
	IAT_UnInstallHook();
	MessageBox(NULL, "Before", "warning", MB_OK);
	getchar();
	return 0;
}

BOOL IsWow64()
{
	BOOL bIsWow64 = FALSE;
	LPFUN_ISWOW64PROCESS fnIsWow64Process=NULL;
	fnIsWow64Process = (LPFUN_ISWOW64PROCESS)GetProcAddress(GetModuleHandle("Kernel32.dll"),
		"IsWow64Process");

	if (NULL != fnIsWow64Process)
	{
		if (!fnIsWow64Process(GetCurrentProcess(), &bIsWow64))
		{
			printf("fnIsWow64Process:%d\n", GetLastError());
		}
	}
	return bIsWow64;
}


BOOL IAT_InstallHook()
{
	//����IAT_HOOK
	BOOL bResult = FALSE;

	HMODULE hCurExe = GetModuleHandle(NULL);   //��ǰģ��ľ��
	PULONG_PTR pt;                             //��Ҫ�����IAT��ַ
	ULONG_PTR OrginalAddr;                     //��Ҫ�����IAT��ֵ


	//��װHOOK
	bResult = InstallModuleIATHook(hCurExe, "user32.dll", "MessageBoxA", (PVOID)My_MessageBoxA, &pt, &OrginalAddr);

	//��װ�ɹ�������Target������ַ��IAT��ַ���Ա����ʹ��
	if (bResult)
	{
		printf("[*]Hook��װ���! pThunk=0x%p  OriginalAddr = 0x%p\n", pt, OrginalAddr);

		//����Target������ַ��IAT��ַ���Ա����ʹ��
		OldMessageBox = (PFN_MessageBoxA)OrginalAddr;
		g_PointerToIATThunk = pt;
	}
	return bResult;
}


//ж��HOOK
VOID IAT_UnInstallHook()
{
	DWORD dwOldProtect;
	if (g_PointerToIATThunk)
	{
		VirtualProtect(g_PointerToIATThunk, sizeof(PULONG_PTR), PAGE_EXECUTE_READWRITE, &dwOldProtect);
		*g_PointerToIATThunk = (ULONG64)OldMessageBox;
		printf("[*]Uninstall--->*g_PointerToIATThunk��%p,OldMessageBox��%p", *g_PointerToIATThunk, OldMessageBox);
		VirtualProtect(g_PointerToIATThunk, sizeof(PULONG_PTR), dwOldProtect, 0);
	}
}


//��װHOOK
BOOL InstallModuleIATHook(
	HMODULE hModToHook,   //��HOOK ��ģ����
	char* szModuleName,   //��HOOK��ģ����
	char* szFuncName,     //Ŀ�꺯������
	PVOID DetourFunc,     //Detour������ַ
	PULONG_PTR *pThunkPointer,  //���Խ���ָ���޸ĵ�λ�õ�ָ��
	ULONG_PTR *pOriginalFuncAddr   //���Խ���ԭʼ������ַ
	//ULONG_PRT��ULONG�Ĺ�ϵ��ULONG_PRT��Ϊ��X64����X32������Щ_PTR����ֻ����32λӦ�ó�����Ϊ32λ������64λӦ�ó�����Ϊ64λ�������͡�����ô�򵥡�
)
{
	BOOL Status = FALSE;
	//1.��ȡĿ�꺯����ַ
	HMODULE hModule = LoadLibrary(szModuleName);
	ULONG_PTR TargetFunAddr = (ULONG_PTR)GetProcAddress(hModule, szFuncName);
	printf("[*]Address of %s:0x%p\n", szFuncName, TargetFunAddr);
	printf("[*]Module To Hook at Base:0x%p\n", hModToHook);
	
	
	//2.��ȡ�����
	ULONG ulSize=0;
	PIMAGE_IMPORT_DESCRIPTOR pImportDescriptor = (PIMAGE_IMPORT_DESCRIPTOR)ImageDirectoryEntryToData(hModToHook,
		TRUE,
		IMAGE_DIRECTORY_ENTRY_IMPORT,
		&ulSize);
	printf("[*]Find ImportTable,Address:0x%p\n", pImportDescriptor);
	
	//3.Ѱ��Ŀ�꺯����ADDRESS
	char *szModName=NULL;
	while (pImportDescriptor->FirstThunk)
	{
		//���DllName
		szModName = (char*)((PBYTE)hModToHook + pImportDescriptor->Name);
		printf("[*]Cur Module Name:%s\n", szModName);

		//�Ƚ�DLLName��Ŀ��DLL�Ƿ���ͬ  ʹ��stricmp�����ǲ����ִ�Сд��
		if (stricmp(szModName, szModuleName) != 0)
		{
			pImportDescriptor++;
			continue;
		}

		//����ʼ��IAT��˫����ɵ�����ֻ��ʹ��FirstThunk���в���.���ݺ�����ֱַ���жϣ�������Ҳ����Ҫ��ǰ֪��Ŀ�꺯����ַ��ԭ��
		PIMAGE_THUNK_DATA pThunkData = (PIMAGE_THUNK_DATA)((BYTE*)hModToHook + pImportDescriptor->FirstThunk);
		PULONG_PTR lpAddr = NULL;
		//ULONG_PTR lpAddr = NULL;
		while (pThunkData->u1.Function)
		{
			/*------------------------------------
			typedef struct _IMAGE_THUNK_DATA32
			{
				union {
					DWORD ForwarderString;          // һ��RVA��ַ��ָ��forwarder string
					DWORD Function;                 // PDWORD��������ĺ�������ڵ�ַ
					DWORD Ordinal;                  // �ú���������
					DWORD AddressOfData;            // һ��RVA��ַ��ָ��IMAGE_IMPORT_BY_NAME
				}u1;
			} IMAGE_THUNK_DATA32;
			----------------------------------*/
			lpAddr = (ULONG_PTR*)pThunkData;     //��ʱIAT�Ѿ������ɺ�����ַ,����ʹ��*pThunkData��ΪĿ�꺯����ַ
			//lpAddr = (PULONG_PTR)pThunkData;
			if ((*lpAddr) == TargetFunAddr)
			{
				printf("[*]Find target address!\n");
				DWORD dwOldProtect = NULL;
				if (VirtualProtect(lpAddr, sizeof(PULONG_PTR), PAGE_EXECUTE_READWRITE, &dwOldProtect))
				{
					if (pThunkPointer != NULL)   //�����޸��ڴ�ĵ�ַ
					{
						*pThunkPointer = lpAddr;
					}
					if (pOriginalFuncAddr != NULL)   //�����޸��ڴ�����ݣ�Ҳ����Target�����ĵ�ַ
					{
						*pOriginalFuncAddr = *lpAddr;
					}

					//�޸�IAT����
					*lpAddr = (ULONG_PTR)DetourFunc;
					Status = TRUE;
					//VirtualProtect(lpAddr, sizeof(ULONG_PTR), dwOldProtect, 0);
					VirtualProtect(lpAddr, sizeof(PULONG_PTR), dwOldProtect, 0);
					printf("[*]Hook ok-->NewMessageBox:%x\n", *lpAddr);
				}
				break;
			}
			pThunkData++;   //��һ��FirstThunk(����)
		}
		if (Status)
			break;
		pImportDescriptor++;   //��һ��IID(DLL)
	}

	FreeLibrary(hModule);
	return TRUE;
}

//DetourFun
int WINAPI My_MessageBoxA(
	HWND hWnd,
	LPCTSTR lpText,
	LPCTSTR lpCaption,
	UINT uType
)
{
	//1.�����ִ����ָ���Ĳ���
	BOOL bReturn = FALSE;
	bReturn = OldMessageBox(NULL, "You Are Hooked", "Warning", MB_OK);

	//2.����Կ���API�����ķ���ֵ
	return bReturn;
}

