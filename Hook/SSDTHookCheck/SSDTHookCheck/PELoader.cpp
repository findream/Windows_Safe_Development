/*-----------------------------------------------------------------------
��13��  Hook����
����������ܣ����İ棩��
(c)  ��ѩѧԺ www.kanxue.com 2000-2018
-----------------------------------------------------------------------*/


// PELoader.cpp: implementation of the PELoader class.
//
//////////////////////////////////////////////////////////////////////

#include "PELoader.h"
#include <shlwapi.h>
#include <stdio.h>

#pragma comment(lib,"shlwapi.lib")
#pragma comment(linker,"Base:0x40000000")
//////////////////////////////////////////////////////////////////////
// Construction/Destruction
//////////////////////////////////////////////////////////////////////

PELoader::PELoader()
{
	m_hFile = INVALID_HANDLE_VALUE;
	m_hMap = INVALID_HANDLE_VALUE;
	m_MappedBase = m_hModule = NULL;
	m_pDosHeader = NULL;
	m_pFileHeader = NULL;
	m_pRelocTable = NULL;
	m_pSecHeader = NULL;
	m_pExportDir = NULL;
	m_pImportDesp = NULL;
	m_pOptHeader = NULL;
}

PELoader::~PELoader()
{
	Cleanup();
}

//************************************
// Method:    LoadPE
// FullName:  PELoader::LoadPE
// Access:    public 
// Returns:   PBYTE
// Qualifier:
// Parameter: char * szPEPath , �����ص�PEģ���ȫ·��
// Parameter: BOOL bDoReloc , �Ƿ����ض�λ
// Parameter: DWORD RelocBase , �ض�λ�Ļ�ַ�����Ϊ0����ʵ�ʼ���λ���ض�λ
// Parameter: BOOL bDoImport , �Ƿ������
//************************************
PBYTE PELoader::LoadPE(char *szPEPath, BOOL bDoReloc, DWORD RelocBase, BOOL bDoImport)
{
	WORD i = 0;
	BYTE *pMemory = NULL;
	BYTE *MappedBase = NULL;
	PIMAGE_SECTION_HEADER pTmpSecHeader = NULL;

	//����PE·��
	lstrcpy(m_szPEPath, szPEPath);

	//�򿪲�ӳ��
	MappedBase = OpenFileAndMap(szPEPath);
	if (MappedBase == NULL)
	{
		return NULL;
	}

	//��������PEͷ���ṹ
	InitializePEHeaders(MappedBase);
	pTmpSecHeader = m_pSecHeader;
	//��ʼ�����ڴ�
	m_TotalImageSize = GetTotalImageSize(m_pOptHeader->SectionAlignment);
	pMemory = m_hModule = (BYTE*)VirtualAlloc(NULL, m_TotalImageSize, MEM_COMMIT, PAGE_EXECUTE_READWRITE);
	if (m_hModule == NULL)
	{
		return NULL;
	}
	//printf("m_hModule = 0x%X\n",m_hModule);
	//�ȿ���PEͷ��������ڴ�
	memcpy(pMemory, MappedBase, m_pOptHeader->SizeOfHeaders);
	pMemory += GetAlignedSize(m_pOptHeader->SizeOfHeaders, m_pOptHeader->SectionAlignment);

	//printf("Section  VirtualAddress VirtualSize   PointertoRawData  RawSize\n");
	//printf("=================================================================\n");
	char szTmpName[9] = { 0 };
	for (i = 0; i < m_SectionCnt; i++)
	{
		strncpy(szTmpName, (char*)pTmpSecHeader->Name, 8);
		//printf("%8s %08X\t%08X\t%08X\t%08X\n",
		//szTmpName,pTmpSecHeader->VirtualAddress,pTmpSecHeader->Misc.VirtualSize,pTmpSecHeader->PointerToRawData,pTmpSecHeader->SizeOfRawData);
		//����������
		//printf("[COPY] %8s\t:0x%08X Kernel=0x%08X Size=0x%08X\n",szTmpName,pMemory,KernelBase,GetAlignedSize(pTmpSecHeader->Misc.VirtualSize,pOptHeader->SectionAlignment));
		memcpy(pMemory, MappedBase + pTmpSecHeader->PointerToRawData, pTmpSecHeader->SizeOfRawData);
		pMemory += GetAlignedSize(pTmpSecHeader->Misc.VirtualSize, m_pOptHeader->SectionAlignment);
		pTmpSecHeader++;
	}

	//���½���PEͷ
	InitializePEHeaders(m_hModule);

	//��ʼ�����ض�λ����
	if (bDoReloc)
	{
		//���RelocBaseΪ0����ʵ�ʼ���λ�ý����ض�λ
		DWORD BaseToReloc = (RelocBase == 0) ? (DWORD)m_hModule : RelocBase;
		ProcessRelocTable(BaseToReloc);
	}

	//�������
	if (bDoImport)
	{
		ProcessImportTable();
	}

	//���м�����ϣ����Թر�ӳ����
	UnmapViewOfFile(MappedBase);
	CloseHandle(m_hMap);
	m_hMap = INVALID_HANDLE_VALUE;
	return m_hModule;
}

VOID PELoader::FreePE(PBYTE pModule)
{
	VirtualFree(pModule, 0, MEM_RELEASE);
	pModule = NULL;
}

DWORD PELoader::GetAlignedSize(DWORD theSize, DWORD Alignment)
{
	DWORD dwAlignedVirtualSize = 0;
	DWORD moded = 0, dived = 0;
	dived = theSize / Alignment;
	moded = theSize % Alignment;
	if (moded)//������
	{
		dwAlignedVirtualSize = dived * Alignment;
		dwAlignedVirtualSize += Alignment;
	}
	else
	{
		dwAlignedVirtualSize = theSize;
	}
	//printf("Recevid Size=%08X\tdived=%X\tmoded=%X\n",theSize,dived,moded);
	return dwAlignedVirtualSize;//���ض����Ĵ�С
}

DWORD PELoader::_GetProcAddress(PBYTE pModule, char *szFuncName)
{
	//�Լ�ʵ��GetProcAddress
	DWORD retAddr = 0;
	DWORD *namerav, *funrav;
	DWORD cnt = 0;
	DWORD max, min, mid;
	WORD *nameOrdinal;
	WORD nIndex = 0;
	int cmpresult = 0;
	char *ModuleBase = (char*)pModule;
	char *szMidName = NULL;
	PIMAGE_DOS_HEADER pDosHeader;
	PIMAGE_FILE_HEADER pFileHeader;
	PIMAGE_OPTIONAL_HEADER pOptHeader;
	PIMAGE_EXPORT_DIRECTORY pExportDir;

	if (ModuleBase == NULL)
	{
		return 0;
	}

	pDosHeader = (PIMAGE_DOS_HEADER)ModuleBase;
	pFileHeader = (PIMAGE_FILE_HEADER)(ModuleBase + pDosHeader->e_lfanew + 4);
	pOptHeader = (PIMAGE_OPTIONAL_HEADER)((char*)pFileHeader + sizeof(IMAGE_FILE_HEADER));
	pExportDir = (PIMAGE_EXPORT_DIRECTORY)(ModuleBase + pOptHeader->DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress);
	namerav = (DWORD*)(ModuleBase + pExportDir->AddressOfNames);
	funrav = (DWORD*)(ModuleBase + pExportDir->AddressOfFunctions);
	nameOrdinal = (WORD*)(ModuleBase + pExportDir->AddressOfNameOrdinals);

	if ((DWORD)szFuncName < 0x0000FFFF)
	{
		retAddr = (DWORD)(ModuleBase + funrav[(WORD)szFuncName]);
	}
	else
	{
		//���ַ�����
		max = pExportDir->NumberOfNames;
		min = 0;
		mid = (max + min) / 2;
		while (min < max)
		{
			//printf("min = %d max = %d mid = %d ",min,max,mid);
			szMidName = ModuleBase + namerav[mid];
			cmpresult = strcmp(szFuncName, szMidName);
			//printf("Now[%d] : %s \n",mid,szMidName);
			if (cmpresult < 0)
			{
				//����ֵС,��ȡ��ֵ-1Ϊ���ֵ
				max = mid - 1;
			}
			else if (cmpresult > 0)
			{
				//����ֵ��,��ȡ��ֵ+1Ϊ��Сֵ
				min = mid + 1;
			}
			else
			{
				break;
			}
			mid = (max + min) / 2;

		}

		if (strcmp(szFuncName, ModuleBase + namerav[mid]) == 0)
		{
			nIndex = nameOrdinal[mid];
			retAddr = (DWORD)(ModuleBase + funrav[nIndex]);
		}
	}
	return retAddr;
}

PBYTE PELoader::OpenFileAndMap(char *szPEFilePath)
{
	//printf("���ڴ��ļ���ӳ��...\n");
	m_hFile = CreateFile(szPEFilePath, GENERIC_READ, FILE_SHARE_READ, NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);

	if (INVALID_HANDLE_VALUE == m_hFile)
	{
		FormatErrorMsg(m_szErrorMsg, "���ļ�ʧ��!", GetLastError());
		goto __Failed;
	}
	m_hMap = CreateFileMapping(m_hFile, NULL, PAGE_READONLY, 0, 0, NULL);
	if (m_hMap == NULL)
	{
		FormatErrorMsg(m_szErrorMsg, "�����ļ�ӳ��ʧ��!", GetLastError());
		goto __Failed;
	}
	m_MappedBase = (BYTE*)MapViewOfFile(m_hMap, FILE_MAP_READ, 0, 0, 0);
	if (m_MappedBase == NULL)
	{
		FormatErrorMsg(m_szErrorMsg, "ӳ���ļ�ʧ��!", GetLastError());
		goto __Failed;
	}
	CloseHandle(m_hFile);
	m_hFile = INVALID_HANDLE_VALUE;
	return m_MappedBase;


__Failed:
	Cleanup();
	return NULL;
}

DWORD PELoader::GetTotalImageSize(DWORD Alignment)
{
	DWORD TotalSize = 0;
	DWORD tmp = 0;
	PIMAGE_SECTION_HEADER pTmpSecHeader = m_pSecHeader;
	TotalSize += GetAlignedSize(m_pOptHeader->SizeOfHeaders, Alignment);
	for (WORD i = 0; i < m_SectionCnt; i++)
	{
		tmp = GetAlignedSize(pTmpSecHeader->Misc.VirtualSize, Alignment);
		TotalSize += tmp;
		pTmpSecHeader++;
	}
	//printf("Total Size=0x%08X\n",TotalSize);
	return TotalSize;
}

DWORD PELoader::Rav2Raw(DWORD VirtualAddr)
{
	DWORD RawAddr = 0;
	if (VirtualAddr < m_pOptHeader->SizeOfHeaders)
	{
		RawAddr = VirtualAddr;
		//printf("Rav2Raw 0x%08X\n",RawAddr);
		return RawAddr;
	}
	PIMAGE_SECTION_HEADER pTmpSecHeader = m_pSecHeader;
	for (WORD i = 0; i < m_SectionCnt; i++)
	{
		//�ж��Ƿ���ĳ��������
		if (VirtualAddr >= (pTmpSecHeader->VirtualAddress)
			&& (VirtualAddr < (pTmpSecHeader->VirtualAddress + pTmpSecHeader->Misc.VirtualSize)))
		{
			RawAddr = pTmpSecHeader->PointerToRawData + VirtualAddr - pTmpSecHeader->VirtualAddress;
			return RawAddr;
		}
		pTmpSecHeader++;
	}
	return 0;
}

VOID PELoader::FormatErrorMsg(char *szBuf, char *szPrompt, DWORD ErrCode)
{
	LPVOID lpMsgBuf;
	FormatMessage(
		FORMAT_MESSAGE_ALLOCATE_BUFFER |
		FORMAT_MESSAGE_FROM_SYSTEM |
		FORMAT_MESSAGE_IGNORE_INSERTS,
		NULL,
		ErrCode,
		MAKELANGID(LANG_NEUTRAL, SUBLANG_DEFAULT), // Default language
		(LPTSTR)&lpMsgBuf,
		0,
		NULL
	);
	sprintf(szBuf, "%s ErrorCode:%d Reason:%s", szPrompt, ErrCode, (LPCTSTR)lpMsgBuf);
	LocalFree(lpMsgBuf);
}

VOID PELoader::Cleanup()
{
	if (m_hFile != INVALID_HANDLE_VALUE)
	{
		CloseHandle(m_hFile);
		m_hFile = INVALID_HANDLE_VALUE;
	}

	if (m_hMap != INVALID_HANDLE_VALUE)
	{
		CloseHandle(m_hMap);
		m_hMap = INVALID_HANDLE_VALUE;
	}

	if (m_hModule != NULL)
	{
		FreePE(m_hModule);
		m_hModule = NULL;
	}
}

VOID PELoader::InitializePEHeaders(PBYTE pBase)
{
	//��������PEͷ���ṹ
	m_pDosHeader = (PIMAGE_DOS_HEADER)pBase;
	m_pFileHeader = (PIMAGE_FILE_HEADER)(pBase + m_pDosHeader->e_lfanew + 4);
	m_SectionCnt = m_pFileHeader->NumberOfSections;
	m_pOptHeader = (PIMAGE_OPTIONAL_HEADER)((char*)m_pFileHeader + sizeof(IMAGE_FILE_HEADER));
	m_pRelocTable = &(m_pOptHeader->DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC]);
	m_pSecHeader = (PIMAGE_SECTION_HEADER)((char*)m_pOptHeader + sizeof(IMAGE_OPTIONAL_HEADER));
	m_dwEntryPoint = (DWORD)pBase + m_pOptHeader->AddressOfEntryPoint;

	//�����
	if (m_pOptHeader->DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress != NULL)
	{
		m_pExportDir = (PIMAGE_EXPORT_DIRECTORY)(pBase + m_pOptHeader->DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress);
	}

	//������
	if (m_pOptHeader->DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT].VirtualAddress != NULL)
	{
		m_pImportDesp = (PIMAGE_IMPORT_DESCRIPTOR)(pBase + m_pOptHeader->DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT].VirtualAddress);
	}

}

VOID PELoader::ProcessRelocTable(DWORD RelocBase)
{
	WORD i = 0;
	PIMAGE_BASE_RELOCATION pRelocBlock = NULL;
	if (m_pRelocTable->VirtualAddress != NULL)
	{
		pRelocBlock = (PIMAGE_BASE_RELOCATION)(m_hModule + m_pRelocTable->VirtualAddress);
		//printf("After Loaded,Reloc Table=0x%08X\n",pRelocBlock);
		do
		{//����һ����һ�����ض�λ�飬���һ���ض�λ����RAV=0����
			//��Ҫ�ض�λ�ĸ������Ǳ���Ĵ�С��ȥ��ͷ�Ĵ�С���������DWORD��ʾ�Ĵ�С
			//���ض�λ������16λ�ģ��Ǿ͵ó���2
			int numofReloc = (pRelocBlock->SizeOfBlock - sizeof(IMAGE_BASE_RELOCATION)) / 2;
			//printf("Reloc Data num=%d\n",numofReloc);
			//�ض�λ������16λ��
			WORD offset = 0;
			WORD *pRelocData = (WORD*)((char*)pRelocBlock + sizeof(IMAGE_BASE_RELOCATION));
			for (i = 0; i < numofReloc; i++)//ѭ������ֱ���ж�*pData�Ƿ�Ϊ0Ҳ������Ϊ�������
			{
				DWORD *RelocAddress = 0;//��Ҫ�ض�λ�ĵ�ַ
				//�ض�λ�ĸ�4λ���ض�λ���ͣ�
				if (((*pRelocData) >> 12) == IMAGE_REL_BASED_HIGHLOW)//�ж��ض�λ�����Ƿ�ΪIMAGE_REL_BASED_HIGHLOW
				{
					//������Ҫ�����ض�λ�ĵ�ַ
					//�ض�λ���ݵĵ�12λ�ټ��ϱ��ض�λ��ͷ��RAV��������Ҫ�ض�λ�����ݵ�RAV
					offset = (*pRelocData) & 0xFFF;//Сƫ��
					RelocAddress = (DWORD*)(m_hModule + pRelocBlock->VirtualAddress + offset);
					//����Ҫ�ض�λ�����ݽ�������
					//��������:��ȥIMAGE_OPTINAL_HEADER�еĻ�ַ���ټ����µĻ�ַ����
					*RelocAddress = *RelocAddress - m_pOptHeader->ImageBase + RelocBase;
				}
				pRelocData++;

			}
			//ָ����һ���ض�λ��
			pRelocBlock = (PIMAGE_BASE_RELOCATION)((char*)pRelocBlock + pRelocBlock->SizeOfBlock);

		} while (pRelocBlock->VirtualAddress);
	}
}

BOOL PELoader::ProcessImportTable()
{
	BOOL bResult = FALSE;
	char szPreDirectory[MAX_PATH] = { 0 };
	char szCurDirectory[MAX_PATH] = { 0 };
	PIMAGE_IMPORT_DESCRIPTOR  pImportDescriptor = m_pImportDesp;
	PIMAGE_THUNK_DATA         NameThunk = NULL, AddrThunk = NULL;
	PIMAGE_IMPORT_BY_NAME	  pImpName = NULL;
	HMODULE hMod = NULL;
	char *szImpModName = NULL;

	if (pImportDescriptor == NULL)
	{
		//�޵��������Ҫ����
		return TRUE;
	}

	//���ĵ�ǰ·�����������ĳЩ������dllʱ���Ҳ���ģ��
	GetCurrentDirectory(MAX_PATH, szPreDirectory);
	lstrcpy(szCurDirectory, m_szPEPath);
	PathRemoveFileSpec(szCurDirectory);
	SetCurrentDirectory(szCurDirectory);

	//
	// Walk through the IAT and snap all the thunks.
	//

	while (pImportDescriptor->OriginalFirstThunk)
	{
		szImpModName = (char*)m_hModule + pImportDescriptor->Name;
		hMod = LoadLibrary(szImpModName);
		if (hMod == NULL)
		{
			return FALSE;
		}

		//printf("�������ģ�� : %s\n",szImpModName);
		NameThunk = (PIMAGE_THUNK_DATA)(m_hModule + (ULONG)pImportDescriptor->OriginalFirstThunk);
		AddrThunk = (PIMAGE_THUNK_DATA)(m_hModule + (ULONG)pImportDescriptor->FirstThunk);

		while (NameThunk->u1.AddressOfData)
		{
			bResult = SnapThunk(hMod, m_hModule, NameThunk, AddrThunk);
			NameThunk++;
			AddrThunk++;
		}

		pImportDescriptor++;
	}

	SetCurrentDirectory(szPreDirectory);
	return TRUE;
}

BOOL PELoader::SnapThunk(HMODULE hImpMode, PBYTE ImageBase, PIMAGE_THUNK_DATA NameThunk, PIMAGE_THUNK_DATA AddrThunk)
{
	BOOL bResult = FALSE;
	PIMAGE_IMPORT_BY_NAME	  pImpName = NULL;
	DWORD dwFunAddr = 0;
	ULONG Ordinal = 0;

	if (NameThunk->u1.Ordinal & IMAGE_ORDINAL_FLAG32)
	{
		Ordinal = IMAGE_ORDINAL32(NameThunk->u1.Ordinal);
		dwFunAddr = (DWORD)GetProcAddress(hImpMode, (char*)Ordinal);
		//printf("0x%08X ����ŵ��� : %d\n",dwFunAddr,Ordinal);
	}
	else
	{
		pImpName = (PIMAGE_IMPORT_BY_NAME)(m_hModule + (ULONG)NameThunk->u1.AddressOfData);
		dwFunAddr = (DWORD)GetProcAddress(hImpMode, (char*)pImpName->Name);
		//printf("0x%08X �����Ƶ��� : %s\n",dwFunAddr,pImpName->Name);
	}

	if (dwFunAddr != 0)
	{
		AddrThunk->u1.Function = dwFunAddr;
		bResult = TRUE;
	}

	return bResult;
}
