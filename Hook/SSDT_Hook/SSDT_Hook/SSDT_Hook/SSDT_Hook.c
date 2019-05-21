#include "GetSSDTFunctionIndex.h"

#define PROCESS_TERMINATE 0x0001
FuZwOpenProcess g_OldZwOpenProcess = NULL;
HANDLE g_Pid = NULL;

/*----------------------------------------------
                  Driver.c
-----------------------------------------------*/
NTSTATUS DriverEntry(PDRIVER_OBJECT pDriverObject, PUNICODE_STRING pRegPath)
{
	DbgPrint("[*]Enter DriverEntry\n");

	NTSTATUS status = STATUS_SUCCESS;
	
	//����ж�غ���
	pDriverObject->DriverUnload = DriverUnload;

	for (ULONG i = 0; i < IRP_MJ_MAXIMUM_FUNCTION; i++)
	{
		pDriverObject->MajorFunction[i] = DriverDefaultHandle;
	}

	SSDTHook();

	DbgPrint("Leave DriverEntry\n");
	return status;
}

//ж�غ���
VOID DriverUnload(PDRIVER_OBJECT pDriverObject)
{
	SSDTUnhook();
}

NTSTATUS DriverDefaultHandle(PDEVICE_OBJECT pDevObj, PIRP pIrp)
{
	NTSTATUS status = STATUS_SUCCESS;
	pIrp->IoStatus.Status= status;
	pIrp->IoStatus.Information = 0;
	IoCompleteRequest(pIrp, IO_NO_INCREMENT);

	return status;
}


//Hook����
//Step1.��ȡϵͳ����������
//Step2.����SSDT������ȡ��Ӧ��������ַ
BOOLEAN SSDTHook()
{
	//��ȡϵͳ��������
	UNICODE_STRING ustrDllFileName;
	RtlInitUnicodeString(&ustrDllFileName, "\\??\\C:\\Windows\\System32\\ntdll.dll");
	ULONG ulSSDTFunctionIndex = NULL;
	ulSSDTFunctionIndex=GetSSDTFunctionIndex(ustrDllFileName, "ZwOpenProcess");

	//�����������ַ
	g_OldZwOpenProcess = (PVOID)KeServiceDescriptorTable.ServiceTableBase[ulSSDTFunctionIndex];
	if (NULL == g_OldZwOpenProcess)
	{
		DbgPrint("Get SSDT Function Address Failed\n");
		return FALSE;
	}

	//ʹ��MDL�޸�SSDT
	//�ο����£�https://www.write-bug.com/article/2136.html
	//�� MmCreateMdl ��������һ���㹻��� MDL �ṹ��ӳ������Ļ�����
	PMDL pMdl = NULL;
	pMdl=MmCreateMdl(NULL, &KeServiceDescriptorTable.ServiceTableBase[ulSSDTFunctionIndex], sizeof(ULONG));
	if (NULL == pMdl)
	{
		DbgPrint("MmCreateMdl Failed\n");
		return FALSE;
	}

	//ʹ��MmBuildMdlForNonPagedPool()�޸�MDL���ڴ������
	MmBuildMdlForNonPagedPool(pMdl);

	//ʹ��MmMapLockedPage()��Mdl�������������ڴ�ӳ�䵽�����ڴ���
	//����������������Ӧ��ʹ��KernelMode��
	PVOID pNewAddress = NULL;
	pNewAddress = MmMapLockedPages(pMdl, KernelMode);
	if (NULL == pNewAddress)
	{
		IoFreeMdl(pMdl);
		DbgPrint("MmMapLockedPages Failed\n");
		return FALSE;
	}
	//д���µ�ַ
	RtlCopyMemory(pNewAddress, (ULONG)MyZwOpenProcess, sizeof(ULONG));
	
	//�ͷ�
	MmUnmapLockedPages(pNewAddress, pMdl);
	IoFreeMdl(pMdl);
	return TRUE;
}

ULONG GetSSDTFunctionIndex(UNICODE_STRING ustrDllFileName, PCHAR pszFunctionName)
{
	//ӳ���ļ�
	HANDLE hFile = NULL;
	HANDLE hSection = NULL;
	PVOID pBaseAddress = NULL;
	ULONG ulFunctionIndex = 0;

	NTSTATUS status = DllFileMap(ustrDllFileName, &hFile, hSection, &pBaseAddress);
	if (!NT_SUCCESS(status))
	{
		DbgPrint("DllFileMap Error!\n");
		return 0;
	}

	//���ݵ������ȡ����������ַ���Ӷ���ȡSSDT����������
	ulFunctionIndex = GetIndexFromExportTable(pBaseAddress, pszFunctionName);
	return ulFunctionIndex;
}

//�ڴ�ӳ���ļ�
NTSTATUS DllFileMap(UNICODE_STRING ustrDllFileName, HANDLE *phFile, HANDLE *phSection, PVOID *ppBaseAddress)
{
	NTSTATUS status = STATUS_SUCCESS;
	OBJECT_ATTRIBUTES objectAttributes = { 0 };
	IO_STATUS_BLOCK iosb = { 0 };
	HANDLE hFile = NULL;
	HANDLE hSection = NULL;
	PVOID pBaseAddress = NULL;
	SIZE_T viewSize = 0;

	//��ʼ���ļ�����
	InitializeObjectAttributes(&objectAttributes,
		&ustrDllFileName,
		OBJ_CASE_INSENSITIVE | OBJ_KERNEL_HANDLE,
		NULL, NULL);

	//���ӳ���ļ����
	status = ZwOpenFile(&hFile,
		GENERIC_READ,
		&objectAttributes,
		&iosb,
		FILE_SHARE_READ,
		FILE_SYNCHRONOUS_IO_NONALERT);
	if (!NT_SUCCESS(status))
	{
		//DbgPrint�궨��
		KdPrint(("ZwOpenFile Error! [error code: 0x%X]", status));
		return status;
	}

	//����һ���ڶ���
	status = ZwCreateSection(&hSection, SECTION_MAP_READ | SECTION_MAP_WRITE, NULL, 0, PAGE_READWRITE, 0x100000, hFile);
	if (!NT_SUCCESS(status))
	{
		//DbgPrint�궨��
		ZwClose(hFile);
		KdPrint(("ZwCreateSection Error! [error code: 0x%X]", status));
		return status;
	}

	//���ļ�ӳ�䵽�ڴ�
	status = ZwMapViewOfSection(hSection, NtCurrentProcess(), &pBaseAddress, 0, 1024, 0, &viewSize, ViewShare, MEM_TOP_DOWN, PAGE_READWRITE);
	if (!NT_SUCCESS(status))
	{
		//DbgPrint�궨��
		ZwClose(hFile);
		ZwClose(hSection);
		KdPrint(("ZwMapViewOfSection Error! [error code: 0x%X]", status));
		return status;
	}

	// ��������
	*phFile = hFile;
	*phSection = hSection;
	*ppBaseAddress = pBaseAddress;

	return status;
}


// ���ݵ������ȡ����������ַ, �Ӷ���ȡ SSDT ����������
ULONG GetIndexFromExportTable(PVOID pBaseAddress, PCHAR pszFunctionName)
{
	ULONG ulFunctionIndex = 0;
	// Dos Header
	PIMAGE_DOS_HEADER pDosHeader = (PIMAGE_DOS_HEADER)pBaseAddress;
	// NT Header
	PIMAGE_NT_HEADERS pNtHeaders = (PIMAGE_NT_HEADERS)((PUCHAR)pDosHeader + pDosHeader->e_lfanew);
	// Export Table
	PIMAGE_EXPORT_DIRECTORY pExportTable = (PIMAGE_EXPORT_DIRECTORY)((PUCHAR)pDosHeader + pNtHeaders->OptionalHeader.DataDirectory[0].VirtualAddress);
	// �����Ƶĵ�����������
	ULONG ulNumberOfNames = pExportTable->NumberOfNames;
	// �����������Ƶ�ַ��
	PULONG lpNameArray = (PULONG)((PUCHAR)pDosHeader + pExportTable->AddressOfNames);
	PCHAR lpName = NULL;
	// ��ʼ����������
	for (ULONG i = 0; i < ulNumberOfNames; i++)
	{
		lpName = (PCHAR)((PUCHAR)pDosHeader + lpNameArray[i]);
		// �ж��Ƿ���ҵĺ���
		if (0 == _strnicmp(pszFunctionName, lpName, strlen(pszFunctionName)))
		{
			// ��ȡ����������ַ
			USHORT uHint = *(USHORT *)((PUCHAR)pDosHeader + pExportTable->AddressOfNameOrdinals + 2 * i);
			ULONG ulFuncAddr = *(PULONG)((PUCHAR)pDosHeader + pExportTable->AddressOfFunctions + 4 * uHint);
			PVOID lpFuncAddr = (PVOID)((PUCHAR)pDosHeader + ulFuncAddr);
			// ��ȡ SSDT ���� Index
#ifdef _WIN64
			ulFunctionIndex = *(ULONG *)((PUCHAR)lpFuncAddr + 4);
#else
			ulFunctionIndex = *(ULONG *)((PUCHAR)lpFuncAddr + 1);
#endif
			break;
		}
	}
	return ulFunctionIndex;
}

BOOLEAN SSDTUnhook()
{
	UNICODE_STRING ustrDllFileName;
	ULONG ulSSDTFunctionIndex = 0;
	PVOID pSSDTFunctionAddress = NULL;
	PMDL pMdl = NULL;
	PVOID pNewAddress = NULL;
	ULONG ulOldFuncAddr = 0;

	RtlInitUnicodeString(&ustrDllFileName, L"\\??\\C:\\Windows\\System32\\ntdll.dll");
	// �� ntdll.dll �л�ȡ SSDT ����������
	ulSSDTFunctionIndex = GetSSDTFunctionIndex(ustrDllFileName, "ZwOpenProcess");
	// ʹ�� MDL ��ʽ�޸� SSDT
	pMdl = MmCreateMdl(NULL, &KeServiceDescriptorTable.ServiceTableBase[ulSSDTFunctionIndex], sizeof(ULONG));
	if (NULL == pMdl)
	{
		DbgPrint("MmCreateMdl Error!\n");
		return FALSE;
	}
	MmBuildMdlForNonPagedPool(pMdl);
	pNewAddress = MmMapLockedPages(pMdl, KernelMode);
	if (NULL == pNewAddress)
	{
		IoFreeMdl(pMdl);
		DbgPrint("MmMapLockedPages Error!\n");
		return FALSE;
	}
	// д��ԭ������ַ
	ulOldFuncAddr = (ULONG)g_OldZwOpenProcess;
	RtlCopyMemory(pNewAddress, &ulOldFuncAddr, sizeof(ULONG));

	// �ͷ�
	MmUnmapLockedPages(pNewAddress, pMdl);
	IoFreeMdl(pMdl);

	return TRUE;
}

//��д�ĺ���
NTSTATUS NTAPI MyZwOpenProcess(
	_Out_ PHANDLE ProcessHandle,
	_In_ ACCESS_MASK DesiredAccess,
	_In_ POBJECT_ATTRIBUTES ObjectAttributes,
	_In_opt_ PCLIENT_ID ClientId
)
{
	//���˽���ΪҪ�����Ľ���ʱ
	if (ClientId->UniqueProcess == (HANDLE)g_Pid &&
		DesiredAccess == PROCESS_TERMINATE)
	{
		//��Ϊ�ܾ�����
		DesiredAccess = 0;
	}
	//����ԭ����
	return g_OldZwOpenProcess(
		ProcessHandle,
		DesiredAccess,
		ObjectAttributes,
		ClientId);
}
