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
	
	//设置卸载函数
	pDriverObject->DriverUnload = DriverUnload;

	for (ULONG i = 0; i < IRP_MJ_MAXIMUM_FUNCTION; i++)
	{
		pDriverObject->MajorFunction[i] = DriverDefaultHandle;
	}

	SSDTHook();

	DbgPrint("Leave DriverEntry\n");
	return status;
}

//卸载函数
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


//Hook函数
//Step1.获取系统服务索引号
//Step2.根据SSDT索引获取对应服务函数地址
BOOLEAN SSDTHook()
{
	//获取系统服务索引
	UNICODE_STRING ustrDllFileName;
	RtlInitUnicodeString(&ustrDllFileName, "\\??\\C:\\Windows\\System32\\ntdll.dll");
	ULONG ulSSDTFunctionIndex = NULL;
	ulSSDTFunctionIndex=GetSSDTFunctionIndex(ustrDllFileName, "ZwOpenProcess");

	//保存服务函数地址
	g_OldZwOpenProcess = (PVOID)KeServiceDescriptorTable.ServiceTableBase[ulSSDTFunctionIndex];
	if (NULL == g_OldZwOpenProcess)
	{
		DbgPrint("Get SSDT Function Address Failed\n");
		return FALSE;
	}

	//使用MDL修改SSDT
	//参考文章：https://www.write-bug.com/article/2136.html
	//用 MmCreateMdl 函数分配一个足够大的 MDL 结构来映射给定的缓冲区
	PMDL pMdl = NULL;
	pMdl=MmCreateMdl(NULL, &KeServiceDescriptorTable.ServiceTableBase[ulSSDTFunctionIndex], sizeof(ULONG));
	if (NULL == pMdl)
	{
		DbgPrint("MmCreateMdl Failed\n");
		return FALSE;
	}

	//使用MmBuildMdlForNonPagedPool()修改MDL对内存的描述
	MmBuildMdlForNonPagedPool(pMdl);

	//使用MmMapLockedPage()将Mdl中描述的物理内存映射到虚拟内存中
	//几乎所有驱动程序都应该使用KernelMode。
	PVOID pNewAddress = NULL;
	pNewAddress = MmMapLockedPages(pMdl, KernelMode);
	if (NULL == pNewAddress)
	{
		IoFreeMdl(pMdl);
		DbgPrint("MmMapLockedPages Failed\n");
		return FALSE;
	}
	//写入新地址
	RtlCopyMemory(pNewAddress, (ULONG)MyZwOpenProcess, sizeof(ULONG));
	
	//释放
	MmUnmapLockedPages(pNewAddress, pMdl);
	IoFreeMdl(pMdl);
	return TRUE;
}

ULONG GetSSDTFunctionIndex(UNICODE_STRING ustrDllFileName, PCHAR pszFunctionName)
{
	//映射文件
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

	//根据导出表获取导出函数地址，从而获取SSDT函数索引号
	ulFunctionIndex = GetIndexFromExportTable(pBaseAddress, pszFunctionName);
	return ulFunctionIndex;
}

//内存映射文件
NTSTATUS DllFileMap(UNICODE_STRING ustrDllFileName, HANDLE *phFile, HANDLE *phSection, PVOID *ppBaseAddress)
{
	NTSTATUS status = STATUS_SUCCESS;
	OBJECT_ATTRIBUTES objectAttributes = { 0 };
	IO_STATUS_BLOCK iosb = { 0 };
	HANDLE hFile = NULL;
	HANDLE hSection = NULL;
	PVOID pBaseAddress = NULL;
	SIZE_T viewSize = 0;

	//初始化文件对象
	InitializeObjectAttributes(&objectAttributes,
		&ustrDllFileName,
		OBJ_CASE_INSENSITIVE | OBJ_KERNEL_HANDLE,
		NULL, NULL);

	//获得映射文件句柄
	status = ZwOpenFile(&hFile,
		GENERIC_READ,
		&objectAttributes,
		&iosb,
		FILE_SHARE_READ,
		FILE_SYNCHRONOUS_IO_NONALERT);
	if (!NT_SUCCESS(status))
	{
		//DbgPrint宏定义
		KdPrint(("ZwOpenFile Error! [error code: 0x%X]", status));
		return status;
	}

	//创建一个节对象
	status = ZwCreateSection(&hSection, SECTION_MAP_READ | SECTION_MAP_WRITE, NULL, 0, PAGE_READWRITE, 0x100000, hFile);
	if (!NT_SUCCESS(status))
	{
		//DbgPrint宏定义
		ZwClose(hFile);
		KdPrint(("ZwCreateSection Error! [error code: 0x%X]", status));
		return status;
	}

	//将文件映射到内存
	status = ZwMapViewOfSection(hSection, NtCurrentProcess(), &pBaseAddress, 0, 1024, 0, &viewSize, ViewShare, MEM_TOP_DOWN, PAGE_READWRITE);
	if (!NT_SUCCESS(status))
	{
		//DbgPrint宏定义
		ZwClose(hFile);
		ZwClose(hSection);
		KdPrint(("ZwMapViewOfSection Error! [error code: 0x%X]", status));
		return status;
	}

	// 返回数据
	*phFile = hFile;
	*phSection = hSection;
	*ppBaseAddress = pBaseAddress;

	return status;
}


// 根据导出表获取导出函数地址, 从而获取 SSDT 函数索引号
ULONG GetIndexFromExportTable(PVOID pBaseAddress, PCHAR pszFunctionName)
{
	ULONG ulFunctionIndex = 0;
	// Dos Header
	PIMAGE_DOS_HEADER pDosHeader = (PIMAGE_DOS_HEADER)pBaseAddress;
	// NT Header
	PIMAGE_NT_HEADERS pNtHeaders = (PIMAGE_NT_HEADERS)((PUCHAR)pDosHeader + pDosHeader->e_lfanew);
	// Export Table
	PIMAGE_EXPORT_DIRECTORY pExportTable = (PIMAGE_EXPORT_DIRECTORY)((PUCHAR)pDosHeader + pNtHeaders->OptionalHeader.DataDirectory[0].VirtualAddress);
	// 有名称的导出函数个数
	ULONG ulNumberOfNames = pExportTable->NumberOfNames;
	// 导出函数名称地址表
	PULONG lpNameArray = (PULONG)((PUCHAR)pDosHeader + pExportTable->AddressOfNames);
	PCHAR lpName = NULL;
	// 开始遍历导出表
	for (ULONG i = 0; i < ulNumberOfNames; i++)
	{
		lpName = (PCHAR)((PUCHAR)pDosHeader + lpNameArray[i]);
		// 判断是否查找的函数
		if (0 == _strnicmp(pszFunctionName, lpName, strlen(pszFunctionName)))
		{
			// 获取导出函数地址
			USHORT uHint = *(USHORT *)((PUCHAR)pDosHeader + pExportTable->AddressOfNameOrdinals + 2 * i);
			ULONG ulFuncAddr = *(PULONG)((PUCHAR)pDosHeader + pExportTable->AddressOfFunctions + 4 * uHint);
			PVOID lpFuncAddr = (PVOID)((PUCHAR)pDosHeader + ulFuncAddr);
			// 获取 SSDT 函数 Index
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
	// 从 ntdll.dll 中获取 SSDT 函数索引号
	ulSSDTFunctionIndex = GetSSDTFunctionIndex(ustrDllFileName, "ZwOpenProcess");
	// 使用 MDL 方式修改 SSDT
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
	// 写入原函数地址
	ulOldFuncAddr = (ULONG)g_OldZwOpenProcess;
	RtlCopyMemory(pNewAddress, &ulOldFuncAddr, sizeof(ULONG));

	// 释放
	MmUnmapLockedPages(pNewAddress, pMdl);
	IoFreeMdl(pMdl);

	return TRUE;
}

//自写的函数
NTSTATUS NTAPI MyZwOpenProcess(
	_Out_ PHANDLE ProcessHandle,
	_In_ ACCESS_MASK DesiredAccess,
	_In_ POBJECT_ATTRIBUTES ObjectAttributes,
	_In_opt_ PCLIENT_ID ClientId
)
{
	//当此进程为要保护的进程时
	if (ClientId->UniqueProcess == (HANDLE)g_Pid &&
		DesiredAccess == PROCESS_TERMINATE)
	{
		//设为拒绝访问
		DesiredAccess = 0;
	}
	//调用原函数
	return g_OldZwOpenProcess(
		ProcessHandle,
		DesiredAccess,
		ObjectAttributes,
		ClientId);
}
