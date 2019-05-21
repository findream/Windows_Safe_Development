#include <ntddk.h>

#define OBJECT_TO_OBJECT_HEADER(o)\
      CONTAINING_RECORD((o),OBJECT_HEADER,Body)
#define CONTAINING_RECORD(address,type,field)\
      ((type*)(((ULONG_PTR)address)-(ULONG_PTR)(&(((type*)0)->field))))


typedef struct _OBJECT_TYPE_INITIALIZER {
	USHORT Length;
	BOOLEAN UseDefaultObject;
	BOOLEAN CaseInsensitive;
	ULONG InvalidAttributes;
	GENERIC_MAPPING GenericMapping;
	ULONG ValidAccessMask;
	BOOLEAN SecurityRequired;
	BOOLEAN MaintainHandleCount;
	BOOLEAN MaintainTypeList;
	POOL_TYPE PoolType;
	ULONG DefaultPagedPoolCharge;
	ULONG DefaultNonPagedPoolCharge;
	PVOID DumpProcedure;
	PVOID OpenProcedure;
	PVOID CloseProcedure;
	PVOID DeleteProcedure;
	PVOID ParseProcedure;
	PVOID SecurityProcedure;
	PVOID QueryNameProcedure;
	PVOID OkayToCloseProcedure;
} OBJECT_TYPE_INITIALIZER, *POBJECT_TYPE_INITIALIZER;


typedef struct _OBJECT_TYPE {
	ERESOURCE Mutex;
	LIST_ENTRY TypeList;
	UNICODE_STRING Name;
	PVOID DefaultObject;
	ULONG Index;
	ULONG TotalNumberOfObjects;
	ULONG TotalNumberOfHandles;
	ULONG HighWaterNumberOfObjects;
	ULONG HighWaterNumberOfHandles;
	OBJECT_TYPE_INITIALIZER TypeInfo;
#ifdef POOL_TAGGING 
	ULONG Key;
#endif 
} OBJECT_TYPE, *POBJECT_TYPE;

typedef struct _OBJECT_CREATE_INFORMATION {
	ULONG Attributes;
	HANDLE RootDirectory;
	PVOID ParseContext;
	KPROCESSOR_MODE ProbeMode;
	ULONG PagedPoolCharge;
	ULONG NonPagedPoolCharge;
	ULONG SecurityDescriptorCharge;
	PSECURITY_DESCRIPTOR SecurityDescriptor;
	PSECURITY_QUALITY_OF_SERVICE SecurityQos;
	SECURITY_QUALITY_OF_SERVICE SecurityQualityOfService;
} OBJECT_CREATE_INFORMATION, *POBJECT_CREATE_INFORMATION;



typedef struct _OBJECT_HEADER {
	LONG PointerCount;
	union {
		LONG HandleCount;
		PSINGLE_LIST_ENTRY SEntry;
	};
	POBJECT_TYPE Type;
	UCHAR NameInfoOffset;
	UCHAR HandleInfoOffset;
	UCHAR QuotaInfoOffset;
	UCHAR Flags;
	union
	{
		POBJECT_CREATE_INFORMATION ObjectCreateInfo;
		PVOID QuotaBlockCharged;
	};

	PSECURITY_DESCRIPTOR SecurityDescriptor;
	QUAD Body;
} OBJECT_HEADER, *POBJECT_HEADER;
POBJECT_TYPE pType = NULL;
POBJECT_HEADER addrs = NULL;
PVOID OldParseProcedure = NULL;


NTSTATUS NewParseProcedure(IN PVOID ParseObject,
	IN PVOID ObjectType,
	IN OUT PACCESS_STATE AccessState,
	IN KPROCESSOR_MODE AccessMode,
	IN ULONG Attributes,
	IN OUT PUNICODE_STRING CompleteName,
	IN OUT PUNICODE_STRING RemainingName,
	IN OUT PVOID Context OPTIONAL,
	IN PSECURITY_QUALITY_OF_SERVICE SecurityQos OPTIONAL,
	OUT PVOID *Object)
{
	NTSTATUS Status;
	KdPrint(("object is hook\n"));

	__asm
	{
		push eax
		push Object
		push SecurityQos
		push Context
		push RemainingName
		push CompleteName
		push Attributes
		movzx eax, AccessMode
		push eax
		push AccessState
		push ObjectType
		push ParseObject
		call OldParseProcedure
		mov Status, eax
		pop eax


	}
	return Status;

}
NTSTATUS Hook()
{
	NTSTATUS  Status;
	HANDLE hFile;
	UNICODE_STRING Name;
	OBJECT_ATTRIBUTES Attr;
	IO_STATUS_BLOCK ioStaBlock;
	PVOID pObject = NULL;


	RtlInitUnicodeString(&Name, L"\\Device\\HarddiskVolume1\\1.txt");
	InitializeObjectAttributes(&Attr,
		&Name, 
		OBJ_CASE_INSENSITIVE | OBJ_KERNEL_HANDLE, 
		0, NULL);
	Status = ZwOpenFile(&hFile,
		GENERIC_ALL,
		&Attr,
		&ioStaBlock, 
		0, FILE_NON_DIRECTORY_FILE);

	if (!NT_SUCCESS(Status))
	{
		KdPrint(("File is Null\n"));
		return Status;
	}

	//获取访问对象的句柄
	Status = ObReferenceObjectByHandle(hFile, GENERIC_ALL, NULL, KernelMode, &pObject, NULL);

	if (!NT_SUCCESS(Status))
	{
		KdPrint(("Object is Null\n"));
		return Status;
	}

	KdPrint(("pobject is %08X\n", pObject));

	addrs = OBJECT_TO_OBJECT_HEADER(pObject);//获取对象头

	//POBJECT_TYPE
	pType = addrs->Type;//获取对象类型结构 object-10h

	KdPrint(("pType is %08X\n", pType));

	//保存原始地址
	//POBJECT_TYPE->OBJECT_TYPE_INITIALIZER.ParseProcedure
	OldParseProcedure = pType->TypeInfo.ParseProcedure;//获取服务函数原始地址OBJECT_TYPE+9C位置为打开
	KdPrint(("OldParseProcedure addrs is %08X\n", OldParseProcedure));
	KdPrint(("addrs is %08X\n", addrs));
	//这里最好检查一下OldParseProcedure ，我真的是太懒了。

	//MDL去掉内存保护
	__asm
	{
		cli;
		mov eax, cr0;
		and eax, not 10000h;
		mov cr0, eax;
	}
	//hook
	pType->TypeInfo.ParseProcedure = NewParseProcedure;
	__asm
	{
		mov eax, cr0;
		or eax, 10000h;
		mov cr0, eax;
		sti;
	}
	Status = ZwClose(hFile);
	return Status;
}

NTSTATUS DriverEntry(PDRIVER_OBJECT DriverObject, PUNICODE_STRING RegistryPath)
{
	NTSTATUS Status = STATUS_SUCCESS;
	Status = Hook();
	return Status;
}