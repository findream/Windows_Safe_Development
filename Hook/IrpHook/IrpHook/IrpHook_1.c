
#include "ntddk.h"

typedef NTSTATUS(FASTCALL
	*pIofCallDriver)(
		IN PDEVICE_OBJECT DeviceObject,
		IN OUT PIRP Irp);

pIofCallDriver old_piofcalldriver;
UNICODE_STRING SymbolicLinkName;
PDRIVER_OBJECT g_drvobj;
UNICODE_STRING DeviceName;
PDEVICE_OBJECT deviceObject;
ULONG oData;

#define IOCTL_DISABLE  CTL_CODE(FILE_DEVICE_UNKNOWN ,0x8101,METHOD_BUFFERED,FILE_ANY_ACCESS)   
#define IOCTL_ENABLE   CTL_CODE(FILE_DEVICE_UNKNOWN ,0x8100,METHOD_BUFFERED,FILE_ANY_ACCESS)   


NTSTATUS FASTCALL
NewpIofCallDriver(
	IN PDEVICE_OBJECT DeviceObject,
	IN OUT PIRP Irp
)
{
	NTSTATUS stat;
	DbgPrint("Hacked Great!");

	__asm
	{
		mov ecx, DeviceObject
		mov edx, Irp
		Call old_piofcalldriver
		mov stat, eax
	}
	return stat;
}

NTSTATUS DriverIoControl(
	IN PDEVICE_OBJECT DeviceObject,
	IN PIRP Irp)
{
	PIO_STACK_LOCATION pisl;
	NTSTATUS ns = STATUS_UNSUCCESSFUL;
	ULONG BuffSize, DataSize;
	PVOID pBuff, pData, pInout;
	KIRQL OldIrql;
	ULONG i;
	pisl = IoGetCurrentIrpStackLocation(Irp);

	BuffSize = pisl->Parameters.DeviceIoControl.OutputBufferLength;

	pBuff = Irp->AssociatedIrp.SystemBuffer;

	Irp->IoStatus.Information = 0;
	switch (pisl->Parameters.DeviceIoControl.IoControlCode)
	{
	case IOCTL_DISABLE:
	{

		DbgPrint("IOCTL_DISABLE");
		ns = STATUS_SUCCESS;

	}
	break;
	case IOCTL_ENABLE:
	{

		DbgPrint("IOCTL_ENABLE");
		ns = STATUS_SUCCESS;

	}
	break;
	}

	Irp->IoStatus.Status = ns;
	IoCompleteRequest(Irp, IO_NO_INCREMENT);
	return ns;
}

NTSTATUS DrivercreateClose(
	IN PDEVICE_OBJECT DeviceObject,
	IN PIRP Irp)
{
	Irp->IoStatus.Information = 0;
	Irp->IoStatus.Status = STATUS_SUCCESS;
	IoCompleteRequest(Irp, IO_NO_INCREMENT);
	return STATUS_SUCCESS;

}

void UnHookpIofCallDriver()
{
	KIRQL oldIrql;
	ULONG addr = (ULONG)IofCallDriver;

	oldIrql = KeRaiseIrqlToDpcLevel();
	__asm
	{
		mov eax, cr0
		mov oData, eax
		and eax, 0xffffffff
		mov cr0, eax
		mov eax, addr
		mov esi, [eax + 2]
		mov eax, old_piofcalldriver
		mov dword ptr[esi], eax
		mov eax, oData
		mov cr0, eax
	}
	KeLowerIrql(oldIrql);
	return;
}

VOID DriverUnload(IN PDRIVER_OBJECT DriverObject)
{
	UnHookpIofCallDriver();
	IoDeleteSymbolicLink(&SymbolicLinkName);
	IoDeleteDevice(deviceObject);
}

NTSTATUS DriverClose(
	IN PDEVICE_OBJECT DeviceObject,
	IN PIRP Irp)
{
	return DrivercreateClose(DeviceObject, Irp);
}

NTSTATUS IoComplete(
	IN PDEVICE_OBJECT DeviceObject,
	IN PIRP Irp)
{
	IoCompleteRequest(Irp, IO_NO_INCREMENT);
	return STATUS_SUCCESS;
}


void HookpIofCallDriver()
{
	KIRQL oldIrql;
	ULONG addr = (ULONG)IofCallDriver;
	//保存原始的IofCallDriver函数地址
	__asm
	{
		mov eax, addr
		mov esi, [eax + 2]
		mov eax, [esi]
		mov old_piofcalldriver, eax
	}
	//引发硬件优先IRQL
	oldIrql = KeRaiseIrqlToDpcLevel();
	__asm
	{
		mov eax, cr0
		mov oData, eax
		and eax, 0xffffffff
		mov cr0, eax
		mov eax, addr; IofCallDriver
		mov esi, [eax + 2]
		mov dword ptr[esi], offset NewpIofCallDriver; 写入新的数据
		mov eax, oData;恢复cr0的数据
		mov cr0, eax
	}
	KeLowerIrql(oldIrql);
	return;
}


//驱动入口函数
NTSTATUS DriverEntry(IN PDRIVER_OBJECT DriverObject,
	IN PUNICODE_STRING RegistryPath)
{
	NTSTATUS status;
	PDRIVER_DISPATCH *ppdd;
	ULONG i;
	PCWSTR dDeviceName = L"\\Device\\irphook";
	PCWSTR dSymbolicLinkName = L"\\DosDevices\\irphook";

	RtlInitUnicodeString(&DeviceName, dDeviceName);
	RtlInitUnicodeString(&SymbolicLinkName, dSymbolicLinkName);

	//创建一个设备对象
	status = IoCreateDevice(DriverObject, 0, &DeviceName, FILE_DEVICE_UNKNOWN, 0, TRUE, &deviceObject);
	if (!NT_SUCCESS(status)) 
		return status;

	//设备名和用户可见名字之间创建链接
	//果想要在用户层的应用程序中访问(比如调用CreateFile函数打开)，就需要创建符号链接
	//应用层是无法直接通过设备名字来打开对象的，必须建立一个暴露给应用程序的符号链接
	status = IoCreateSymbolicLink(&SymbolicLinkName, &DeviceName);


	DriverObject->DriverUnload = DriverUnload;
	ppdd = DriverObject->MajorFunction;
	for (i = 0; i <= IRP_MJ_MAXIMUM_FUNCTION; i++)
		ppdd[i] = IoComplete;

	ppdd[IRP_MJ_CREATE] = DrivercreateClose;
	ppdd[IRP_MJ_DEVICE_CONTROL] = DriverIoControl;
	g_drvobj = DriverObject;
	HookpIofCallDriver();
	return status;
}

