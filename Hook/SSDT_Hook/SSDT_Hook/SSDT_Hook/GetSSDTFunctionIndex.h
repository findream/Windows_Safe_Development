#pragma once

#include <fltkernel.h>
#include <ntddk.h>
#include <stdio.h>
#include <ntimage.h>
#include <wdm.h>
#include <ntifs.h>



typedef struct _SERVICE_DESCIPTOR_TABLE
{
	PULONG ServiceTableBase;		  // SSDT基址
	PULONG ServiceCounterTableBase;   // SSDT中服务被调用次数计数器
	ULONG NumberOfService;            // SSDT服务个数
	PUCHAR ParamTableBase;		      // 系统服务参数表基址
}SSDTEntry, *PSSDTEntry;

//定义HOOK的函数的类型
typedef NTSTATUS(NTAPI*FuZwOpenProcess)(
	_Out_ PHANDLE ProcessHandle,
	_In_ ACCESS_MASK DesiredAccess,
	_In_ POBJECT_ATTRIBUTES ObjectAttributes,
	_In_opt_ PCLIENT_ID ClientId
	);

//因为是X86，所以SSDT直接有KiServiceDescritorTable导出
//你直接就这样用吧，就需要知道_declspec(dllexport)和_declspec(dllexport)
//当一个外部程序要使用DLL 内部代码（类，函数，全局变量）时，只需要在程序内部使用（dllimport）关键字声明需要使用的代码就可以了
//用他表明这些东西可以被外部函数使用，即（dllexport）是把 DLL中的相关代码（类，函数，数据）暴露出来为其他应用程序使用。

extern SSDTEntry __declspec(dllimport) KeServiceDescriptorTable;

VOID DriverUnload(PDRIVER_OBJECT pDriverObject);

NTSTATUS DriverDefaultHandle(PDEVICE_OBJECT pDevObj, PIRP pIrp);

BOOLEAN SSDTHook();

ULONG GetSSDTFunctionIndex(UNICODE_STRING ustrDllFileName, PCHAR pszFunctionName);

NTSTATUS DllFileMap(UNICODE_STRING ustrDllFileName, HANDLE *phFile, HANDLE *phSection, PVOID *ppBaseAddress);

ULONG GetIndexFromExportTable(PVOID pBaseAddress, PCHAR pszFunctionName);



//自写的函数声明
NTSTATUS NTAPI MyZwOpenProcess(
	_Out_ PHANDLE ProcessHandle,
	_In_ ACCESS_MASK DesiredAccess,
	_In_ POBJECT_ATTRIBUTES ObjectAttributes,
	_In_opt_ PCLIENT_ID ClientId
);

BOOLEAN SSDTUnhook();