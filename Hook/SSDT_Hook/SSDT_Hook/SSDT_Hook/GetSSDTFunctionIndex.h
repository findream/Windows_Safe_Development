#pragma once

#include <fltkernel.h>
#include <ntddk.h>
#include <stdio.h>
#include <ntimage.h>
#include <wdm.h>
#include <ntifs.h>



typedef struct _SERVICE_DESCIPTOR_TABLE
{
	PULONG ServiceTableBase;		  // SSDT��ַ
	PULONG ServiceCounterTableBase;   // SSDT�з��񱻵��ô���������
	ULONG NumberOfService;            // SSDT�������
	PUCHAR ParamTableBase;		      // ϵͳ����������ַ
}SSDTEntry, *PSSDTEntry;

//����HOOK�ĺ���������
typedef NTSTATUS(NTAPI*FuZwOpenProcess)(
	_Out_ PHANDLE ProcessHandle,
	_In_ ACCESS_MASK DesiredAccess,
	_In_ POBJECT_ATTRIBUTES ObjectAttributes,
	_In_opt_ PCLIENT_ID ClientId
	);

//��Ϊ��X86������SSDTֱ����KiServiceDescritorTable����
//��ֱ�Ӿ������ðɣ�����Ҫ֪��_declspec(dllexport)��_declspec(dllexport)
//��һ���ⲿ����Ҫʹ��DLL �ڲ����루�࣬������ȫ�ֱ�����ʱ��ֻ��Ҫ�ڳ����ڲ�ʹ�ã�dllimport���ؼ���������Ҫʹ�õĴ���Ϳ�����
//����������Щ�������Ա��ⲿ����ʹ�ã�����dllexport���ǰ� DLL�е���ش��루�࣬���������ݣ���¶����Ϊ����Ӧ�ó���ʹ�á�

extern SSDTEntry __declspec(dllimport) KeServiceDescriptorTable;

VOID DriverUnload(PDRIVER_OBJECT pDriverObject);

NTSTATUS DriverDefaultHandle(PDEVICE_OBJECT pDevObj, PIRP pIrp);

BOOLEAN SSDTHook();

ULONG GetSSDTFunctionIndex(UNICODE_STRING ustrDllFileName, PCHAR pszFunctionName);

NTSTATUS DllFileMap(UNICODE_STRING ustrDllFileName, HANDLE *phFile, HANDLE *phSection, PVOID *ppBaseAddress);

ULONG GetIndexFromExportTable(PVOID pBaseAddress, PCHAR pszFunctionName);



//��д�ĺ�������
NTSTATUS NTAPI MyZwOpenProcess(
	_Out_ PHANDLE ProcessHandle,
	_In_ ACCESS_MASK DesiredAccess,
	_In_ POBJECT_ATTRIBUTES ObjectAttributes,
	_In_opt_ PCLIENT_ID ClientId
);

BOOLEAN SSDTUnhook();