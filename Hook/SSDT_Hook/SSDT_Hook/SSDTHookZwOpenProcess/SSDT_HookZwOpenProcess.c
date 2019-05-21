#include <ntifs.h>
#include <ntddk.h>

#define PROCESS_TERMINATE 0x0001

//�ں�֮SSDT-HOOK
//ϵͳ�����
typedef struct _KSYSTEM_SERVICE_TABLE
{
	PULONG ServiceTableBase;       //������ַ����׵�ַ
	PULONG ServiceCounterTableBase;//��������ÿ�����������õĴ���
	ULONG  NumberOfService;        //�������ĸ���
	ULONG ParamTableBase;          //�����������׵�ַ
}KSYSTEM_SERVICE_TABLE;


typedef struct _KSERVICE_TABLE_DESCRIPTOR
{
	KSYSTEM_SERVICE_TABLE ntoskrnl;//ntoskrnl.exe�ķ�����,SSDT
	KSYSTEM_SERVICE_TABLE win32k;  //win32k.sys�ķ�����,ShadowSSDT
	KSYSTEM_SERVICE_TABLE notUsed1;//��ʱû��1
	KSYSTEM_SERVICE_TABLE notUsed2;//��ʱû��2
}KSERVICE_TABLE_DESCRIPTOR;



//����HOOK�ĺ���������
typedef NTSTATUS(NTAPI*FuZwOpenProcess)(
	_Out_ PHANDLE ProcessHandle,
	_In_ ACCESS_MASK DesiredAccess,
	_In_ POBJECT_ATTRIBUTES ObjectAttributes,
	_In_opt_ PCLIENT_ID ClientId
	);

//��д�ĺ�������
NTSTATUS NTAPI MyZwOpenProcess(
	_Out_ PHANDLE ProcessHandle,
	_In_ ACCESS_MASK DesiredAccess,
	_In_ POBJECT_ATTRIBUTES ObjectAttributes,
	_In_opt_ PCLIENT_ID ClientId
);

//��¼ϵͳ�ĸú���
FuZwOpenProcess g_OldZwOpenProcess;
//������������ָ��
KSERVICE_TABLE_DESCRIPTOR* g_pServiceTable = NULL;
//Ҫ�������̵�ID
ULONG g_Pid = 9527;

//��װ����
void InstallHook();
//ж�ع���
void UninstallHook();
//�ر�ҳд�뱣��
void ShutPageProtect();
//����ҳд�뱣��
void OpenPageProtect();

//ж������
void OutLoad(DRIVER_OBJECT* obj);



////***�������������***/
NTSTATUS DriverEntry(DRIVER_OBJECT* driver, UNICODE_STRING* path)
{
	path;
	KdPrint(("���������ɹ���\n"));
	//DbgBreakPoint();

	//��װ����
	InstallHook();

	driver->DriverUnload = OutLoad;
	return STATUS_SUCCESS;
}

//ж������
void OutLoad(DRIVER_OBJECT* obj)
{
	obj;
	//ж�ع���
	UninstallHook();
}

//��װ����
void InstallHook()
{
	//1.��ȡKTHREAD
	PETHREAD pNowThread = PsGetCurrentThread();
	//2.��ȡServiceTable��
	g_pServiceTable = (KSERVICE_TABLE_DESCRIPTOR*)
		(*(ULONG*)((ULONG)pNowThread + 0xbc));
	//3.����ɵĺ���
	g_OldZwOpenProcess = (FuZwOpenProcess)
		g_pServiceTable->ntoskrnl.ServiceTableBase[0xbe];
	//4.�ر�ҳֻ������
	ShutPageProtect();
	//5.д���Լ��ĺ�����SSDT����
	g_pServiceTable->ntoskrnl.ServiceTableBase[0xbe]
		= (ULONG)MyZwOpenProcess;
	//6.����ҳֻ������
	OpenPageProtect();
}

//ж�ع���
void UninstallHook()
{
	//1.�ر�ҳֻ������
	ShutPageProtect();
	//2.д��ԭ���ĺ�����SSDT����
	g_pServiceTable->ntoskrnl.ServiceTableBase[0xbe]
		= (ULONG)g_OldZwOpenProcess;
	//3.����ҳֻ������
	OpenPageProtect();
}

//�ر�ҳֻ������
void _declspec(naked) ShutPageProtect()
{
	__asm
	{
		push eax;
		mov eax, cr0;
		and eax, ~0x10000;
		mov cr0, eax;
		pop eax;
		ret;
	}
}

//����ҳֻ������
void _declspec(naked) OpenPageProtect()
{
	__asm
	{
		push eax;
		mov eax, cr0;
		or eax, 0x10000;
		mov cr0, eax;
		pop eax;
		ret;
	}
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