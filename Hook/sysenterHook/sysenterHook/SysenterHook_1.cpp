#include <ntddk.h>


__declspec(naked) void MyKiFastCallEntry()
{
	__asm {
		jmp[d_origKiFastCallEntry]
	}
}

VOID OnUnload(IN PDRIVER_OBJECT DriverObject)
{
	_asm
	{
		mov ecx, 0x176
		xor edx, edx
		mov eax, d_origKiFastCallEntry     // Hook function address
		wrmsr                        // Write to the IA32_SYSENTER_EIP register
	}
}


NTSTATUS DriverEntry(PDRIVER_OBJECT theDriverObject, PUNICODE_STRING theRegistryPath)
{
	//����ж�غ���
	theDriverObject->DriverUnload = OnUnload;

	_asm
	{
		//��ȡIA32_SYSENTER_EIP
		mov ecx, 0x176
		rdmsr

		//����ԭʼ����
		//�����޷��ж�����һΪ�˻ص��ú������ڶ�Ϊ��ж��Hook��ʱ�򷽱�ָ���
		mov d_origKiFastCallEntry eax

		//Hook
		mov eax,MyKiFastCallEntry
		wrmsr
	}
	return STATUS_SUCCESS;
}

//////////////
VOID HookSysenter()
{
	UCHAR  cHookCode[8] = { 0x57,          //push edi       ��һ��,��KiFastCall����MyKiFastCallEntry.���ƹ�rootkit��⹤�߼��
						    0xBF,0,0,0,0,  //mov  edi,0000  0000��Ҫ�����
							0xFF,0xE7 };   //jmp  edi

	UCHAR  JmpCode[] = {0xE9,0,0,0,0};       //jmp 0000 ������,��KiFastCall����ͷ������ת��ԭ��KiFastCall+N

	int    nCopyLen = 0;
	int    nPos = 0;

	//�õ�KiFastCallEntry��ַ
	//����Ҳ����ʹ��rdmsr��ȡ��IP������KiFastCallEntry��ַ
	ULONG uSysenter=NULL;
	__asm {
		mov ecx, 0x176
		rdmsr
		mov uSysenter, eax  
	}
	DbgPrint("sysenter:0x%08X", uSysenter);

	//����Ҫ��д�ĺ���ͷ������Ҫ8�ֽ� �������ʵ����ҪCOPY�Ĵ��볤�� ��Ϊ���ǲ��ܰ�һ��������ָ����
	nPos = uSysenter;
	while (nCopyLen < 8) {
		nCopyLen += GetOpCodeSize((PVOID)nPos);  
		nPos = uSysenter + nCopyLen;
	}

	//����ԭ�ǵ�ǰ�˸��ֽڴ���
	ULONG uOrigSysenterHead[8];
	DbgPrint("copy code lenght:%d", nCopyLen);
	PVOID pMovedSysenterCode = ExAllocatePool(NonPagedPool, 20);
	memcpy(uOrigSysenterHead, (PVOID)uSysenter, 8);

	//������ת��ַ
	*((ULONG*)(JmpCode + 1)) = (uSysenter + nCopyLen) - ((ULONG)pMovedSysenterCode + nCopyLen) - 5;

	memcpy(pMovedSysenterCode, (PVOID)uSysenter, nCopyLen); //��ԭ���ĺ���ͷ�ŵ��·�����ڴ�
	memcpy((PVOID)(pMovedSysenterCode + nCopyLen), JmpCode, 5); //����ת����COPY��ȥ

	*((ULONG*)(cHookCode + 2)) = (ULONG)MyKiFastCallEntry; //HOOK��ַ����ʵ�����ǵڶ������ĵ�ַ

	DbgPrint("Saved sysenter code:0x%08X", pMovedSysenterCode);
	DbgPrint("MyKiFastCallEntry:0x%08X", MyKiFastCallEntry);

	__asm {
		cli
		mov  eax, cr0
		and  eax, not 10000h
		mov  cr0, eax
	}

	memcpy((PVOID)uSysenter, cHookCode, 8);//�Ѹ�дԭ������ͷ

	__asm {
		mov  eax, cr0
		or eax, 10000h
		mov  cr0, eax
		sti
	}

}
