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
	//设置卸载函数
	theDriverObject->DriverUnload = OnUnload;

	_asm
	{
		//读取IA32_SYSENTER_EIP
		mov ecx, 0x176
		rdmsr

		//保存原始数据
		//作用无非有二，第一为了回调该函数，第二为了卸载Hook的时候方便恢复。
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
	UCHAR  cHookCode[8] = { 0x57,          //push edi       第一跳,从KiFastCall跳到MyKiFastCallEntry.并绕过rootkit检测工具检测
						    0xBF,0,0,0,0,  //mov  edi,0000  0000需要被填充
							0xFF,0xE7 };   //jmp  edi

	UCHAR  JmpCode[] = {0xE9,0,0,0,0};       //jmp 0000 第三跳,从KiFastCall函数头代码跳转到原来KiFastCall+N

	int    nCopyLen = 0;
	int    nPos = 0;

	//得到KiFastCallEntry地址
	//但是也存在使用rdmsr读取的IP并不是KiFastCallEntry地址
	ULONG uSysenter=NULL;
	__asm {
		mov ecx, 0x176
		rdmsr
		mov uSysenter, eax  
	}
	DbgPrint("sysenter:0x%08X", uSysenter);

	//我们要改写的函数头至少需要8字节 这里计算实际需要COPY的代码长度 因为我们不能把一条完整的指令打断
	nPos = uSysenter;
	while (nCopyLen < 8) {
		nCopyLen += GetOpCodeSize((PVOID)nPos);  
		nPos = uSysenter + nCopyLen;
	}

	//保存原是的前八个字节代码
	ULONG uOrigSysenterHead[8];
	DbgPrint("copy code lenght:%d", nCopyLen);
	PVOID pMovedSysenterCode = ExAllocatePool(NonPagedPool, 20);
	memcpy(uOrigSysenterHead, (PVOID)uSysenter, 8);

	//计算跳转地址
	*((ULONG*)(JmpCode + 1)) = (uSysenter + nCopyLen) - ((ULONG)pMovedSysenterCode + nCopyLen) - 5;

	memcpy(pMovedSysenterCode, (PVOID)uSysenter, nCopyLen); //把原来的函数头放到新分配的内存
	memcpy((PVOID)(pMovedSysenterCode + nCopyLen), JmpCode, 5); //把跳转代码COPY上去

	*((ULONG*)(cHookCode + 2)) = (ULONG)MyKiFastCallEntry; //HOOK地址，其实填充的是第二条语句的地址

	DbgPrint("Saved sysenter code:0x%08X", pMovedSysenterCode);
	DbgPrint("MyKiFastCallEntry:0x%08X", MyKiFastCallEntry);

	__asm {
		cli
		mov  eax, cr0
		and  eax, not 10000h
		mov  cr0, eax
	}

	memcpy((PVOID)uSysenter, cHookCode, 8);//把改写原来函数头

	__asm {
		mov  eax, cr0
		or eax, 10000h
		mov  cr0, eax
		sti
	}

}
