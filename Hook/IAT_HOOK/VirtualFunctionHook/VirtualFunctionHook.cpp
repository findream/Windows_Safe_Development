#include <iostream>
#include <windows.h>

using namespace std;
void VirtualFunHook();
LPVOID GetClassVirtualFnAddress(LPVOID pthis, int Index);




//ԭʼ��
class base
{
public :
	virtual int Add(int a, int b)
	{
		printf("base::Add:");
		return a + b;
	};
	virtual void g() { cout << "base::g" << endl; };
	virtual void h() { cout << "base::h" << endl; };
	void novirtual() { cout << "base::not virtual" << endl; };
};


//��Ϊʹ����This�ĵ��÷�����������Hook��ʱ��ͬʱ��Ҫ����DetourClass�࣬��֤����Լ����һ�µ�
class DetourClass
{
public:
	virtual int DetourFun(int a, int b);
};

//TrampolineClass����ԭ��Ҫ��Target����ԭ�ͱ���һ��
class TrampolineClass
{
public:
	virtual int TrampolineFun(int a,int b)
	{
		printf("TrampolineFun");
		return a + b;
	}
};

DetourClass Detour;
TrampolineClass Trampoline;

//�˴�����DetourFun
int DetourClass::DetourFun(int a, int b)
{
	//�˴�ִ���Զ������
	MessageBox(NULL, "Hooked", "warning", MB_OK);

	//����TrampolineFun��������Ҫ��TrampolineClassʵ����
	TrampolineClass *pTrampoline = new TrampolineClass;
	int iRet = pTrampoline->TrampolineFun(a, b);
	delete pTrampoline;
	return iRet+10;
}


int main(int agrc, char* argv[])
{

	base *pBase = new base;
	printf("FirstCall:%d\n", pBase->Add(1, 2));
	
	//HOOK
	VirtualFunHook();
	printf("SecondCall:%d\n", pBase->Add(1, 2));
}




//VirtualFun
void VirtualFunHook()
{
	DWORD dwOldProtect;

	//��ȡ����ַvfTableToHook
	base base;
	printf("[*]pBase=0x%x\n", &base);
	ULONG_PTR *vfTableToHook = (ULONG_PTR*)*(ULONG_PTR*)&base;
	printf("[*]vfTable = 0x%x\n", vfTableToHook);

	//��ȡTrampoline����ַ�����ڻص�
	ULONG_PTR *vfTableTrampoline = (ULONG_PTR*)*(ULONG_PTR*)&Trampoline;

	//��һ���޸ģ����ڱ���ԭʼ��Target������ַ
	//�޸��ڴ汣������
	VirtualProtect(vfTableTrampoline, sizeof(ULONG_PTR), PAGE_EXECUTE_READWRITE, &dwOldProtect);
	vfTableTrampoline[0] = (ULONG_PTR)GetClassVirtualFnAddress(&base, 0);
	printf("[*]vfTableTrampoline=0x%x\n", vfTableTrampoline[0]);
	VirtualProtect(vfTableTrampoline, sizeof(ULONG_PTR), dwOldProtect, &dwOldProtect);

	//�ڶ����޸ģ�Ϊ��HookTarget�������޸�ԭʼ���
	VirtualProtect(vfTableToHook, sizeof(ULONG_PTR), PAGE_EXECUTE_READWRITE, &dwOldProtect);
	vfTableToHook[0] = (ULONG_PTR)GetClassVirtualFnAddress(&Detour, 0);
	printf("[*]vfTableTrampoline=0x%x\n", vfTableToHook[0]);
	VirtualProtect(vfTableToHook, sizeof(ULONG_PTR), dwOldProtect, &dwOldProtect);
}


//����������Ա����ָ��
LPVOID GetClassVirtualFnAddress(LPVOID pthis, int Index)
{
	ULONG_PTR *vfTable = (ULONG_PTR*)*(ULONG_PTR*)pthis;
	return (LPVOID)vfTable[Index];
}



