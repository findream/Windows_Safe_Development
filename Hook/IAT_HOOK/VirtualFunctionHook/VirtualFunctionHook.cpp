#include <iostream>
#include <windows.h>

using namespace std;
void VirtualFunHook();
LPVOID GetClassVirtualFnAddress(LPVOID pthis, int Index);




//原始类
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


//因为使用了This的调用方法，所以在Hook的时候同时需要创建DetourClass类，保证函数约定是一致的
class DetourClass
{
public:
	virtual int DetourFun(int a, int b);
};

//TrampolineClass函数原型要与Target函数原型保持一致
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

//此处构造DetourFun
int DetourClass::DetourFun(int a, int b)
{
	//此处执行自定义操作
	MessageBox(NULL, "Hooked", "warning", MB_OK);

	//调用TrampolineFun，首先需要将TrampolineClass实例化
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

	//获取虚表地址vfTableToHook
	base base;
	printf("[*]pBase=0x%x\n", &base);
	ULONG_PTR *vfTableToHook = (ULONG_PTR*)*(ULONG_PTR*)&base;
	printf("[*]vfTable = 0x%x\n", vfTableToHook);

	//获取Trampoline虚表地址，用于回调
	ULONG_PTR *vfTableTrampoline = (ULONG_PTR*)*(ULONG_PTR*)&Trampoline;

	//第一次修改，用于保存原始的Target函数地址
	//修改内存保护属性
	VirtualProtect(vfTableTrampoline, sizeof(ULONG_PTR), PAGE_EXECUTE_READWRITE, &dwOldProtect);
	vfTableTrampoline[0] = (ULONG_PTR)GetClassVirtualFnAddress(&base, 0);
	printf("[*]vfTableTrampoline=0x%x\n", vfTableTrampoline[0]);
	VirtualProtect(vfTableTrampoline, sizeof(ULONG_PTR), dwOldProtect, &dwOldProtect);

	//第二次修改，为了HookTarget函数，修改原始虚表
	VirtualProtect(vfTableToHook, sizeof(ULONG_PTR), PAGE_EXECUTE_READWRITE, &dwOldProtect);
	vfTableToHook[0] = (ULONG_PTR)GetClassVirtualFnAddress(&Detour, 0);
	printf("[*]vfTableTrampoline=0x%x\n", vfTableToHook[0]);
	VirtualProtect(vfTableToHook, sizeof(ULONG_PTR), dwOldProtect, &dwOldProtect);
}


//获得类虚拟成员函数指针
LPVOID GetClassVirtualFnAddress(LPVOID pthis, int Index)
{
	ULONG_PTR *vfTable = (ULONG_PTR*)*(ULONG_PTR*)pthis;
	return (LPVOID)vfTable[Index];
}



