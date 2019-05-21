#pragma once
# include <stdio.h>
# include <windows.h>

//处理函数例程
LONG WINAPI VectoredHandler1(struct _EXCEPTION_POINTERS *ExceptionInfo);
//LONG WINAPI VectoredHandler2(struct _EXCEPTION_POINTERS *ExceptionInfo);
//LONG WINAPI VectoredHandler3(struct _EXCEPTION_POINTERS *ExceptionInfo);

LONG WINAPI VectoredHandler1(struct _EXCEPTION_POINTERS *ExceptionInfo);
ULONG_PTR InitTrampolineFun();
BOOL InstallVEHHook(PVECTORED_EXCEPTION_HANDLER Handle);
BOOL SetBreakPoint();
BOOL ClearBreakPoint();
VOID UnInstallVEHHook();
