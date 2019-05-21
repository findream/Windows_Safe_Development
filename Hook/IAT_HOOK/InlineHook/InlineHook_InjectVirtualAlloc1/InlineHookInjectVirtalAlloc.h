#pragma once
#include <stdio.h>
#include <windows.h>

void TestHook();

LPVOID WINAPI DetourVirtualAllocEx(
	HANDLE hProcess,
	LPVOID lpAddress,
	SIZE_T dwSize,
	DWORD  flAllocationType,
	DWORD  flProtect
);

BOOL Inline_InstallHook();

BOOL Inline_UninstallHook();