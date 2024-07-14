#include <stdio.h>
#include <windows.h>
#include <tlhelp32.h>
#include <stdint.h>

FARPROC WCTMBAddress;
DWORD textEncodeProcessId;
HANDLE textEncodeProcess;
FARPROC HWCTMBAddress;

FARPROC GetWCTMBAddress() {
	HMODULE hKernel32;
	FARPROC WCTMBAddress;

	hKernel32 = GetModuleHandleA("kernel32.dll");
	if (hKernel32 == NULL) {
		printf("[X] Failed to load kernel32.dll");
		exit(-1);
	}
	WCTMBAddress = GetProcAddress(hKernel32, "WideCharToMultiByte");
	if (WCTMBAddress == NULL) {
		printf("[X] Failed to retrieve WideCharToMultiByte address");
		exit(-1);
	}
	return WCTMBAddress;
}

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

HANDLE InjectDLL(DWORD textEncodeProcessId, const char* dllPath) {
	HANDLE textEncodeProcess = OpenProcess(PROCESS_CREATE_THREAD | PROCESS_QUERY_INFORMATION | PROCESS_VM_OPERATION | PROCESS_VM_WRITE | PROCESS_VM_READ, FALSE, textEncodeProcessId);
	if (textEncodeProcess == NULL) {
		printf("[X] Failed to get handle for process.\n");
		exit(-1);
	}
	LPVOID allocDllMem = VirtualAllocEx(textEncodeProcess, NULL, strlen(dllPath) + 1, MEM_COMMIT, PAGE_READWRITE);
	if (allocDllMem == NULL) {
		printf("[X] Failed to allocate memory for the DLLs name in the remote process.\n");
		exit(-1);
	}
	BOOL writeDllMem = WriteProcessMemory(textEncodeProcess, allocDllMem, (LPVOID)dllPath, strlen(dllPath) + 1, NULL);
	if (writeDllMem == 0) {
		printf("[X] Failed to write DLL name in the allocated space.\n");
		exit(-1);
	}
	LPVOID pLoadLibraryA = (LPVOID)GetProcAddress(GetModuleHandleA("kernel32.dll"), "LoadLibraryA");
	if (pLoadLibraryA == NULL) {
		printf("[X] Failed to find the address of LoadLibraryA.\n");
		exit(-1);
	}
	HANDLE hRemoteThread = CreateRemoteThread(textEncodeProcess, NULL, 0, (LPTHREAD_START_ROUTINE)pLoadLibraryA, allocDllMem, 0, NULL);
	if (hRemoteThread == NULL) {
		printf("Failed to load the DLL using LoadLibraryA.\n");
		exit(-1);
	}
	WaitForSingleObject(hRemoteThread, INFINITE);
	return textEncodeProcess;
}

FARPROC GetHWCTMBAddress() {
	HMODULE hHook;
	FARPROC HWCTMBAddress;

	hHook = LoadLibraryA("C:\\Users\\jdoe\\Desktop\\hook.dll");
	if (hHook == NULL) {
		printf("[X] Failed to load hook.dll");
		exit(-1);
	}

	HWCTMBAddress = GetProcAddress(hHook, "HookedWideCharToMultiByte");
	if (HWCTMBAddress == NULL) {
		printf("[X] Failed to retrieve HookedWideCharToMultiByte address");
		exit(-1);
	}
	return HWCTMBAddress;
}

void PatchWideCharToMultiByte(FARPROC HWCTMBAddress, FARPROC WCTMBAddress, HANDLE
	textEncodeProcess) {
	BYTE jmp[5];
	SIZE_T written;

	intptr_t offset = (intptr_t)HWCTMBAddress - ((intptr_t)WCTMBAddress + 5);
	jmp[0] = 0xE9;
	*((intptr_t*)(jmp + 1)) = offset;
	WriteProcessMemory(textEncodeProcess, WCTMBAddress, jmp, sizeof(jmp), &written);
	if (&written == 0) {
		printf("[X] Failed to patch WideCharToMultiByte");
		exit(-1);
	}
	return;
}

int main() {
	const char* dllPath = "C:\\Users\\jdoe\\Desktop\\hook.dll";
	printf("[-] Getting address of WideCharToMultiByte in memory.\n");
	WCTMBAddress = GetWCTMBAddress();
	printf("[+] Address of WideCharToMultiByte: %p\n", WCTMBAddress);

	printf("[-] Retrieving process ID of TextEncode.exe.\n");
	textEncodeProcessId = GetTextEncodeProcessId();
	printf("[+] Target process ID: %i\n", textEncodeProcessId);

	printf("[-] Attempting to inject the DLL in the TextEncode.exe process.\n");
	textEncodeProcess = InjectDLL(textEncodeProcessId, dllPath);
	printf("[+] DLL loaded.\n");

	printf("[-] Retrieving HookedWideCharToMultiByte address in memory.\n");
	HWCTMBAddress = GetHWCTMBAddress();
	printf("[+] Address of HookedWideCharToMultiByte: %p\n", HWCTMBAddress);

	printf("[-] Patching WideCharToMultiByte.\n");
	PatchWideCharToMultiByte(HWCTMBAddress, WCTMBAddress, textEncodeProcess);
	printf("[+] Patching Completed.");
}