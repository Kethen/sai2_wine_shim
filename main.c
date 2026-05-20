#include <sysinfoapi.h>
#include <libloaderapi.h>
#include <errhandlingapi.h>
#include <guiddef.h>
#include <winerror.h>
#include <winternl.h>
#include <ntstatus.h>
#include <fileapi.h>

#include <stdlib.h>
#include <stdio.h>
#include <stdarg.h>
#include <stdint.h>

#include <MinHook.h>

#define ARRAY_SIZE(a) (sizeof(a) / sizeof(a[0]))

#define LOG_PATH "sai2_wine_shim.log"

static void LOG(const char *fmt, ...){
	FILE *log_file = fopen(LOG_PATH, "ab");

	char log_buf[1024] = {0};

	va_list args;
	va_start(args, fmt);
	int log_len = vsnprintf(log_buf, sizeof(log_buf), fmt, args);
	va_end(args);
	printf("%s", log_buf);

	if (log_file != NULL){
		fprintf(log_file, "%s", log_buf);
		fclose(log_file);
	}
}

static void INIT_LOG(){
	FILE *log_file = fopen(LOG_PATH, "wb");
	if (log_file != NULL){
		fclose(log_file);
	}
}

#define STR(s) #s
#define HOOK(name) { \
	int status = MH_CreateHook(name, name##_hooked, (void **)&name##_orig); \
	if (status != MH_OK){ \
		LOG("%s: failed creating hook for %s, %d\n", __func__, STR(name), status); \
		exit(1); \
	} \
	status = MH_EnableHook(name); \
	if (status != MH_OK){ \
		LOG("%s: failed enabling hook for %s, %d\n", __func__, STR(name), status); \
		exit(1); \
	} \
	LOG("%s: hooked %s\n", __func__, STR(name)); \
}

#define HOOK_TARGET(target, name) { \
	int status = MH_CreateHook(target, name##_hooked, (void **)&name##_orig); \
	if (status != MH_OK){ \
		LOG("%s: failed creating hook for %s, %d\n", __func__, STR(name), status); \
		exit(1); \
	} \
	status = MH_EnableHook(target); \
	if (status != MH_OK){ \
		LOG("%s: failed enabling hook for %s, %d\n", __func__, STR(name), status); \
		exit(1); \
	} \
	LOG("%s: hooked %s\n", __func__, STR(name)); \
}

#define HOOK_API(module, name) { \
	void *target; \
	int status = MH_CreateHookApiEx(module, STR(name), name##_hooked, (void **)&name##_orig, &target); \
	if (status != MH_OK){ \
		LOG("%s: failed creating hook for %s, %d\n", __func__, STR(name), status); \
		exit(1); \
	} \
	status = MH_EnableHook(target); \
	if (status != MH_OK){ \
		LOG("%s: failed enabling hook for %s, %d\n", __func__, STR(name), status); \
		exit(1); \
	} \
	LOG("%s: hooked %s\n", __func__, STR(name)); \
}

#define REDIRECT(name, ret_type, arg, call) \
	static ret_type (*name##_orig) arg = NULL; \
	ret_type name arg { return name##_orig call; }

REDIRECT(WTInfoA, UINT WINAPI, (UINT a, UINT b, LPVOID c), (a, b, c))
REDIRECT(WTInfoW, UINT WINAPI, (UINT a, UINT b, LPVOID c), (a, b, c))
REDIRECT(WTOpenA, HANDLE WINAPI, (void *a, void *b, BOOL c), (a, b, c))
REDIRECT(WTOpenW, HANDLE WINAPI, (void *a, void *b, BOOL c), (a, b, c))
REDIRECT(WTClose, BOOL WINAPI, (HANDLE a), (a))
REDIRECT(WTPacketsGet, int WINAPI, (HANDLE a, int b, LPVOID c), (a, b, c))
REDIRECT(WTPacket, BOOL WINAPI, (HANDLE a, UINT b, LPVOID c), (a, b, c))
REDIRECT(WTEnable, BOOL WINAPI, (HANDLE a, BOOL b), (a, b))
REDIRECT(WTOverlap, BOOL WINAPI, (HANDLE a, BOOL b), (a, b))
REDIRECT(WTConfig, BOOL WINAPI, (HANDLE a, HANDLE b), (a, b))
REDIRECT(WTGetA, BOOL WINAPI, (HANDLE a, void *b), (a, b))
REDIRECT(WTGetW, BOOL WINAPI, (HANDLE a, void *b), (a, b))
REDIRECT(WTSetA, BOOL WINAPI, (HANDLE a, void *b), (a, b))
REDIRECT(WTSetW, BOOL WINAPI, (HANDLE a, void *b), (a, b))
REDIRECT(WTExtGet, BOOL WINAPI, (HANDLE a, UINT b, void *c), (a, b, c))
REDIRECT(WTExtSet, BOOL WINAPI, (HANDLE a, UINT b, void *c), (a, b, c))
REDIRECT(WTSave, BOOL WINAPI, (HANDLE a, LPVOID b), (a, b))
REDIRECT(WTRestore, HANDLE WINAPI, (HANDLE a, LPVOID b, BOOL c), (a, b, c))
REDIRECT(WTPacketsPeek, int WINAPI, (HANDLE a, int b, LPVOID c), (a, b, c))
REDIRECT(WTDataGet, int WINAPI, (HANDLE a, UINT b, UINT c, int d, LPVOID e, LPINT f), (a, b, c, d, e, f))
REDIRECT(WTDataPeek, int WINAPI, (HANDLE a, UINT b, UINT c, int d, LPVOID e, LPINT f), (a, b, c, d, e, f))
REDIRECT(WTQueueSizeGet, int WINAPI, (HANDLE a), (a))
REDIRECT(WTQueueSizeSet, BOOL WINAPI, (HANDLE a, int b), (a, b))
REDIRECT(WTMgrOpen, HANDLE WINAPI, (HANDLE a, UINT b), (a, b))
REDIRECT(WTMgrClose, BOOL WINAPI, (HANDLE a), (a))
REDIRECT(WTMgrContextEnum, BOOL WINAPI, (HANDLE a, void *b, void *c), (a, b, c))
REDIRECT(WTMgrContextOwner, HANDLE WINAPI, (HANDLE a, HANDLE b), (a, b))
REDIRECT(WTMgrDefContext, HANDLE WINAPI, (HANDLE a, BOOL b), (a, b))
REDIRECT(WTMgrDefContextEx, HANDLE WINAPI, (HANDLE a, UINT b, BOOL c), (a, b, c))
REDIRECT(WTMgrDeviceConfig, UINT WINAPI, (HANDLE a, UINT b, HANDLE c), (a, b, c))
REDIRECT(WTMgrExt, BOOL WINAPI, (HANDLE a, UINT b, LPVOID c), (a, b, c))
REDIRECT(WTMgrCsrEnable, BOOL WINAPI, (HANDLE a, UINT b, BOOL c), (a, b, c))
REDIRECT(WTMgrCsrButtonMap, BOOL WINAPI, (HANDLE a, UINT b, void *c, void *d), (a, b, c, d))
REDIRECT(WTMgrCsrPressureBtnMarks, BOOL WINAPI, (HANDLE a, UINT b, DWORD c, DWORD d), (a, b, c, d))
REDIRECT(WTMgrCsrPressureResponse, BOOL WINAPI, (HANDLE a, UINT b, void *c, void *d), (a, b, c, d))
REDIRECT(WTMgrCsrExt, BOOL WINAPI, (HANDLE a, UINT b, UINT c, LPVOID d), (a, b, c, d))
REDIRECT(WTQueuePacketsEx, BOOL WINAPI, (HANDLE a, void *b, void *c), (a, b, c))
REDIRECT(WTMgrConfigReplaceExA, BOOL WINAPI, (HANDLE a, BOOL b, void *c, void *d), (a, b, c, d))
REDIRECT(WTMgrConfigReplaceExW, BOOL WINAPI, (HANDLE a, BOOL b, void *c, void *d), (a, b, c, d))
REDIRECT(WTMgrPacketHookExA, HANDLE WINAPI, (HANDLE a, int b, void *c, void *d), (a, b, c, d))
REDIRECT(WTMgrPacketHookExW, HANDLE WINAPI, (HANDLE a, int b, void *c, void *d), (a, b, c, d))
REDIRECT(WTMgrPacketUnhook, BOOL WINAPI, (HANDLE a), (a))
REDIRECT(WTMgrPacketHookNext, void * WINAPI, (HANDLE a, int b, WPARAM c, void *d), (a, b, c, d))
REDIRECT(WTMgrCsrPressureBtnMarksEx, BOOL WINAPI, (HANDLE a, UINT b, void *c, void *d), (a, b, c, d))


#define FETCH_REDIRECT_WIN(module, name) { \
	char win_dir[1024] = {0}; \
	GetWindowsDirectoryA(win_dir, sizeof(win_dir)); \
	char lib_path[1024] = {0}; \
	sprintf(lib_path, "%s\\system32\\%s", win_dir, module); \
	HANDLE lib_handle = LoadLibraryA(lib_path); \
	if (lib_handle == NULL) { \
		LOG("%s: failed loading %s, 0x%x\n", __func__, lib_path, GetLastError()); \
		sprintf(lib_path, "%s\\syswow64\\%s", win_dir, module); \
		lib_handle = LoadLibraryA(lib_path); \
	} \
	if (lib_handle == NULL){ \
		LOG("%s: failed fetching handle of %s for %s, 0x%x\n", __func__, module, STR(name), GetLastError()); \
		exit(1); \
	} \
	name##_orig = (void *)GetProcAddress(lib_handle, STR(name)); \
	if (name##_orig == NULL){ \
		LOG("%s: failed fetching %s from %s\n", __func__, STR(name), module); \
		exit(1); \
	} \
	LOG("%s: fetched %s from %s\n", __func__, STR(name), lib_path); \
}

void load_wintab_redirects(){
	FETCH_REDIRECT_WIN("wintab32.dll", WTInfoA);
	FETCH_REDIRECT_WIN("wintab32.dll", WTOpenA);
	FETCH_REDIRECT_WIN("wintab32.dll", WTClose);
	FETCH_REDIRECT_WIN("wintab32.dll", WTPacketsGet);
	FETCH_REDIRECT_WIN("wintab32.dll", WTPacket);
	FETCH_REDIRECT_WIN("wintab32.dll", WTEnable);
	FETCH_REDIRECT_WIN("wintab32.dll", WTOverlap);
	FETCH_REDIRECT_WIN("wintab32.dll", WTConfig);
	FETCH_REDIRECT_WIN("wintab32.dll", WTGetA);
	FETCH_REDIRECT_WIN("wintab32.dll", WTSetA);
	FETCH_REDIRECT_WIN("wintab32.dll", WTExtGet);
	FETCH_REDIRECT_WIN("wintab32.dll", WTExtSet);
	FETCH_REDIRECT_WIN("wintab32.dll", WTSave);
	FETCH_REDIRECT_WIN("wintab32.dll", WTRestore);
	FETCH_REDIRECT_WIN("wintab32.dll", WTPacketsPeek);
	FETCH_REDIRECT_WIN("wintab32.dll", WTDataGet);
	FETCH_REDIRECT_WIN("wintab32.dll", WTDataPeek);
	FETCH_REDIRECT_WIN("wintab32.dll", WTQueueSizeGet);
	FETCH_REDIRECT_WIN("wintab32.dll", WTQueueSizeSet);
	FETCH_REDIRECT_WIN("wintab32.dll", WTMgrOpen);
	FETCH_REDIRECT_WIN("wintab32.dll", WTMgrClose);
	FETCH_REDIRECT_WIN("wintab32.dll", WTMgrContextEnum);
	FETCH_REDIRECT_WIN("wintab32.dll", WTMgrContextOwner);
	FETCH_REDIRECT_WIN("wintab32.dll", WTMgrDefContext);
	FETCH_REDIRECT_WIN("wintab32.dll", WTMgrDeviceConfig);
	FETCH_REDIRECT_WIN("wintab32.dll", WTMgrExt);
	FETCH_REDIRECT_WIN("wintab32.dll", WTMgrCsrEnable);
	FETCH_REDIRECT_WIN("wintab32.dll", WTMgrCsrButtonMap);
	FETCH_REDIRECT_WIN("wintab32.dll", WTMgrCsrPressureBtnMarks);
	FETCH_REDIRECT_WIN("wintab32.dll", WTMgrCsrPressureResponse);
	FETCH_REDIRECT_WIN("wintab32.dll", WTMgrCsrExt);
	FETCH_REDIRECT_WIN("wintab32.dll", WTQueuePacketsEx);
	FETCH_REDIRECT_WIN("wintab32.dll", WTMgrCsrPressureBtnMarksEx);
	FETCH_REDIRECT_WIN("wintab32.dll", WTMgrConfigReplaceExA);
	FETCH_REDIRECT_WIN("wintab32.dll", WTMgrPacketHookExA);
	FETCH_REDIRECT_WIN("wintab32.dll", WTMgrPacketUnhook);
	FETCH_REDIRECT_WIN("wintab32.dll", WTMgrPacketHookNext);
	FETCH_REDIRECT_WIN("wintab32.dll", WTMgrDefContextEx);
	FETCH_REDIRECT_WIN("wintab32.dll", WTInfoW);
	FETCH_REDIRECT_WIN("wintab32.dll", WTOpenW);
	FETCH_REDIRECT_WIN("wintab32.dll", WTGetW);
	FETCH_REDIRECT_WIN("wintab32.dll", WTSetW);
	FETCH_REDIRECT_WIN("wintab32.dll", WTMgrConfigReplaceExW);
	FETCH_REDIRECT_WIN("wintab32.dll", WTMgrPacketHookExW);
}

void init_minhook(){
	int status = MH_Initialize();
	if (status != MH_ERROR_ALREADY_INITIALIZED && status != MH_OK){
		LOG("%s: failed initializing minhook, %d\n", __func__, status);
		exit(1);
	}

	LOG("%s: minhook initialized\n", __func__);
}

static NTSTATUS NTAPI (*NtSetInformationFile_orig)(HANDLE hFile,PIO_STATUS_BLOCK io,PVOID ptr,ULONG len,FILE_INFORMATION_CLASS FileInformationClass) = NULL;
NTSTATUS NTAPI NtSetInformationFile_hooked(HANDLE hFile,PIO_STATUS_BLOCK io,PVOID ptr,ULONG len,FILE_INFORMATION_CLASS FileInformationClass){
	FILE_RENAME_INFORMATION *rename_info_orig = ptr;

	if (
		hFile == NULL ||
		FileInformationClass != FileRenameInformation ||
		rename_info_orig->RootDirectory != NULL ||
		rename_info_orig->FileName[0] == '\\'
	){
		return NtSetInformationFile_orig(hFile, io, ptr, len, FileInformationClass);
	}

	wchar_t from_path[1024] = {0};
	wchar_t to_path[1024] = {0};
	memcpy(to_path, rename_info_orig->FileName, rename_info_orig->FileNameLength);

	GetFinalPathNameByHandleW(hFile, from_path, ARRAY_SIZE(from_path), VOLUME_NAME_DOS);
	LOG("%s: moving %ls to %ls\n", __func__, from_path, to_path);

	int final_slash_offset = 0;
	for(int i = 0;i < wcslen(from_path);i++){
		if (from_path[i] == '\\'){
			final_slash_offset = i;
		}
	}
	static const int trim = 0;
	memset(to_path, 0, sizeof(to_path));
	memcpy(to_path, &from_path[trim], (final_slash_offset + 1 - trim) * 2);
	memcpy(&to_path[final_slash_offset + 1 - trim], rename_info_orig->FileName, rename_info_orig->FileNameLength);

	UNICODE_STRING nt_name;
	BOOL nt_pathname_resolve_status = RtlDosPathNameToNtPathName_U(to_path, &nt_name, NULL, NULL);
	if (!nt_pathname_resolve_status){
		LOG("%s: RtlDosPathNameToNtPathName_U of %ls failed\n", __func__, to_path);
	}else{
		memset(to_path, 0, sizeof(to_path));
		memcpy(to_path, nt_name.Buffer, nt_name.Length);
	}
	RtlFreeUnicodeString(&nt_name);

	char rename_info_new_buffer[sizeof(FILE_RENAME_INFORMATION) + sizeof(to_path)] = {0};
	FILE_RENAME_INFORMATION *rename_info_new = (void *)rename_info_new_buffer;
	memcpy(rename_info_new, rename_info_orig, sizeof(FILE_RENAME_INFORMATION));
	rename_info_new->FileNameLength = wcslen(to_path) * 2;
	memcpy(rename_info_new->FileName, to_path, sizeof(to_path));

	LOG("%s: new moving destination %ls\n", __func__, rename_info_new->FileName);

	NTSTATUS status =  NtSetInformationFile_orig(hFile, io, rename_info_new, sizeof(rename_info_new_buffer), FileInformationClass);
	LOG("%s: returing 0x%x\n", __func__, status);

	//asm("int $3");

	return status;
}

BOOL WINAPI (*MoveFileExW_orig)(const WCHAR *source, const WCHAR *dest, DWORD flag) = NULL;
BOOL WINAPI MoveFileExW_hooked(const WCHAR *source, const WCHAR *dest, DWORD flag){
	LOG("%s: moving %ls to %ls with flag 0x%x\n", __func__, source, dest, flag);
	return MoveFileExW_orig(source, dest, flag);
}

void hook_rename(){
	HOOK_API(L"ntdll", NtSetInformationFile);
	//HOOK_API(L"kernel32.dll", MoveFileExW);
}

__attribute__((constructor))
int init(){
	INIT_LOG();

	load_wintab_redirects();
	init_minhook();
	hook_rename();

	LOG("%s: ready\n", __func__);
	
	return 0;
}
