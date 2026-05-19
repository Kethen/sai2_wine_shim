#include <sysinfoapi.h>
#include <libloaderapi.h>
#include <errhandlingapi.h>
#include <guiddef.h>
#include <winerror.h>
#include <winternl.h>

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

#if 0
static long int (*UuidCreate_orig)(GUID *uuid);
#endif

long int UuidCreate(GUID *uuid){
	#if 0
	return UuidCreate_orig(Uuid);
	#endif

	FILE *random_dev = fopen("/dev/random", "rb");
	if (random_dev == NULL){
		LOG("%s: failed opening /dev/random, 0x%x\n", __func__, GetLastError());
		exit(1);
	}

	int count = fread(uuid, sizeof(GUID), 1, random_dev);
	if (count != 1){
		LOG("%s: failed reading from random dev, 0x%x\n", __func__, GetLastError());
		exit(1);
	}

	fclose(random_dev);
	
	return ERROR_SUCCESS;
}

void self_test(){
	GUID test_uuid = {0};
	UuidCreate(&test_uuid);
	LOG("%s: generated uuid: ", __func__);
	for(int i = 0;i < sizeof(test_uuid);i++){
		LOG("%02x", (uint32_t)((uint8_t*)&test_uuid)[i]);
	}
	LOG("\n");
}

void init_minhook(){
	int status = MH_Initialize();
	if (status != MH_ERROR_ALREADY_INITIALIZED && status != MH_OK){
		LOG("%s: failed initializing minhook, %d\n", __func__, status);
		exit(1);
	}

	LOG("%s: minhook initialized\n", __func__);
}

NTSTATUS NTAPI (*NtSetInformationFile_orig)(HANDLE hFile,PIO_STATUS_BLOCK io,PVOID ptr,ULONG len,FILE_INFORMATION_CLASS FileInformationClass) = NULL;
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

	GetFinalPathNameByHandleW(hFile, from_path, ARRAY_SIZE(from_path), VOLUME_NAME_NT);
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

	char rename_info_new_buffer[sizeof(FILE_RENAME_INFORMATION) + sizeof(to_path)] = {0};
	FILE_RENAME_INFORMATION *rename_info_new = (void *)rename_info_new_buffer;
	memcpy(rename_info_new, rename_info_orig, sizeof(FILE_RENAME_INFORMATION));
	rename_info_new->FileNameLength = wcslen(to_path) * 2;
	memcpy(rename_info_new->FileName, to_path, sizeof(to_path));

	LOG("%s: new moving destination %ls\n", __func__, rename_info_new->FileName);

	NTSTATUS status =  NtSetInformationFile_orig(hFile, io, rename_info_new, sizeof(rename_info_new_buffer), FileInformationClass);
	LOG("%s: returing 0x%x\n", __func__, status);
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

	#if 0
	const char lib_name[] = "rpcrt4.dll";
	char win_dir[1024] = {0};
	GetWindowsDirectoryA(win_dir, sizeof(win_dir));
	char lib_path[1024] = {0};
	sprintf(lib_path, "%s\\system32\\%s", win_dir, lib_name);
	HANDLE lib_handle = LoadLibraryA(lib_path);
	if (lib_handle == NULL){
		LOG("%s: failed loading %s, 0x%x\n", __func__, lib_path, GetLastError());
		sprintf(lib_path, "%s\\syswow64\\%s", win_dir, lib_name);
		lib_handle = LoadLibraryA(lib_path);
	}
	if (lib_handle == NULL){
		LOG("%s: failed loading %s, 0x%x\n", __func__, lib_path, GetLastError());
		exit(1);
	}

	UuidCreate_orig = (void *)GetProcAddress(lib_handle, "UuidCreate");
	#endif

	self_test();
	init_minhook();
	hook_rename();

	LOG("%s: ready\n", __func__);
	
	return 0;
}
