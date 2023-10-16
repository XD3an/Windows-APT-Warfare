#include <stdio.h>
#include <Shlwapi.h>
#include <windows.h>
#define _CRT_SECURE_NO_WARNINGS

typedef struct _PEB_LDR_DATA
{
	ULONG Length;
	BOOLEAN Initialized;
	PVOID SsHandle;
	LIST_ENTRY InLoadOrderModuleList;
	LIST_ENTRY InMemoryOrderModuleList;
	LIST_ENTRY InInitializationOrderModuleList;
	PVOID EntryInProgress;
} PEB_LDR_DATA, * PPEB_LDR_DATA;

#ifdef _WIN64
typedef struct _UNICODE_STRING
{
	USHORT Length;
	USHORT MaximumLength;
	PWSTR Buffer;
} UNICODE_STRING, * PUNICODE_STRING;

typedef struct _PEB
{
	BOOLEAN InheritedAddressSpace;
	BOOLEAN ReadImageFileExecOptions;
	BOOLEAN BeingDebugged;
	BOOLEAN BitField;
	PVOID Mutant;
	PVOID ImageBaseAddress;
	PPEB_LDR_DATA Ldr;
	PVOID ProcessParameters;
	PVOID SubSystemData;
	PVOID ProcessHeap;
	PVOID FastPebLock;
	PVOID AtlThunkSListPtr;
	PVOID IFEOKey;
	PVOID CrossProcessFlags;
	PVOID UserSharedInfoPtr;
	ULONG SystemReserved;
	ULONG AtlThunkSListPtr32;
	PVOID ApiSetMap;
} PEB, * PPEB;

typedef struct _LDR_DATA_TABLE_ENTRY
{
	LIST_ENTRY InLoadOrderLinks;
	LIST_ENTRY InMemoryOrderLinks;
	LIST_ENTRY InInitializationOrderLinks;
	PVOID DllBase;
	PVOID EntryPoint;
	ULONG SizeOfImage;
	UNICODE_STRING FullDllName;
	UNICODE_STRING BaseDllName;
	ULONG Flags;
	USHORT LoadCount;
	USHORT TlsIndex;
	LIST_ENTRY HashLinks;
	PVOID SectionPointer;
	ULONG CheckSum;
	ULONG TimeDateStamp;
	PVOID LoadedImports;
	PVOID EntryPointActivationContext;
	PVOID PatchInformation;
} LDR_DATA_TABLE_ENTRY, * PLDR_DATA_TABLE_ENTRY;
#else 
typedef struct _UNICODE_STRING32
{
	USHORT Length;
	USHORT MaximumLength;
	PWSTR Buffer;
} UNICODE_STRING32, * PUNICODE_STRING32;

typedef struct _PEB32
{
	UCHAR InheritedAddressSpace;
	UCHAR ReadImageFileExecOptions;
	UCHAR BeingDebugged;
	UCHAR BitField;
	ULONG Mutant;
	ULONG ImageBaseAddress;
	PPEB_LDR_DATA Ldr;
	ULONG ProcessParameters;
	ULONG SubSystemData;
	ULONG ProcessHeap;
	ULONG FastPebLock;
	ULONG AtlThunkSListPtr;
	ULONG IFEOKey;
	ULONG CrossProcessFlags;
	ULONG UserSharedInfoPtr;
	ULONG SystemReserved;
	ULONG AtlThunkSListPtr32;
	ULONG ApiSetMap;
} PEB32, * PPEB32;

typedef struct _PEB_LDR_DATA32
{
	ULONG Length;
	BOOLEAN Initialized;
	ULONG SsHandle;
	LIST_ENTRY32 InLoadOrderModuleList;
	LIST_ENTRY32 InMemoryOrderModuleList;
	LIST_ENTRY32 InInitializationOrderModuleList;
	ULONG EntryInProgress;
} PEB_LDR_DATA32, * PPEB_LDR_DATA32;

typedef struct _LDR_DATA_TABLE_ENTRY32
{
	LIST_ENTRY32 InLoadOrderLinks;
	LIST_ENTRY32 InMemoryOrderLinks;
	LIST_ENTRY32 InInitializationOrderLinks;
	ULONG DllBase;
	ULONG EntryPoint;
	ULONG SizeOfImage;
	UNICODE_STRING32 FullDllName;
	UNICODE_STRING32 BaseDllName;
	ULONG Flags;
	USHORT LoadCount;
	USHORT TlsIndex;
	union
	{
		LIST_ENTRY32 HashLinks;
		ULONG SectionPointer;
	};
	ULONG CheckSum;
	union
	{
		ULONG TimeDateStamp;
		ULONG LoadedImports;
	};
	ULONG EntryPointActivationContext;
	ULONG PatchInformation;
} LDR_DATA_TABLE_ENTRY32, * PLDR_DATA_TABLE_ENTRY32;
#endif

wchar_t* StrToWstr(const char* string)
{
	int len = MultiByteToWideChar(CP_UTF8, 0, string, -1, nullptr, 0); // 取得轉換後需要的寬字元長度
	wchar_t* w_string = new wchar_t[len];						 	   // 分配記憶體給寬字元字串
	MultiByteToWideChar(CP_UTF8, 0, string, -1, w_string, len);        // 執行轉換
	return w_string;
}

size_t GetModHandle(const wchar_t* ModuleName) 
{
#ifdef _WIN64
	PEB* pPEB = (PEB*)__readgsqword(0x60);
#else
	PEB32* pPEB = (PEB32*)__readfsdword(0x30); // ds: fs[0x30]
#endif
	PLIST_ENTRY header = &(pPEB->Ldr->InMemoryOrderModuleList);

	for (PLIST_ENTRY curr = header->Flink; curr != header; curr = curr->Flink) 
	{
#ifdef _WIN64
		LDR_DATA_TABLE_ENTRY* data = CONTAINING_RECORD(
			curr, LDR_DATA_TABLE_ENTRY, InMemoryOrderLinks
		);
#else
		LDR_DATA_TABLE_ENTRY32* data = CONTAINING_RECORD(
			curr, LDR_DATA_TABLE_ENTRY32, InMemoryOrderLinks
		);
#endif
		printf("[*] Current node: %ls\n", data->BaseDllName.Buffer);
		if (StrStrIW(ModuleName, data->BaseDllName.Buffer))
			return (size_t)data->DllBase;
	}
	return 0;
}


size_t GetFuncAddr(size_t moduleBase, const char* szFuncName)
{
	// parse export table
	PIMAGE_DOS_HEADER dosHdr = (PIMAGE_DOS_HEADER)(moduleBase);
	PIMAGE_NT_HEADERS ntHdr = (PIMAGE_NT_HEADERS)(moduleBase + dosHdr->e_lfanew);
	IMAGE_OPTIONAL_HEADER optHdr = ntHdr->OptionalHeader;
	IMAGE_DATA_DIRECTORY dataDir_exportDir = optHdr.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT];

	// parse exported function info
	PIMAGE_EXPORT_DIRECTORY exportTable = (PIMAGE_EXPORT_DIRECTORY)(moduleBase + dataDir_exportDir.VirtualAddress);
	DWORD* arrFuncs = (DWORD*)(moduleBase + exportTable->AddressOfFunctions);
	DWORD* arrNames = (DWORD*)(moduleBase + exportTable->AddressOfNames);
	WORD* arrNameOrds = (WORD*)(moduleBase + exportTable->AddressOfNameOrdinals);

	// lookup
	for (size_t i = 0; i < exportTable->NumberOfNames; i++) {
		char* sz_CurrApiName = (char*)(moduleBase + arrNames[i]);
		WORD num_CurrApiOrdinal = arrNameOrds[i] + 1;
		if (!_stricmp(sz_CurrApiName, szFuncName))
		{
			printf("[+] Found ordinal %.4x - %s\n", num_CurrApiOrdinal, sz_CurrApiName);
			return moduleBase + arrFuncs[num_CurrApiOrdinal - 1];
		}
	}
	return 0;
}

int main(int argc, char** argv, char* envp)
{
	if (argc != 3)
	{
		puts("[!] Usage: .\\DynEatCall.exe [Module Name] [Function Name]");
	}
	else
	{
		size_t Base = GetModHandle(StrToWstr(argv[1]));
		if (Base)
			printf("Found Module %s @ %p\n", argv[1], (void*)Base);
		else
			printf("Module %s is not found...\n", argv[1]);

		size_t FuncAddr = GetFuncAddr(Base, argv[2]);
		if (Base && FuncAddr)
		{
			printf("Found Function %s of %s @ %p\n", argv[2], argv[1], (void*)FuncAddr);
		}
		else
			printf("Function %s is not found...\n", argv[2]);
	}
	return 0;
}