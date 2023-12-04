#pragma once
#include <ntdef.h>
#include <ntifs.h>
#include <ntddk.h>
#include <windef.h>
#include <ntstrsafe.h>
#include <ntstatus.h>
#include <wdm.h>
#include <wingdi.h>
#pragma comment(lib, "ntoskrnl.lib")

typedef enum _SYSTEM_INFORMATION_CLASS {
	SystemBasicInformation,
	SystemProcessorInformation,
	SystemPerformanceInformation,
	SystemTimeOfDayInformation,
	SystemPathInformation,
	SystemProcessInformation,
	SystemCallCountInformation,
	SystemDeviceInformation,
	SystemProcessorPerformanceInformation,
	SystemFlagsInformation,
	SystemCallTimeInformation,
	SystemModuleInformation = 0x0B
} SYSTEM_INFORMATION_CLASS, * PSYSTEM_INFORMATION_CLASS;

typedef struct _RTL_PROCESS_MODULE_INFORMATION {
	HANDLE Section;
	PVOID MappedBase;
	PVOID ImageBase;
	ULONG ImageSize;
	ULONG Flags;
	USHORT LoadOrderIndex;
	USHORT InitOrderIndex;
	USHORT LoadCount;
	USHORT OffsetToFileName;
	UCHAR FullPathName[256];
} RTL_PROCESS_MODULE_INFORMATION, * PRTL_PROCESS_MODULE_INFORMATION;

typedef struct _RTL_PROCESS_MODULES {
	ULONG NumberOfModules;
	RTL_PROCESS_MODULE_INFORMATION Modules[1];
} RTL_PROCESS_MODULES, * PRTL_PROCESS_MODULES;

typedef struct _NON_PAGED_DEBUG_INFO{
	USHORT      Signature;
	USHORT      Flags;
	ULONG       Size;
	USHORT      Machine;
	USHORT      Characteristics;
	ULONG       TimeDateStamp;
	ULONG       CheckSum;
	ULONG       SizeOfImage;
	ULONGLONG   ImageBase;
} NON_PAGED_DEBUG_INFO, * PNON_PAGED_DEBUG_INFO;

typedef struct _KLDR_DATA_TABLE_ENTRY{
	LIST_ENTRY InLoadOrderLinks;
	PVOID ExceptionTable;
	ULONG ExceptionTableSize;
	// ULONG padding on IA64
	PVOID GpValue;
	PNON_PAGED_DEBUG_INFO NonPagedDebugInfo;
	PVOID DllBase;
	PVOID EntryPoint;
	ULONG SizeOfImage;
	UNICODE_STRING FullDllName;
	UNICODE_STRING BaseDllName;
	ULONG Flags;
	USHORT LoadCount;
	USHORT __Unused5;
	PVOID SectionPointer;
	ULONG CheckSum;
	// ULONG padding on IA64
	PVOID LoadedImports;
	PVOID PatchInformation;
} KLDR_DATA_TABLE_ENTRY, * PKLDR_DATA_TABLE_ENTRY;

typedef HBRUSH(*GdiSelectBrush_t)(_In_ HDC hdc, _In_ HBRUSH hbr);
typedef BOOL(*PatBlt_t)(_In_ HDC, _In_ int x, _In_ int y, _In_ int w, _In_ int h, _In_ DWORD);
typedef HDC(*NtUserGetDC_t)(HWND hWnd);
typedef HBRUSH(*NtGdiCreateSolidBrush_t)(_In_ COLORREF crColor, _In_opt_ HBRUSH hbr);

extern "C" NTSTATUS DriverEntry(PDRIVER_OBJECT pDriverObject, PUNICODE_STRING pRegistryPath);
NTSTATUS UnloadDriver(PDRIVER_OBJECT pDriverObject);

extern "C" NTSTATUS NTAPI ZwProtectVirtualMemory(HANDLE ProcessHandle, PVOID* BaseAddress, PULONG ProtectSize, ULONG NewProtect, PULONG OldProtect);
extern "C" PVOID NTAPI RtlFindExportedRoutineByName(_In_ PVOID ImageBase, _In_ PCCH RoutineNam);
extern "C" NTSTATUS NTAPI ZwQuerySystemInformation(ULONG InfoClass, PVOID Buffer, ULONG Length, PULONG ReturnLength);

PPEB PsGetProcessPeb(IN PEPROCESS Process);

NTSTATUS NTAPI MmCopyVirtualMemory(PEPROCESS SourceProcess, PVOID SourceAddress, PEPROCESS TargetProcess, PVOID TargetAddress, SIZE_T BufferSize, KPROCESSOR_MODE PreviousMode, PSIZE_T ReturnSize);

PVOID GetSystemModuleBase(const char * moduleName);
PVOID GetSystemModuleExportByRoutineAddress(LPCWSTR moduleName, LPCSTR routineName);
PVOID GetSystemModuleExportByModuleBase(const char* moduleName, const char* routineName);
PVOID GetSystemRoutineAddress(PCWSTR routineName);
NTSTATUS WriteMemory(void * address, void * buffer, size_t size);
NTSTATUS WriteToReadOnlyMemory(void* address, void* buffer, ULONG size);

NTSTATUS CallKernelFunction(void * kernelFunctionAddress);
NTSTATUS HookHandler(PVOID calledProgram);

INT FrameRect(HDC hdc, CONST RECT* lprc, HBRUSH hbr, int thickness);