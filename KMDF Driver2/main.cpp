#pragma warning (disable : 4100 4047 4024 4022)
#include "main.h"

//sc create testDriver type= kernel binpath="C:\Users\Fabrício\source\repos\KMDF Driver2\x64\Release\KMDFDriver2.sys"
//bcdedit /set testsigning on
//sc start testDriver
//sc stop testDriver
//sc delete testDriver

GdiSelectBrush_t GdiSelectBrush = NULL;
PatBlt_t NtGdiPatBlt = NULL;
NtUserGetDC_t NtUserGetDC = NULL;
NtGdiCreateSolidBrush_t NtGdiCreateSolidBrush = NULL;

INT FrameRect(HDC hdc, CONST RECT* lprc, HBRUSH hbr, int thickness) {
	HBRUSH oldbrush;
	RECT r = *lprc;

	if (!(oldbrush = (HBRUSH)GdiSelectBrush(hdc, hbr))) return 0;

	NtGdiPatBlt(hdc, r.left, r.top, thickness, r.bottom - r.top, PATCOPY);
	NtGdiPatBlt(hdc, r.right - thickness, r.top, thickness, r.bottom - r.top, PATCOPY);
	NtGdiPatBlt(hdc, r.left, r.top, r.right - r.left, thickness, PATCOPY);
	NtGdiPatBlt(hdc, r.left, r.bottom - thickness, r.right - r.left, thickness, PATCOPY);

	GdiSelectBrush(hdc, oldbrush);
	return TRUE;
}


PVOID GetSystemModuleBase(const char* moduleName) {
	ULONG bytes = 0;
	NTSTATUS status = ZwQuerySystemInformation(SystemModuleInformation, 0, bytes, &bytes);

	if (!bytes) {
		DbgPrintEx(0, 0, "bytes null");
		return NULL;
	}

	PRTL_PROCESS_MODULES modules = (PRTL_PROCESS_MODULES)ExAllocatePoolWithTag(NonPagedPool, bytes, 0x4e554c4c);

	if (!modules) {
		DbgPrintEx(0, 0, "modules length equals to 0");
		return NULL;
	}

	status = ZwQuerySystemInformation(SystemModuleInformation, modules, bytes, &bytes);

	if (!NT_SUCCESS(status)) {
		DbgPrintEx(0, 0, "status null");
		return NULL;
	}

	PRTL_PROCESS_MODULE_INFORMATION module = modules->Modules;
	PVOID moduleBase = 0;
	ULONG moduleSize = 0;

	for (ULONG i = 0; i < modules->NumberOfModules; i++) {
		if (strcmp((char *)module[i].FullPathName, moduleName) == NULL) {
			moduleBase = module[i].ImageBase;
			moduleSize = module[i].ImageSize;
			break;
		}
	}

	if (modules) {
		ExFreePoolWithTag(modules, NULL);
	}

	if (moduleBase <= NULL) {
		DbgPrintEx(0, 0, "module base null");
		return NULL;
	}

	return moduleBase;
}

PVOID GetSystemModuleExportByModuleBase(const char* moduleName, const char* routineName) {
	PVOID lpModule = GetSystemModuleBase(moduleName);

	if (!lpModule) {
		return NULL;
	}

	return (PVOID)RtlFindExportedRoutineByName(lpModule, routineName);
}


PVOID GetSystemRoutineAddress(PCWSTR routineName) {
	__try {
		UNICODE_STRING name;
		RtlInitUnicodeString(&name, routineName);
		return MmGetSystemRoutineAddress(&name);
	}
	__except (EXCEPTION_EXECUTE_HANDLER) {
		NTSTATUS status = GetExceptionCode();
		DbgPrintEx(0, 0, "Catch: get sytem routine address failed with code 0x%x", status);
		return NULL;
	}
}

PVOID GetSystemModuleExportByRoutineAddress(LPCWSTR moduleName, LPCSTR routineName) {
	__try {
		PLIST_ENTRY moduleList = reinterpret_cast<PLIST_ENTRY>(GetSystemRoutineAddress(L"PsLoadedModuleList"));

		if (!moduleList) {
			DbgPrintEx(0, 0, "module list not found");
			return NULL;
		}

		for (PLIST_ENTRY link = moduleList->Flink; link != moduleList; link = link->Flink) {
			PKLDR_DATA_TABLE_ENTRY entry = CONTAINING_RECORD(link, KLDR_DATA_TABLE_ENTRY, InLoadOrderLinks);

			UNICODE_STRING name;
			RtlInitUnicodeString(&name, moduleName);

			if (RtlCompareUnicodeString(&entry->FullDllName, &name, TRUE) == 0) {
				if (!MmIsAddressValid(entry->DllBase)) {
					DbgPrintEx(0, 0, "Address %p cannot be accessed", entry->DllBase);
					return NULL;
				}

				PVOID address = (entry->DllBase) ? (PVOID)RtlFindExportedRoutineByName((entry->DllBase), routineName) : NULL;

				DbgPrintEx(0, 0, "Kernel function module base address %p", entry->DllBase);
				DbgPrintEx(0, 0, "Kernel function address %p", address);

				return address;
			}
		}

		return NULL;
	}
	__except (EXCEPTION_EXECUTE_HANDLER) {
		NTSTATUS status = GetExceptionCode();
		DbgPrintEx(0, 0, "Catch: get sytem module export by routine address failed with code 0x%x", status);
		return NULL;
	}
}

NTSTATUS WriteMemory(void* address, void* buffer, size_t size) {
	__try {
		if (!RtlCopyMemory(address, buffer, size)) {
			return STATUS_UNSUCCESSFUL;
		} else {
			return STATUS_SUCCESS;
		}
	}
	__except (EXCEPTION_EXECUTE_HANDLER) {
		NTSTATUS status = GetExceptionCode();
		DbgPrintEx(0, 0, "Catch: write memory failed with code 0x%x", status);
		return STATUS_UNSUCCESSFUL;
	}
}

NTSTATUS WriteToReadOnlyMemory(void* address, void* buffer, ULONG size) {
	__try {
		if (!MmIsAddressValid(address)) {
			DbgPrintEx(0, 0, "Address %p cannot be accessed", address);
			return STATUS_ACCESS_VIOLATION;
		}

		PMDL Mdl = IoAllocateMdl(address, size, FALSE, FALSE, NULL);

		if (!Mdl) {
			DbgPrintEx(0, 0, "Cannot allocated mdl");
			return STATUS_UNSUCCESSFUL;
		}

		MmProbeAndLockPages(Mdl, KernelMode, IoReadAccess);
		PVOID mapping = MmMapLockedPagesSpecifyCache(Mdl, KernelMode, MmNonCached, NULL, FALSE, NormalPagePriority);
		MmProtectMdlSystemAddress(Mdl, PAGE_READWRITE);

		if (!mapping) {
			DbgPrintEx(0, 0, "mapping failed");
			return STATUS_UNSUCCESSFUL;
		}

		DbgPrintEx(0, 0, "mapping address %p", mapping);

		
		if (!NT_SUCCESS(WriteMemory(mapping, buffer, size))) {
			DbgPrintEx(0, 0, "Write to memory failed");
			return STATUS_UNSUCCESSFUL;
		}

		MmUnmapLockedPages(mapping, Mdl);
		MmUnlockPages(Mdl);
		IoFreeMdl(Mdl);

		return STATUS_SUCCESS;
	}
	__except (EXCEPTION_EXECUTE_HANDLER) {
		NTSTATUS status = GetExceptionCode();
		DbgPrintEx(0, 0, "Catch: write to read only memory failed with code 0x%x", status);
		return STATUS_UNSUCCESSFUL;
	}
}

NTSTATUS CallKernelFunction(void* kernelFunctionAddress) {
	PVOID* function = (PVOID*)(GetSystemModuleExportByRoutineAddress(L"\\SystemRoot\\System32\\drivers\\dxgkrnl.sys", "NtQueryCompositionSurfaceStatistics"));

	return STATUS_UNSUCCESSFUL;

	__try {
		if (!kernelFunctionAddress) {
			return STATUS_UNSUCCESSFUL;
		}

		DbgPrintEx(0, 0, "Hook address %p", kernelFunctionAddress);

		//PVOID* function = (PVOID *)(GetSystemModuleExportByRoutineAddress(L"\\SystemRoot\\System32\\drivers\\dxgkrnl.sys", "NtDxgkGetTrackedWorkloadStatistics"));
		PVOID* function = (PVOID*)(GetSystemModuleExportByRoutineAddress(L"\\SystemRoot\\System32\\drivers\\dxgkrnl.sys", "NtQueryCompositionSurfaceStatistics"));

		if (!function) {
			DbgPrintEx(0, 0, "function address not found");
			return STATUS_UNSUCCESSFUL;
		}

		BYTE orig[] = { 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00 };

		BYTE shellCode[] = { 0x48, 0xB8 };
		BYTE shellCodeEnd[] = { 0xFF, 0xE0 };

		RtlSecureZeroMemory(&orig, sizeof(orig));
		memcpy((PVOID)((ULONG_PTR)orig), &shellCode, sizeof(shellCode));
		uintptr_t hookAddress = (uintptr_t)kernelFunctionAddress;
		memcpy((PVOID)((ULONG_PTR)orig + sizeof(shellCode)), &hookAddress, sizeof(void*));
		memcpy((PVOID)((ULONG_PTR)orig + sizeof(shellCode) + sizeof(void*)), &shellCodeEnd, sizeof(shellCodeEnd));

		if (!NT_SUCCESS(WriteToReadOnlyMemory(function, &orig, sizeof(orig)))) {
			DbgPrintEx(0, 0, "Write to read only memory failed");
			return STATUS_UNSUCCESSFUL;
		}

		//GdiSelectBrush = (GdiSelectBrush_t)(GetSystemModuleExportByRoutineAddress(L"\\SystemRoot\\System32\\win32kfull.sys", "NtGdiSelectBrush"));
		//DbgPrintEx(0, 0, "GdiSelectBrush address %p", GdiSelectBrush);

		//NtGdiPatBlt = (PatBlt_t)(GetSystemModuleExportByRoutineAddress(L"\\SystemRoot\\System32\\win32kfull.sys", "NtGdiPatBlt"));
		//DbgPrintEx(0, 0, "NtGdiPatBlt address %p", NtGdiPatBlt);

		//NtUserGetDC = (NtUserGetDC_t)(GetSystemModuleExportByRoutineAddress(L"\\SystemRoot\\System32\\win32kbase.sys", "NtUserGetDC"));
		//DbgPrintEx(0, 0, "NtUserGetDC address %p", NtUserGetDC);

		//NtGdiCreateSolidBrush = (NtGdiCreateSolidBrush_t)(GetSystemModuleExportByRoutineAddress(L"\\SystemRoot\\System32\\win32kfull.sys", "NtGdiCreateSolidBrush"));
		//DbgPrintEx(0, 0, "NtGdiCreateSolidBrush address %p", NtGdiCreateSolidBrush);

		return STATUS_SUCCESS;
	}
	__except (EXCEPTION_EXECUTE_HANDLER) {
		NTSTATUS status = GetExceptionCode();
		DbgPrintEx(0, 0, "Catch: write hook to kernel function failed with code 0x%x", status);
		return STATUS_UNSUCCESSFUL;
	}
}

NTSTATUS HookHandler(PVOID calledProgram) {
	DbgPrintEx(0, 0, "Hooked");

	__try {
		HDC hdc = NtUserGetDC(NULL);

		if (!hdc) {
			DbgPrintEx(0, 0, "Create hdc ");
			return STATUS_UNSUCCESSFUL;
		}

		HBRUSH brush = NtGdiCreateSolidBrush(RGB(250, 0, 0), NULL);

		if (!brush) {
			return STATUS_UNSUCCESSFUL;
		}

		return STATUS_UNSUCCESSFUL;

		RECT rect = { 50, 50, 100, 100 };

		FrameRect(hdc, &rect, brush, 2);

		return STATUS_SUCCESS;
	}
	__except (EXCEPTION_EXECUTE_HANDLER) {
		NTSTATUS status = GetExceptionCode();
		DbgPrintEx(0, 0, "Catch: create rect failed with code 0x%x", status);
		return STATUS_UNSUCCESSFUL;
	}
}

extern "C" NTSTATUS DriverEntry(PDRIVER_OBJECT pDriverObject, PUNICODE_STRING pRegistryPath) {
	pDriverObject->DriverUnload = (PDRIVER_UNLOAD)UnloadDriver;

	DbgPrintEx(0, 0, "Load Driver");

	if (!NT_SUCCESS(CallKernelFunction(&HookHandler))) {
		DbgPrintEx(0, 0, "Write hook failed");
	}

	return STATUS_SUCCESS;
}

NTSTATUS UnloadDriver(PDRIVER_OBJECT pDriverObject) {
	DbgPrintEx(0, 0, "Unload Driver");

	return STATUS_SUCCESS;
}
