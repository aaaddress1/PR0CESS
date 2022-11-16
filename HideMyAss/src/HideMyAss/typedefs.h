#include <Windows.h>
#define _AMD64_
#include <winternl.h>

#define DEBUG_READ_EVENT 0x0001
#define DEBUG_PROCESS_ASSIGN 0x0002
#define DEBUG_SET_INFORMATION 0x0004
#define DEBUG_QUERY_INFORMATION 0x0008
#define DEBUG_ALL_ACCESS (STANDARD_RIGHTS_REQUIRED | SYNCHRONIZE | \
    DEBUG_READ_EVENT | DEBUG_PROCESS_ASSIGN | DEBUG_SET_INFORMATION | \
    DEBUG_QUERY_INFORMATION)

#define DEBUG_KILL_ON_CLOSE 0x1

typedef struct _UNI_STR {
	USHORT Length;
	USHORT MaximumLength;
	PWSTR  Buffer;
} UNI_STR, * PUNI_STR;
typedef void* LPVOID;
typedef unsigned long DWORD;
typedef unsigned __int64 QWORD;
typedef unsigned int UINT;


struct DBUTIL_READ_BUFFER {
	unsigned long long pad1 = 0x4141414141414141;
	unsigned long long Address;
	unsigned long long three1 = 0x0000000000000000;
	unsigned long long value = 0x0000000000000000;
};
struct DBUTIL_WRITE_BUFFER {
	unsigned long long pad1 = 0x4141414141414141;
	unsigned long long Address;
	unsigned long long three1 = 0x0000000000000000;
	unsigned long long Value = 0x0000000000000000;
};



struct DBUTIL23_MEMORY_WRITE {
	DWORD64 field0;
	DWORD64 Address;
	DWORD Offset;
	DWORD field14;
	BYTE Buffer[1];
};


typedef struct _PS_PROTECTION
{
	union
	{
		UINT8                   Level;
		struct
		{
			UINT8               Type : 3;
			UINT8               Audit : 1;
			UINT8               Signer : 4;
		};
	};
} PS_PROTECTION, * PPS_PROTECTION;


#define InitObjAttr(p, n, a, r, s) \
{ \
(p)->Length = sizeof(OBJECT_ATTRIBUTES); \
(p)->RootDirectory = r; \
(p)->Attributes = a; \
(p)->ObjectName = n; \
(p)->SecurityDescriptor = s; \
(p)->SecurityQualityOfService = NULL; \
}

typedef struct _HANDLE_TABLE_ENTRY_INFO
{
	ULONG AuditMask;
} HANDLE_TABLE_ENTRY_INFO, * PHANDLE_TABLE_ENTRY_INFO;


typedef struct _HANDLE_TABLE_ENTRY
{
	union
	{
		PVOID Object;
		ULONG ObAttributes;
		PHANDLE_TABLE_ENTRY_INFO InfoTable;
		ULONG Value;
	};
	union
	{
		ULONG GrantedAccess;
		struct
		{
			WORD GrantedAccessIndex;
			WORD CreatorBackTraceIndex;
		};
		LONG NextFreeTableEntry;
	};
} HANDLE_TABLE_ENTRY, * PHANDLE_TABLE_ENTRY;


typedef enum _THREAD_STATE_CHANGE_TYPE
{
	ThreadStateChangeSuspend = 0,
	ThreadStateChangeResume = 1,
	ThreadStateChangeMax = 2,
} THREAD_STATE_CHANGE_TYPE, * PTHREAD_STATE_CHANGE_TYPE;

typedef enum _PROCESS_STATE_CHANGE_TYPE
{
	ProcessStateChangeSuspend = 0,
	ProcessStateChangeResume = 1,
	ProcessStateChangeMax = 2,
} PROCESS_STATE_CHANGE_TYPE, * PPROCESS_STATE_CHANGE_TYPE;


struct _EXHANDLE
{
	union
	{
		struct
		{
			ULONG TagBits : 2;                                                //0x0
			ULONG Index : 30;                                                 //0x0
		};
		VOID* GenericHandleOverlay;                                         //0x0
		ULONGLONG Value;                                                    //0x0
	};
};


typedef union _HANDLE_TABLE_ENTRY1
{
	volatile LONGLONG VolatileLowValue;                                     //0x0
	LONGLONG LowValue;                                                      //0x0
	struct
	{
		struct _HANDLE_TABLE_ENTRY_INFO* volatile InfoTable;                //0x0
		LONGLONG HighValue;                                                     //0x8
		union _HANDLE_TABLE_ENTRY1* NextFreeHandleEntry;                         //0x8
		struct _EXHANDLE LeafHandleValue;                                   //0x8
	};
	LONGLONG RefCountField;                                                 //0x0
	ULONGLONG Unlocked : 1;                                                   //0x0
	ULONGLONG RefCnt : 16;                                                    //0x0
	ULONGLONG Attributes : 3;                                                 //0x0
	struct
	{
		ULONGLONG ObjectPointerBits : 44;                                     //0x0
		ULONG GrantedAccessBits : 25;                                             //0x8
		ULONG NoRightsUpgrade : 1;                                                //0x8
		ULONG Spare1 : 6;                                                     //0x8
	};
	ULONG Spare2;                                                           //0xc
} HANDLE_TABLE_ENTRY1, * PHANDLE_TABLE_ENTRY1;


struct _EX_PUSH_LOCK
{
	union
	{
		struct
		{
			ULONGLONG Locked : 1;                                             //0x0
			ULONGLONG Waiting : 1;                                            //0x0
			ULONGLONG Waking : 1;                                             //0x0
			ULONGLONG MultipleShared : 1;                                     //0x0
			ULONGLONG Shared : 60;                                            //0x0
		};
		ULONGLONG Value;                                                    //0x0
		VOID* Ptr;                                                          //0x0
	};
};

typedef struct _QUAD
{
	union
	{
		LONGLONG UseThisFieldToCopy;                                        //0x0
		double DoNotUseThisField;                                           //0x0
	};
}QUAD, * PQUAD;
typedef struct _OBJECT_HEADER
{
	LONGLONG PointerCount;                                                  //0x0
	union
	{
		LONGLONG HandleCount;                                               //0x8
		VOID* NextToFree;                                                   //0x8
	};
	struct _EX_PUSH_LOCK Lock;                                              //0x10
	UCHAR TypeIndex;                                                        //0x18
	union
	{
		UCHAR TraceFlags;                                                   //0x19
		struct
		{
			UCHAR DbgRefTrace : 1;                                            //0x19
			UCHAR DbgTracePermanent : 1;                                      //0x19
		};
	};
	UCHAR InfoMask;                                                         //0x1a
	union
	{
		UCHAR Flags;                                                        //0x1b
		struct
		{
			UCHAR NewObject : 1;                                              //0x1b
			UCHAR KernelObject : 1;                                           //0x1b
			UCHAR KernelOnlyAccess : 1;                                       //0x1b
			UCHAR ExclusiveObject : 1;                                        //0x1b
			UCHAR PermanentObject : 1;                                        //0x1b
			UCHAR DefaultSecurityQuota : 1;                                   //0x1b
			UCHAR SingleHandleEntry : 1;                                      //0x1b
			UCHAR DeletedInline : 1;                                          //0x1b
		};
	};
	ULONG Reserved;                                                         //0x1c
	union
	{
		struct _OBJECT_CREATE_INFORMATION* ObjectCreateInfo;                //0x20
		VOID* QuotaBlockCharged;                                            //0x20
	};
	VOID* SecurityDescriptor;                                               //0x28
	struct _QUAD Body;                                                      //0x30
} OBJECT_HEADER, * POBJECT_HEADER;

typedef struct _CLIENT_ID1
{
	PVOID UniqueProcess;
	PVOID UniqueThread;
} MY_CLIENT_ID, * PCLIENT_ID1;



typedef struct _KTRAP_FRAME
{
	ULONGLONG P1Home;                                                       //0x0
	ULONGLONG P2Home;                                                       //0x8
	ULONGLONG P3Home;                                                       //0x10
	ULONGLONG P4Home;                                                       //0x18
	ULONGLONG P5;                                                           //0x20
	CHAR PreviousMode;                                                      //0x28
	UCHAR PreviousIrql;                                                     //0x29
	UCHAR FaultIndicator;                                                   //0x2a
	UCHAR ExceptionActive;                                                  //0x2b
	ULONG MxCsr;                                                            //0x2c
	ULONGLONG Rax;                                                          //0x30
	ULONGLONG Rcx;                                                          //0x38
	ULONGLONG Rdx;                                                          //0x40
	ULONGLONG R8;                                                           //0x48
	ULONGLONG R9;                                                           //0x50
	ULONGLONG R10;                                                          //0x58
	ULONGLONG R11;                                                          //0x60
	union
	{
		ULONGLONG GsBase;                                                   //0x68
		ULONGLONG GsSwap;                                                   //0x68
	};
	struct _M128A Xmm0;                                                     //0x70
	struct _M128A Xmm1;                                                     //0x80
	struct _M128A Xmm2;                                                     //0x90
	struct _M128A Xmm3;                                                     //0xa0
	struct _M128A Xmm4;                                                     //0xb0
	struct _M128A Xmm5;                                                     //0xc0
	union
	{
		ULONGLONG FaultAddress;                                             //0xd0
		ULONGLONG ContextRecord;                                            //0xd0
		ULONGLONG TimeStampCKCL;                                            //0xd0
	};
	ULONGLONG Dr0;                                                          //0xd8
	ULONGLONG Dr1;                                                          //0xe0
	ULONGLONG Dr2;                                                          //0xe8
	ULONGLONG Dr3;                                                          //0xf0
	ULONGLONG Dr6;                                                          //0xf8
	ULONGLONG Dr7;                                                          //0x100
	union
	{
		struct
		{
			ULONGLONG DebugControl;                                         //0x108
			ULONGLONG LastBranchToRip;                                      //0x110
			ULONGLONG LastBranchFromRip;                                    //0x118
			ULONGLONG LastExceptionToRip;                                   //0x120
			ULONGLONG LastExceptionFromRip;                                 //0x128
		};
		struct
		{
			ULONGLONG LastBranchControl;                                    //0x108
			ULONG LastBranchMSR;                                            //0x110
		};
	};
	USHORT SegDs;                                                           //0x130
	USHORT SegEs;                                                           //0x132
	USHORT SegFs;                                                           //0x134
	USHORT SegGs;                                                           //0x136
	ULONGLONG TrapFrame;                                                    //0x138
	ULONGLONG Rbx;                                                          //0x140
	ULONGLONG Rdi;                                                          //0x148
	ULONGLONG Rsi;                                                          //0x150
	ULONGLONG Rbp;                                                          //0x158
	union
	{
		ULONGLONG ErrorCode;                                                //0x160
		ULONGLONG ExceptionFrame;                                           //0x160
		ULONGLONG TimeStampKlog;                                            //0x160
	};
	ULONGLONG Rip;                                                          //0x168
	USHORT SegCs;                                                           //0x170
	UCHAR Fill0;                                                            //0x172
	UCHAR Logging;                                                          //0x173
	USHORT Fill1[2];                                                        //0x174
	ULONG EFlags;                                                           //0x178
	ULONG Fill2;                                                            //0x17c
	ULONGLONG Rsp;                                                          //0x180
	USHORT SegSs;                                                           //0x188
	USHORT Fill3;                                                           //0x18a
	LONG CodePatchCycle;                                                    //0x18c
}KTRAP_FRAME, * PKTRAP_FRAME;


typedef struct _EX_FAST_REF
{
	union
	{
		PVOID Object;
		ULONG RefCnt : 3;
		ULONG Value;
	};
} EX_FAST_REF, * PEX_FAST_REF;

typedef struct _FILE_DISPOSITION_INFORMATION {
	BOOLEAN DeleteFile;
} FILE_DISPOSITION_INFORMATION, * PFILE_DISPOSITION_INFORMATION;


// ZwCreateSection
EXTERN_C NTSTATUS NTSYSAPI NTAPI NtCreateSection(
	OUT PHANDLE            SectionHandle,
	IN ULONG               DesiredAccess,
	IN POBJECT_ATTRIBUTES  ObjectAttributes OPTIONAL,
	IN PLARGE_INTEGER      MaximumSize OPTIONAL,
	IN ULONG               PageAttributess,
	IN ULONG               SectionAttributes,
	IN HANDLE              FileHandle OPTIONAL
	);

// NtMapViewOfSection syntax
EXTERN_C NTSTATUS NTSYSAPI NTAPI NtMapViewOfSection(
	IN HANDLE               SectionHandle,
	IN HANDLE               ProcessHandle,
	IN OUT PVOID* BaseAddress OPTIONAL,
	IN ULONG                ZeroBits OPTIONAL,
	IN ULONG                CommitSize,
	IN OUT PLARGE_INTEGER   SectionOffset OPTIONAL,
	IN OUT PSIZE_T           ViewSize,
	IN   DWORD                  InheritDisposition,
	IN ULONG                AllocationType OPTIONAL,
	IN ULONG                Protect
	);

// ZwCreateThreadEx
typedef NTSTATUS(NTAPI* pfnNtCreateThreadEx)
	(_Out_ PHANDLE                 ThreadHandle,
	_In_ ACCESS_MASK              DesiredAccess,
	_In_opt_ POBJECT_ATTRIBUTES   ObjectAttributes,
	_In_ HANDLE                   ProcessHandle,
	_In_ PVOID                    StartRoutine,
	_In_opt_ PVOID                Argument,
	_In_ ULONG                    CreateFlags,
	_In_opt_ ULONG_PTR            ZeroBits,
	_In_opt_ SIZE_T               StackSize,
	_In_opt_ SIZE_T               MaximumStackSize,
	_In_opt_ PVOID                AttributeList
	);

// ZwUnmapViewOfSection syntax
EXTERN_C NTSTATUS NTSYSAPI NTAPI NtUnmapViewOfSection(
	HANDLE            ProcessHandle,
	PVOID             BaseAddress
	);

EXTERN_C NTSTATUS NTSYSAPI NTAPI NtDebugActiveProcess(
	_In_ HANDLE               ProcessHandle,
	_In_ HANDLE               DebugObjectHandle);

EXTERN_C NTSTATUS NTSYSAPI NTAPI NtCreateDebugObject(
	_Out_ PHANDLE             DebugObjectHandle,
	_In_ ACCESS_MASK          DesiredAccess,
	_In_opt_ POBJECT_ATTRIBUTES   ObjectAttributes,
	_In_ BOOLEAN              KillProcessOnExit);

EXTERN_C NTSTATUS NTSYSAPI NTAPI NtRemoveProcessDebug(
	_In_ HANDLE               ProcessHandle,
	_In_ HANDLE               DebugObjectHandle);



EXTERN_C NTSTATUS NTSYSAPI NTAPI NtResumeThread(
	_In_ HANDLE     ThreadHandle,
	_Out_opt_ ULONG SuspendCount);


EXTERN_C NTSTATUS NTSYSAPI NTAPI NtCreateThreadStateChange(
	_Out_ PHANDLE StateChangeHandle,
	_In_ ACCESS_MASK DesiredAccess,
	_In_ POBJECT_ATTRIBUTES ObjectAttributes,
	_In_ HANDLE ThreadHandle,
	_In_ ULONG Unused);

EXTERN_C NTSTATUS NTSYSAPI NTAPI NtChangeThreadState(
	_In_ HANDLE ThreadStateChangeHandle,
	_In_ HANDLE ThreadHandle,
	_In_ THREAD_STATE_CHANGE_TYPE StateChangeType,
	_In_opt_ PVOID ExtendedInformation,
	_In_opt_ SIZE_T ExtendedInformationLength,
	_In_opt_ ULONG64 Reserved
	);

EXTERN_C NTSTATUS NTSYSAPI NTAPI NtSetInformationFile(
	_In_  HANDLE                 FileHandle,
	_Out_ PIO_STATUS_BLOCK       IoStatusBlock,
	_In_  PVOID                  FileInformation,
	_In_  ULONG                  Length,
	_In_  FILE_INFORMATION_CLASS FileInformationClass

);

EXTERN_C NTSTATUS NTSYSAPI NTAPI NtOpenProcess(
	_Out_          PHANDLE            ProcessHandle,
	_In_          ACCESS_MASK        DesiredAccess,
	_In_          POBJECT_ATTRIBUTES ObjectAttributes,
	_In_opt_	CLIENT_ID *        ClientId

);

