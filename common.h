#pragma once

#define MAX_SYSCALLS 1000

typedef struct FILE_POSITION_INFORMATION {
    LARGE_INTEGER  CurrentByteOffset;
} FILE_POSITION_INFORMATION, * PFILE_POSITION_INFORMATION;


typedef struct FILE_STANDARD_INFORMATION {
    LARGE_INTEGER  AllocationSize;
    LARGE_INTEGER  EndOfFile;
    ULONG  NumberOfLinks;
    BOOLEAN  DeletePending;
    BOOLEAN  Directory;
} FILE_STANDARD_INFORMATION, * PFILE_STANDARD_INFORMATION;

typedef struct _FILE_DISPOSITION_INFORMATION {
    BOOLEAN  DeleteFile;
} FILE_DISPOSITION_INFORMATION;

typedef struct _SYSCALL {
    PVOID addr;
    PCHAR name;
    DWORD hash;
} SYSCALL, PSYSCALL;

typedef struct _LIST_SYSCALL {
    DWORD dwNbSyscall;
    SYSCALL f[MAX_SYSCALLS];
} LIST_SYSCALL, PLIST_SYSCALL;

typedef NTSTATUS syscallCreateFile(PHANDLE FileHandle, ACCESS_MASK DesiredAccess, POBJECT_ATTRIBUTES ObjectAttributes, PIO_STATUS_BLOCK IoStatusBlock, PLARGE_INTEGER AllocationSize, ULONG FileAttributes, ULONG ShareAccess, ULONG CreateDisposition, ULONG CreateOptions, PVOID EaBuffer, ULONG EaLength);
typedef NTSTATUS syscallCloseHandle(HANDLE Handle);
typedef NTSTATUS syscallWriteFile(HANDLE FileHandle, HANDLE Event, PIO_APC_ROUTINE ApcRoutine, PVOID ApcContext, PIO_STATUS_BLOCK IoStatusBlock, PVOID Buffer, ULONG Length, PLARGE_INTEGER ByteOffset, PULONG Key);
