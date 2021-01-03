#include <windows.h>
#include <winternl.h>
#include <stdio.h>

#include "utils.h"
#include "common.h"

syscallCreateFile* sysCreateFile = 0;
syscallCloseHandle* sysCloseHandle = 0;
syscallWriteFile* sysWriteFile = 0;

HANDLE hstdOut = 0;

DWORD idxSysCall = 0;
LIST_SYSCALL ListSyscall;

char buf[] = "MON BUFFER DE TEST";
char szOutput[64] = { 0 };

// PARSE TABLE EXPORT DE NTDLL.DLL CHARGE EN MEMOIRE
void findSyscall() {
    PPEB_LDR_DATA pLdrData;
    PLDR_DATA_TABLE_ENTRY LdrEntry;
    PIMAGE_DOS_HEADER pDosHeader;
    PIMAGE_NT_HEADERS pNtHeaders;
    PIMAGE_DATA_DIRECTORY DataDirectory;
    PIMAGE_EXPORT_DIRECTORY pExports;
    SYSCALL scTemp;

    PDWORD pFunctions;
    PDWORD pNames;
    PWORD pOrdinals;
    PCHAR szDllName;
    PCHAR szFunctionName;

    DWORD i;
    DWORD j;
    DWORD VirtualAddress;
    
    // RECUPERATION DE L'ADRESSE DE PEB_LDR_DATA QUI CONTIENT LES INFORMATIONS DES MODULES CHARGES
    pLdrData = (PPEB_LDR_DATA)getAddrTEB()->ProcessEnvironmentBlock->Ldr;

    for (LdrEntry = (PLDR_DATA_TABLE_ENTRY)pLdrData->Reserved2[1]; LdrEntry->DllBase != 0; LdrEntry = (PLDR_DATA_TABLE_ENTRY)LdrEntry->Reserved1[0])
    {
        // ON RECUPERE LES ADRESSES DES DIFFERENTES STRUCTURES
        pDosHeader = (PIMAGE_DOS_HEADER)LdrEntry->DllBase;
        pNtHeaders = (PIMAGE_NT_HEADERS)((DWORD_PTR)LdrEntry->DllBase + pDosHeader->e_lfanew);
        DataDirectory = (PIMAGE_DATA_DIRECTORY)pNtHeaders->OptionalHeader.DataDirectory;

        // ON VERIFIE LA TABLE D'EXPORT
        if (!DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress) continue;
        pExports = (PIMAGE_EXPORT_DIRECTORY)((DWORD_PTR)LdrEntry->DllBase + DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress);

        // RECUPERATION DU NOM DU MODULE
        szDllName = (PCHAR)((DWORD_PTR)LdrEntry->DllBase + pExports->Name);

        // SI PAS NTDLL ON CONTINUE DE TESTER
        if ((*(DWORD*)szDllName) != 0x6C64746E) continue; // ldtn
        if ((*(DWORD*)(szDllName + 4)) == 0x6C642E6C) break; // ld.l

    }

    pFunctions = (PDWORD)((DWORD_PTR)LdrEntry->DllBase + pExports->AddressOfFunctions);
    pNames = (PDWORD)((DWORD_PTR)LdrEntry->DllBase + pExports->AddressOfNames);
    pOrdinals = (PDWORD)((DWORD_PTR)LdrEntry->DllBase + pExports->AddressOfNameOrdinals);

    // ON ENREGISTRE TOUTES LES FONCTIONS COMMENCANT PAR "Zw" QUI NOUS INFORME QUE C'EST UN SYSCALL
    i = pExports->NumberOfNames - 1;
    do {
        szFunctionName = (PCHAR)((DWORD_PTR)LdrEntry->DllBase + pNames[i]);
        
        if (*(USHORT*)szFunctionName == 0x775A) { // Zw
            
            ListSyscall.f[ListSyscall.dwNbSyscall].addr = pFunctions[pOrdinals[i]];
            ListSyscall.f[ListSyscall.dwNbSyscall].name = szFunctionName;

            // CALCUL DE NOTRE HASH
            ListSyscall.f[ListSyscall.dwNbSyscall].hash = calcCrc32(-1, ListSyscall.f[ListSyscall.dwNbSyscall].name, strlen(ListSyscall.f[ListSyscall.dwNbSyscall].name));

            // ON INCREMENTE LE NOMBRE DE FONCTIONS TRAITEES
            ListSyscall.dwNbSyscall++;

            // SECURITE
            if (ListSyscall.dwNbSyscall == MAX_SYSCALLS) break;
        }
    } while (--i);


    // TRI DES SYSCALL EN FONCTION DE L'ADRESSE (ASC)
    for (i = 0; i < (ListSyscall.dwNbSyscall - 1); i++) {
        for (j = 0; j < (ListSyscall.dwNbSyscall - i - 1); j++) {
            if (ListSyscall.f[j].addr > ListSyscall.f[j + 1].addr) {
                scTemp.addr = ListSyscall.f[j].addr;
                scTemp.name = ListSyscall.f[j].name;
                scTemp.hash = ListSyscall.f[j].hash;

                ListSyscall.f[j].addr = ListSyscall.f[j + 1].addr;
                ListSyscall.f[j].name = ListSyscall.f[j + 1].name;
                ListSyscall.f[j].hash = ListSyscall.f[j + 1].hash;

                ListSyscall.f[j + 1].addr = scTemp.addr;
                ListSyscall.f[j + 1].name = scTemp.name;
                ListSyscall.f[j + 1].hash= scTemp.hash;
            }
        }
    }
}

DWORD getIdxSyscall(DWORD dwHash) {
    DWORD i;

    for (i = 0; i < MAX_SYSCALLS; i++) {
        if (ListSyscall.f[i].hash == dwHash) return i;
    }
}

void initFunction() {
    sysCreateFile = (syscallCreateFile*)&callSyscall;
    sysCloseHandle = (syscallCloseHandle*)&callSyscall;
    sysWriteFile = (syscallWriteFile*)&callSyscall;
}

void modifyFunction() {
    DWORD dwOldProtect;

    VirtualProtect(((BYTE *)&callSyscall + 3), 2, PAGE_EXECUTE_READWRITE, &dwOldProtect);
    // ON ECRIT L'OPCODE 'syscall'
    *((BYTE*)((BYTE *)&callSyscall + 9)) = 0x0F;
    *((BYTE*)((BYTE *)&callSyscall + 10)) = 0x05;
    VirtualProtect(((BYTE *)&callSyscall + 3), 2, dwOldProtect, &dwOldProtect);
}



#pragma comment(linker, "/entry:myWinMain")
void __fastcall myWinMain() {
    HANDLE hfl;
    OBJECT_ATTRIBUTES oa;    
    IO_STATUS_BLOCK osb;
    DWORD dwrw;
    NTSTATUS dwStatus;
    UNICODE_STRING szFileName;
    char* p;

    hstdOut = GetStdHandle(STD_OUTPUT_HANDLE);

    // POUR TEST ET VERIFICATION
    p = bnqwtohexa(NtCurrentTeb(), &szOutput);
    *(p++) = '\n'; *(p) = 0;
    WriteConsole(hstdOut, &szOutput, strlen(szOutput), &dwrw, 0);

    p = bnqwtohexa(__readgsqword(0x30), &szOutput);
    *(p++) = '\n'; *(p) = 0;
    WriteConsole(hstdOut, &szOutput, strlen(szOutput), &dwrw, 0);

    p = bnqwtohexa(getAddrTEB(), &szOutput);
    *(p++) = '\n'; *(p) = 0;
    WriteConsole(hstdOut, &szOutput, strlen(szOutput), &dwrw, 0);

    // POUR TEST
    //goto ON_EXIT;

    initFunction();

    // ECRITURE DE L'OPCODE 'syscall'
    modifyFunction();

    // RECUPERATION DE LA LISTE DES SYSCALL
    findSyscall(&ListSyscall);

    RtlInitUnicodeString(&szFileName, (PCWSTR)L"\\??\\D:\\_VIDEOS\\Syscall\\x64\\Release\\_SYSCALL_TEST.txt");
    ZeroMemory(&osb, sizeof(IO_STATUS_BLOCK));
    InitializeObjectAttributes(&oa, &szFileName, OBJ_CASE_INSENSITIVE, NULL, NULL);

    // CreateFile
    idxSysCall = getIdxSyscall(0x7235aa8c); // { name=0x00007ff8a9731bcd "ZwCreateFile" hash=0x7235aa8c }
    dwStatus = sysCreateFile(&hfl, FILE_ALL_ACCESS, &oa, &osb, 0, 0, 0, FILE_OVERWRITE_IF, FILE_SYNCHRONOUS_IO_NONALERT, 0, 0);
    if (dwStatus != 0) {
        WriteConsoleA(hstdOut, "[!] Error : CreateFile", 22, &dwrw, NULL);
        goto ON_EXIT;
    }

    // WriteFile
    idxSysCall = getIdxSyscall(0xf4410f2a); // { name=0x00007ff8a9733a30 "ZwWriteFile" hash=0xf4410f2a }
    dwStatus = sysWriteFile(hfl, NULL, NULL, NULL, &osb, &buf, strlen(buf), NULL, NULL);
    if (dwStatus != 0 || osb.Information != strlen(buf)) {
        WriteConsoleA(hstdOut, "[!] Error : WriteFile", 21, &dwrw, NULL);
        goto ON_EXIT;
    }

    // CloseHandle
    idxSysCall = getIdxSyscall(0xca3d545a); // { name=0x00007ff8a97319df "ZwClose" hash=0xca3d545a }
    sysCloseHandle(hfl);

    WriteConsoleA(hstdOut, "[+] File created\n", 17, &dwrw, NULL);
    *bnuqwtoa(osb.Information, &szOutput) = 0;
    WriteConsoleA(hstdOut, szOutput, strlen(szOutput), &dwrw, NULL);
    WriteConsoleA(hstdOut, " bytes written\n\n", 16, &dwrw, NULL);

ON_EXIT:
    ExitProcess(0);   
}