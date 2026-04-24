#include <windows.h>
#include <tlhelp32.h>
#include <stdio.h>

DWORD GetTargetPID()
{
    DWORD pid = 0;
    HANDLE hSnap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if (hSnap == INVALID_HANDLE_VALUE) return 0;

    PROCESSENTRY32 pe = { sizeof(pe) };
    if (Process32First(hSnap, &pe))
    {
        do {
            if (_wcsicmp(pe.szExeFile, L"StarCraft.exe") == 0)
            {
                pid = pe.th32ProcessID;
                break;
            }
        } while (Process32Next(hSnap, &pe));
    }
    CloseHandle(hSnap);
    return pid;
}

DWORD GetModuleBase(DWORD pid)
{
    DWORD base = 0;
    HANDLE hSnap = CreateToolhelp32Snapshot(TH32CS_SNAPMODULE | TH32CS_SNAPMODULE32, pid);
    if (hSnap == INVALID_HANDLE_VALUE) return 0;

    MODULEENTRY32 me = { sizeof(me) };
    if (Module32First(hSnap, &me))
    {
        do {
            if (_wcsicmp(me.szModule, L"StarCraft.exe") == 0)
            {
                base = (DWORD)me.modBaseAddr;
                break;
            }
        } while (Module32Next(hSnap, &me));
    }
    CloseHandle(hSnap);
    return base;
}

// 에러코드 → 문자열 출력
void PrintError(const char* msg)
{
    DWORD err = GetLastError();
    char buf[256];
    FormatMessageA(FORMAT_MESSAGE_FROM_SYSTEM, NULL, err, 0, buf, sizeof(buf), NULL);
    printf("[-] %s | 에러코드: %lu | %s", msg, err, buf);
}

int main()
{
    // 콘솔 창 유지 (어떤 경우에도 꺼지지 않게)
    printf("=== StarCraft Crash Patcher ===\n\n");

    // 1. StarCraft.exe 탐색
    printf("[*] StarCraft.exe 프로세스 탐색 중...\n");
    DWORD pid = GetTargetPID();
    if (!pid)
    {
        printf("[-] StarCraft.exe 를 찾을 수 없습니다.\n");
        printf("    -> 스타크래프트를 먼저 실행하세요!\n");
        goto done;
    }
    printf("[+] PID: %lu\n", pid);

    {
        // 2. 프로세스 열기
        printf("[*] 프로세스 핸들 획득 중...\n");
        HANDLE hProcess = OpenProcess(PROCESS_ALL_ACCESS, FALSE, pid);
        if (!hProcess)
        {
            PrintError("OpenProcess 실패");
            printf("    -> 관리자 권한으로 실행하세요!\n");
            goto done;
        }
        printf("[+] 핸들 획득 성공\n");

        // 3. 베이스 주소
        printf("[*] 베이스 주소 탐색 중...\n");
        DWORD scBase = GetModuleBase(pid);
        if (!scBase)
        {
            PrintError("베이스 주소 획득 실패");
            CloseHandle(hProcess);
            goto done;
        }
        printf("[+] StarCraft.exe base: %08X\n", scBase);

        // 4. 주요 주소
        DWORD gadgetAddr    = scBase + 0x448CAD;
        DWORD redirectAddr  = scBase + 0x3E8EBA;
        printf("[+] 가젯 주소   : %08X\n", gadgetAddr);
        printf("[+] 리다이렉트  : %08X\n", redirectAddr);

        // 5. 원격 메모리 할당
        printf("[*] 원격 메모리 할당 중...\n");
        LPVOID remoteMem = VirtualAllocEx(hProcess, NULL, 0x100,
                                          MEM_COMMIT | MEM_RESERVE,
                                          PAGE_EXECUTE_READWRITE);
        if (!remoteMem)
        {
            PrintError("VirtualAllocEx 실패");
            CloseHandle(hProcess);
            goto done;
        }
        printf("[+] 원격 메모리 : %p\n", remoteMem);

        DWORD remoteVehadd     = (DWORD)remoteMem;
        DWORD remoteVehHandler = remoteVehadd + 0x20;

        // 6. AddVectoredExceptionHandler 주소
        HMODULE hKernel32 = GetModuleHandleA("kernel32.dll");
        DWORD   pAddVEH   = (DWORD)GetProcAddress(hKernel32, "AddVectoredExceptionHandler");
        printf("[+] AddVEH 주소 : %08X\n", pAddVEH);

        // 7. vehadd 셸코드
        BYTE vehadd_code[] = {
            0x68, 0x00, 0x00, 0x00, 0x00,   // push <remoteVehHandler>
            0x6A, 0x01,                      // push 1
            0xB8, 0x00, 0x00, 0x00, 0x00,   // mov eax, <AddVEH>
            0xFF, 0xD0,                      // call eax
            0xC3                             // ret
        };
        *(DWORD*)(vehadd_code + 1) = remoteVehHandler;
        *(DWORD*)(vehadd_code + 8) = pAddVEH;

        // 8. veh_handler 셸코드
        BYTE veh_handler_code[] = {
            0x8B, 0x44, 0x24, 0x04,                         // mov eax, [esp+4]
            0x8B, 0x00,                                     // mov eax, [eax]
            0x81, 0x38, 0x05, 0x00, 0x00, 0xC0,             // cmp [eax], C0000005
            0x75, 0x19,                                     // jne skip
            0x8B, 0x44, 0x24, 0x04,                         // mov eax, [esp+4]
            0x8B, 0x40, 0x04,                               // mov eax, [eax+4]
            0xC7, 0x80, 0xB8, 0x00, 0x00, 0x00,             // mov [eax+B8],
            0x00, 0x00, 0x00, 0x00,                         // <redirectAddr>
            0xB8, 0xFF, 0xFF, 0xFF, 0xFF,                   // mov eax, -1
            0xC2, 0x04, 0x00,                               // ret 4
            0x33, 0xC0,                                     // xor eax, eax
            0xC2, 0x04, 0x00                                // ret 4
        };
        *(DWORD*)(veh_handler_code + 27) = redirectAddr;

        // 9. 원격 메모리에 쓰기
        printf("[*] 셸코드 주입 중...\n");
        SIZE_T written;
        if (!WriteProcessMemory(hProcess, (LPVOID)remoteVehadd, vehadd_code, sizeof(vehadd_code), &written))
        {
            PrintError("vehadd WriteProcessMemory 실패");
            VirtualFreeEx(hProcess, remoteMem, 0, MEM_RELEASE);
            CloseHandle(hProcess);
            goto done;
        }
        printf("[+] vehadd 쓰기 성공 (%zu bytes)\n", written);

        if (!WriteProcessMemory(hProcess, (LPVOID)remoteVehHandler, veh_handler_code, sizeof(veh_handler_code), &written))
        {
            PrintError("veh_handler WriteProcessMemory 실패");
            VirtualFreeEx(hProcess, remoteMem, 0, MEM_RELEASE);
            CloseHandle(hProcess);
            goto done;
        }
        printf("[+] veh_handler 쓰기 성공 (%zu bytes)\n", written);

        // 10. CreateRemoteThread → 가젯 실행, lpParameter = vehadd
        printf("[*] CreateRemoteThread 실행 중...\n");
        printf("    lpStartAddress = %08X (StarCraft.exe+448CAD)\n", gadgetAddr);
        printf("    lpParameter    = %08X (vehadd)\n", remoteVehadd);

        HANDLE hThread = CreateRemoteThread(
            hProcess,
            NULL,
            0,
            (LPTHREAD_START_ROUTINE)gadgetAddr,
            (LPVOID)remoteVehadd,
            0,
            NULL
        );
        if (!hThread)
        {
            PrintError("CreateRemoteThread 실패");
            VirtualFreeEx(hProcess, remoteMem, 0, MEM_RELEASE);
            CloseHandle(hProcess);
            goto done;
        }

        WaitForSingleObject(hThread, 5000);
        DWORD exitCode = 0;
        GetExitCodeThread(hThread, &exitCode);
        printf("[+] 스레드 종료 코드: %08X\n", exitCode);
        printf("[+] VEH 핸들러 등록 완료!\n");
        printf("[+] 닉네임 크래시 방지 패치 적용 성공\n");

        CloseHandle(hThread);
        CloseHandle(hProcess);
    }

done:
    printf("\n[*] 아무 키나 누르면 종료합니다...\n");
    getchar();
    return 0;
}