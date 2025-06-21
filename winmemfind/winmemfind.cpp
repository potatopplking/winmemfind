// winmemfind.cpp : Defines the entry point for the application.
//

#include "winmemfind.h"
#include <windows.h>
#include <tlhelp32.h>
#include <vector>
#include <string>

using namespace std;

// Helper to list processes
void listProcesses() {
    HANDLE hSnap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if (hSnap == INVALID_HANDLE_VALUE) return;
    PROCESSENTRY32 pe;
    pe.dwSize = sizeof(pe);
    if (Process32First(hSnap, &pe)) {
        do {
            wprintf(L"PID: %5u  Name: %ls\n", pe.th32ProcessID, pe.szExeFile);
        } while (Process32Next(hSnap, &pe));
    }
    CloseHandle(hSnap);
}

// Helper to scan memory for a byte value
std::vector<uintptr_t> scanMemoryForByte(DWORD pid, BYTE value) {
    std::vector<uintptr_t> results;
    HANDLE hProcess = OpenProcess(PROCESS_VM_READ | PROCESS_QUERY_INFORMATION, FALSE, pid);
    if (!hProcess) {
        cerr << "Failed to open process." << endl;
        return results;
    }
    SYSTEM_INFO sysInfo;
    GetSystemInfo(&sysInfo);
    uintptr_t addr = (uintptr_t)sysInfo.lpMinimumApplicationAddress;
    uintptr_t maxAddr = (uintptr_t)sysInfo.lpMaximumApplicationAddress;
    MEMORY_BASIC_INFORMATION mbi;
    BYTE buffer[4096];
    while (addr < maxAddr) {
        if (VirtualQueryEx(hProcess, (LPCVOID)addr, &mbi, sizeof(mbi)) == sizeof(mbi)) {
            if ((mbi.State == MEM_COMMIT) && (mbi.Protect & (PAGE_READWRITE | PAGE_READONLY | PAGE_WRITECOPY | PAGE_EXECUTE_READ | PAGE_EXECUTE_READWRITE))) {
                SIZE_T bytesRead = 0;
                uintptr_t regionBase = (uintptr_t)mbi.BaseAddress;
                SIZE_T regionSize = mbi.RegionSize;
                for (uintptr_t offset = 0; offset < regionSize; offset += bytesRead) {
                    SIZE_T toRead = min(sizeof(buffer), regionSize - offset);
                    if (ReadProcessMemory(hProcess, (LPCVOID)(regionBase + offset), buffer, toRead, &bytesRead)) {
                        for (SIZE_T i = 0; i < bytesRead; ++i) {
                            if (buffer[i] == value) {
                                results.push_back(regionBase + offset + i);
                            }
                        }
                    } else {
                        cerr << "Failed to read memory at address 0x" << hex << regionBase + offset << dec << endl;
                        break; // stop reading this region if we can't read it
                    }
                }
            }
            addr = (uintptr_t)mbi.BaseAddress + mbi.RegionSize;
        } else {
            addr += 4096; // fallback step
        }
    }
    CloseHandle(hProcess);
    return results;
}

int main()
{
    cout << "winmemfind - Memory Scanner" << endl;
    // cout << "Listing running processes:" << endl;
    // listProcesses();
    cout << "Enter PID of target process: ";
    DWORD pid;
    cin >> pid;
    cout << "Selected PID: " << pid << endl;

    cout << "Enter byte value to search for (0-255): ";
    int val;
    cin >> val;
    if (val < 0 || val > 255) {
        cerr << "Invalid value." << endl;
        return 1;
    }
    BYTE searchVal = static_cast<BYTE>(val);
    cout << "Scanning memory for value..." << endl;
    auto candidates = scanMemoryForByte(pid, searchVal);
    cout << "Found " << candidates.size() << " candidate addresses." << endl;
    // Optionally print first few candidates
    for (size_t i = 0; i < min<size_t>(candidates.size(), 10); ++i) {
        cout << "0x" << hex << candidates[i] << dec << endl;
    }

    HANDLE hProcess = OpenProcess(PROCESS_VM_READ | PROCESS_QUERY_INFORMATION, FALSE, pid);
    if (!hProcess) {
        cerr << "Failed to open process for filtering." << endl;
        return 1;
    }
    while (!candidates.empty()) {
        cout << "\nEnter new value to filter candidates (or -1 to exit): ";
        int newVal;
        cin >> newVal;
        if (newVal == -1) break;
        if (newVal < 0 || newVal > 255) {
            cerr << "Invalid value." << endl;
            continue;
        }
        BYTE filterVal = static_cast<BYTE>(newVal);
        std::vector<uintptr_t> filtered;
        BYTE memByte;
        for (auto addr : candidates) {
            SIZE_T bytesRead = 0;
            if (ReadProcessMemory(hProcess, (LPCVOID)addr, &memByte, 1, &bytesRead) && bytesRead == 1) {
                if (memByte == filterVal) {
                    filtered.push_back(addr);
                }
            }
        }
        candidates = std::move(filtered);
        cout << "Remaining candidates: " << candidates.size() << endl;
        for (size_t i = 0; i < min<size_t>(candidates.size(), 10); ++i) {
            cout << "0x" << hex << candidates[i] << dec << endl;
        }
        if (candidates.empty()) {
            cout << "No candidates remain. Exiting." << endl;
            break;
        }
    }
    CloseHandle(hProcess);
    return 0;
}
