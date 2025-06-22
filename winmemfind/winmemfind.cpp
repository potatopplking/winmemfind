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
            wprintf(L"PID: %5u  Name: %s\n", pe.th32ProcessID, pe.szExeFile);
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

    // Command-based loop
    std::vector<uintptr_t> candidates;
    SIZE_T bytesRead = 0;
    SIZE_T bytesWritten = 0;
    HANDLE hProcess = OpenProcess(PROCESS_VM_READ | PROCESS_VM_WRITE | PROCESS_VM_OPERATION | PROCESS_QUERY_INFORMATION, FALSE, pid);
    if (!hProcess) {
        cerr << "Failed to open process with PID " << pid << ". Make sure the process is running and you have permissions." << endl;
        return 1;
    }
    string cmd;
    while (true) {
        cout << "\nEnter command (scan V, list, read N, write N V, filter V, add [address], exit): ";
        getline(cin >> ws, cmd);
        if (cmd == "exit") break;
        else if (cmd.rfind("scan ", 0) == 0) {
            int val = stoi(cmd.substr(5));
            if (val < 0 || val > 255) {
                cout << "Invalid value." << endl;
                continue;
            }
            BYTE searchVal = static_cast<BYTE>(val);
            candidates = scanMemoryForByte(pid, searchVal);
            cout << "Found " << candidates.size() << " candidate addresses." << endl;
            for (size_t i = 0; i < min<size_t>(candidates.size(), 10); ++i) {
                cout << i << ": 0x" << hex << candidates[i] << dec << endl;
            }
        } else if (cmd == "list") {
            for (size_t i = 0; i < candidates.size(); ++i) {
                cout << i << ": 0x" << hex << candidates[i] << dec << endl;
            }
        } else if (cmd.rfind("read ", 0) == 0) {
            int idx = stoi(cmd.substr(5));
            if (idx < 0 || (size_t)idx >= candidates.size()) {
                cout << "Invalid candidate number." << endl;
                continue;
            }
            BYTE val;
            SIZE_T bytesRead = 0;
            if (ReadProcessMemory(hProcess, (LPCVOID)candidates[idx], &val, 1, &bytesRead) && bytesRead == 1) {
                cout << "Value at candidate " << idx << ": " << (int)val << endl;
            } else {
                cout << "Failed to read memory." << endl;
            }
        } else if (cmd.rfind("write ", 0) == 0) {
            size_t pos = cmd.find(' ', 6);
            if (pos == string::npos) { cout << "Usage: write N V" << endl; continue; }
            int idx = stoi(cmd.substr(6, pos-6));
            int v = stoi(cmd.substr(pos+1));
            if (idx < 0 || (size_t)idx >= candidates.size() || v < 0 || v > 255) {
                cout << "Invalid input." << endl;
                continue;
            }
            BYTE val = static_cast<BYTE>(v);
            SIZE_T bytesWritten = 0;
            if (WriteProcessMemory(hProcess, (LPVOID)candidates[idx], &val, 1, &bytesWritten) && bytesWritten == 1) {
                cout << "Wrote value " << v << " to candidate " << idx << endl;
            } else {
                cout << "Failed to write memory." << endl;
            }
        } else if (cmd.rfind("filter ", 0) == 0) {
            int newVal = stoi(cmd.substr(7));
            if (newVal < 0 || newVal > 255) {
                cout << "Invalid value." << endl;
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
                cout << i << ": 0x" << hex << candidates[i] << dec << endl;
            }
            if (candidates.empty()) {
                cout << "No candidates remain." << endl;
            }
        } else if (cmd.rfind("add ", 0) == 0) {
            string addrStr = cmd.substr(4);
            uintptr_t addr = 0;
            try {
                size_t idx = 0;
                addr = stoull(addrStr, &idx, 0); // auto-detect base (0x for hex)
                if (idx != addrStr.length()) throw std::invalid_argument("trailing");
            } catch (...) {
                cout << "Invalid address format. Use decimal or 0x... for hex." << endl;
                continue;
            }
            candidates.push_back(addr);
            cout << "Added address 0x" << hex << addr << dec << " as candidate " << (candidates.size()-1) << endl;
        } else {
            cout << "Unknown command." << endl;
        }
    }
    CloseHandle(hProcess);
    return 0;
}
