// winmemfind.cpp : Defines the entry point for the application.
//

#include "winmemfind.h"
#include <windows.h>
#include <tlhelp32.h>
#include <vector>
#include <string>
#include <sstream>
#include <iomanip>

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

// Helper to parse a string of hex bytes into a vector<BYTE>
std::vector<BYTE> parseByteArray(const std::string& s) {
    std::vector<BYTE> bytes;
    std::istringstream iss(s);
    std::string byteStr;
    while (iss >> byteStr) {
        if (byteStr.size() > 2) throw std::invalid_argument("Byte too long");
        BYTE b = (BYTE)std::stoul(byteStr, nullptr, 16);
        bytes.push_back(b);
    }
    return bytes;
}

// Helper to scan memory for a byte array
std::vector<uintptr_t> scanMemoryForBytes(DWORD pid, const std::vector<BYTE>& pattern) {
    std::vector<uintptr_t> results;
    if (pattern.empty()) return results;
    HANDLE hProcess = OpenProcess(PROCESS_VM_READ | PROCESS_QUERY_INFORMATION, FALSE, pid);
    if (!hProcess) return results;
    SYSTEM_INFO sysInfo;
    GetSystemInfo(&sysInfo);
    uintptr_t addr = (uintptr_t)sysInfo.lpMinimumApplicationAddress;
    uintptr_t maxAddr = (uintptr_t)sysInfo.lpMaximumApplicationAddress;
    MEMORY_BASIC_INFORMATION mbi;
    BYTE buffer[4096];
    size_t plen = pattern.size();
    while (addr < maxAddr) {
        if (VirtualQueryEx(hProcess, (LPCVOID)addr, &mbi, sizeof(mbi)) == sizeof(mbi)) {
            if ((mbi.State == MEM_COMMIT) && (mbi.Protect & (PAGE_READWRITE | PAGE_READONLY | PAGE_WRITECOPY | PAGE_EXECUTE_READ | PAGE_EXECUTE_READWRITE))) {
                SIZE_T bytesRead = 0;
                uintptr_t regionBase = (uintptr_t)mbi.BaseAddress;
                SIZE_T regionSize = mbi.RegionSize;
                for (uintptr_t offset = 0; offset < regionSize; offset += bytesRead) {
                    SIZE_T toRead = min(sizeof(buffer), regionSize - offset);
                    if (ReadProcessMemory(hProcess, (LPCVOID)(regionBase + offset), buffer, toRead, &bytesRead)) {
                        for (SIZE_T i = 0; i + plen <= bytesRead; ++i) {
                            if (memcmp(buffer + i, pattern.data(), plen) == 0) {
                                results.push_back(regionBase + offset + i);
                            }
                        }
                    } else {
                        break;
                    }
                }
            }
            addr = (uintptr_t)mbi.BaseAddress + mbi.RegionSize;
        } else {
            addr += 4096;
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
        cout << "\nEnter command (scan BYTES, list, read N, write N BYTES, filter BYTES, add [address], exit): ";
        getline(cin >> ws, cmd);
        if (cmd == "exit") break;
        else if (cmd.rfind("scan ", 0) == 0) {
            try {
                auto pattern = parseByteArray(cmd.substr(5));
                candidates = scanMemoryForBytes(pid, pattern);
                cout << "Found " << candidates.size() << " candidate addresses." << endl;
                for (size_t i = 0; i < min<size_t>(candidates.size(), 10); ++i) {
                    cout << i << ": 0x" << hex << candidates[i] << dec << endl;
                }
            } catch (...) {
                cout << "Invalid byte array. Use e.g. 'scan DE AD BE EF' (hex bytes, space separated)." << endl;
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
            // Read up to 16 bytes for display
            BYTE buf[16] = {0};
            SIZE_T bytesRead = 0;
            if (ReadProcessMemory(hProcess, (LPCVOID)candidates[idx], buf, sizeof(buf), &bytesRead) && bytesRead > 0) {
                cout << "Value at candidate " << idx << ": ";
                for (SIZE_T i = 0; i < bytesRead; ++i) cout << hex << (int)buf[i] << ' ';
                cout << dec << endl;
            } else {
                cout << "Failed to read memory." << endl;
            }
        } else if (cmd.rfind("write ", 0) == 0) {
            size_t pos = cmd.find(' ', 6);
            if (pos == string::npos) { cout << "Usage: write N BYTES" << endl; continue; }
            int idx = stoi(cmd.substr(6, pos-6));
            string bytesStr = cmd.substr(pos+1);
            try {
                auto bytes = parseByteArray(bytesStr);
                DWORD oldProtect = 0;
                if (VirtualProtectEx(hProcess, (LPVOID)candidates[idx], bytes.size(), PAGE_READWRITE, &oldProtect)) {
                    SIZE_T bytesWritten = 0;
                    if (WriteProcessMemory(hProcess, (LPVOID)candidates[idx], bytes.data(), bytes.size(), &bytesWritten) && bytesWritten == bytes.size()) {
                        cout << "Wrote " << bytes.size() << " bytes to candidate " << idx << endl;
                    } else {
                        cout << "Failed to write memory (WriteProcessMemory failed)." << endl;
                    }
                    VirtualProtectEx(hProcess, (LPVOID)candidates[idx], bytes.size(), oldProtect, &oldProtect);
                } else {
                    cout << "Failed to change memory protection (VirtualProtectEx failed)." << endl;
                }
            } catch (...) {
                cout << "Invalid byte array. Use e.g. 'write 0 DE AD BE EF' (hex bytes, space separated)." << endl;
            }
        } else if (cmd.rfind("filter ", 0) == 0) {
            try {
                auto pattern = parseByteArray(cmd.substr(7));
                std::vector<uintptr_t> filtered;
                for (auto addr : candidates) {
                    std::vector<BYTE> buf(pattern.size());
                    SIZE_T bytesRead = 0;
                    if (ReadProcessMemory(hProcess, (LPCVOID)addr, buf.data(), buf.size(), &bytesRead) && bytesRead == buf.size()) {
                        if (memcmp(buf.data(), pattern.data(), buf.size()) == 0) {
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
            } catch (...) {
                cout << "Invalid byte array. Use e.g. 'filter DE AD BE EF' (hex bytes, space separated)." << endl;
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
