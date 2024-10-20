#include <stdlib.h>
#include <stdio.h>
#include <Windows.h>
#include <tlhelp32.h>

DWORD FindProcessId()
{
    HANDLE hProcessSnap;
    PROCESSENTRY32 pe32;
    DWORD result = -1;

    // Take a snapshot of all processes in the system.
    hProcessSnap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if (INVALID_HANDLE_VALUE == hProcessSnap) return -1;

    pe32.dwSize = sizeof(PROCESSENTRY32);

    // Retrieve information about the first process,
    // and exit if unsuccessful
    if (!Process32First(hProcessSnap, &pe32))
    {
        CloseHandle(hProcessSnap);  // clean the snapshot object
        printf("!!! Failed to gather information on system processes! \n");
        return -1;
    }

    do
    {
        printf("Process name:%ls\n\tPID: %d\n\tPPID: %d\n\tThreads: %d\n", pe32.szExeFile, pe32.th32ProcessID, pe32.th32ParentProcessID, pe32.cntThreads);
        //
        //if (0 == strcmp(processname, pe32.szExeFile))
        //{
        //    result = pe32.th32ProcessID;
        //    break;
        //}
        
    } while (Process32Next(hProcessSnap, &pe32));

    CloseHandle(hProcessSnap);

    return result;
}

int main(int argc, char* argv[])
{
    FindProcessId();
    return 0;
}
