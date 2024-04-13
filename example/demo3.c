#include <windows.h>
#include <stdio.h>

#define BUFFER_SIZE 4096 // 增加缓冲区大小以减少系统调用次数

void ScanProcessMemory(HANDLE hProcess, int valueToFind) {
    MEMORY_BASIC_INFORMATION mbi;
    DWORD_PTR startAddr = 0;
    SIZE_T bytesRead;
    BYTE buffer[BUFFER_SIZE];
    MEM_PRIVATE
    
    while (VirtualQueryEx(hProcess, (LPCVOID)startAddr, &mbi, sizeof(mbi))) {
        if (mbi.State == MEM_COMMIT && (mbi.Protect == PAGE_READWRITE || mbi.Protect == PAGE_READONLY)) {
            DWORD_PTR regionEnd = startAddr + mbi.RegionSize;
            for (DWORD_PTR currAddr = startAddr; currAddr < regionEnd; currAddr += bytesRead) {
                SIZE_T bytesToRead = min(BUFFER_SIZE, regionEnd - currAddr);
                if (ReadProcessMemory(hProcess, (LPCVOID)currAddr, buffer, bytesToRead, &bytesRead)) {
                    for (size_t i = 0; i < (bytesRead - sizeof(valueToFind)); ++i) {
                        int* p = (int*)&buffer[i];
                        if (*p == valueToFind) {
                            printf("Found value at: 0x%08X\n", currAddr + i);
                        }
                    }
                }
            }
        }
        startAddr += mbi.RegionSize;
    }
}

int main() {
    DWORD processID = 78876;
    HANDLE hProcess = OpenProcess(PROCESS_VM_READ | PROCESS_QUERY_INFORMATION, FALSE, processID);
    if (hProcess == NULL) {
        fprintf(stderr, "OpenProcess failed. Error: %lu\n", GetLastError());
        return 1;
    }

    int valueToFind = 776688;
    ScanProcessMemory(hProcess, valueToFind);
    CloseHandle(hProcess);
    return 0;
}
