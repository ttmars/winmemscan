#include <windows.h>
#include <stdio.h>

// 扫描特定进程的内存
void ScanProcessMemory(HANDLE hProcess, int valueToFind) {
    MEMORY_BASIC_INFORMATION mbi;
    DWORD_PTR startAddr = 0;
    SIZE_T bytesRead;
    int buffer;
    
    while (VirtualQueryEx(hProcess, (LPCVOID)startAddr, &mbi, sizeof(mbi))) {
        if (mbi.State == MEM_COMMIT && (mbi.Protect == PAGE_READWRITE || mbi.Protect == PAGE_READONLY)) {
            DWORD_PTR regionEnd = startAddr + mbi.RegionSize;
            for (DWORD_PTR currAddr = startAddr; currAddr < regionEnd; currAddr += sizeof(buffer)) {
                if (ReadProcessMemory(hProcess, (LPCVOID)currAddr, &buffer, sizeof(buffer), &bytesRead)) {
                    if (bytesRead == sizeof(buffer) && buffer == valueToFind) {
                        printf("Found value at: 0x%08X\n", currAddr);
                    }
                }
            }
        }
        startAddr += mbi.RegionSize;
    }
}

int main() {
    // 替换为目标进程的ID
    DWORD processID = 78876;
    
    // 要搜索的值
    int valueToFind = 776688;

    // 打开目标进程
    HANDLE hProcess = OpenProcess(PROCESS_VM_READ | PROCESS_QUERY_INFORMATION, FALSE, processID);
    if (hProcess == NULL) {
        fprintf(stderr, "OpenProcess failed. Error: %lu\n", GetLastError());
        return 1;
    }


    // 执行内存扫描
    ScanProcessMemory(hProcess, valueToFind);

    // 清理
    CloseHandle(hProcess);
    return 0;
}
