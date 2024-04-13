package pkg

import (
	"syscall"
	"unsafe"

	"golang.org/x/sys/windows"
)

//type ModuleEntry32 struct {
//	Size         uint32
//	ModuleID     uint32
//	ProcessID    uint32
//	GlblcntUsage uint32
//	ProccntUsage uint32
//	ModBaseAddr  uintptr
//	ModBaseSize  uint32
//	ModuleHandle Handle
//	Module       [MAX_MODULE_NAME32 + 1]uint16
//	ExePath      [MAX_PATH]uint16
//}
//
//typedef struct tagMODULEENTRY32W {
//DWORD dwSize;
//DWORD th32ModuleID;
//DWORD th32ProcessID;
//DWORD GlblcntUsage;
//DWORD ProccntUsage;
//BYTE *modBaseAddr;
//DWORD modBaseSize;
//HMODULE hModule;
//WCHAR szModule[MAX_MODULE_NAME32 + 1];
//WCHAR szExePath[MAX_PATH];
//} MODULEENTRY32W;

//type ProcessEntry32 struct {
//	Size            uint32
//	Usage           uint32
//	ProcessID       uint32
//	DefaultHeapID   uintptr
//	ModuleID        uint32
//	Threads         uint32
//	ParentProcessID uint32
//	PriClassBase    int32
//	Flags           uint32
//	ExeFile         [MAX_PATH]uint16
//}
//
//typedef struct tagPROCESSENTRY32W {
//DWORD dwSize;
//DWORD cntUsage;
//DWORD th32ProcessID;
//ULONG_PTR th32DefaultHeapID;
//DWORD th32ModuleID;
//DWORD cntThreads;
//DWORD th32ParentProcessID;
//LONG pcPriClassBase;
//DWORD dwFlags;
//WCHAR szExeFile[MAX_PATH];
//} PROCESSENTRY32W;

//typedef struct tagHEAPLIST32 {
//SIZE_T dwSize;
//DWORD th32ProcessID;
//ULONG_PTR th32HeapID;
//DWORD dwFlags;
//} HEAPLIST32;

type HeapList32 struct {
	DwSize        uintptr // 指针
	Th32ProcessID uint32
	Th32HeapID    uintptr
	DwFlags       uint32
}

//DwFlags
//#define HF32_DEFAULT 1
//#define HF32_SHARED 2

// typedef struct tagHEAPENTRY32 {
// 	SIZE_T    dwSize;
// 	HANDLE    hHandle;
// 	ULONG_PTR dwAddress;
// 	SIZE_T    dwBlockSize;
// 	DWORD     dwFlags;
// 	DWORD     dwLockCount;
// 	DWORD     dwResvd;
// 	DWORD     th32ProcessID;
// 	ULONG_PTR th32HeapID;
//   } HEAPENTRY32;

type HeapEntry32 struct {
	DwSize        uintptr // 指针
	HHandle       uintptr // 等于Th32HeapID
	DwAddress     uintptr // 块开头的线性地址？
	DwBlockSize   uintptr // 块大小 字节
	DwFlags       uint32
	DwLockCount   uint32
	DwResvd       uint32
	Th32ProcessID uint32
	Th32HeapID    uintptr
}

func GetProcessHeap(processID uint32, heapID uintptr) ([]HeapEntry32, error) {
	kernel32, err := syscall.LoadDLL("kernel32.dll")
	if err != nil {
		return nil, err
	}

	Heap32First, err := kernel32.FindProc("Heap32First")
	if err != nil {
		return nil, err
	}

	Heap32Next, err := kernel32.FindProc("Heap32Next")
	if err != nil {
		return nil, err
	}

	var hp HeapEntry32
	hp.DwSize = unsafe.Sizeof(hp)
	var result []HeapEntry32

	r1, _, err := Heap32First.Call(uintptr(unsafe.Pointer(&hp)), uintptr(processID), heapID)
	if r1 == 0 {
		return nil, err
	}
	result = append(result, hp)

	for {
		r1, _, _ = Heap32Next.Call(uintptr(unsafe.Pointer(&hp)))
		if r1 == 0 {
			break
		}
		result = append(result, hp)
	}

	return result, nil
}

func GetProcessHeapList(processID uint32) ([]HeapList32, error) {
	//kernel32 := syscall.MustLoadDLL("kernel32.dll")
	//Heap32ListNext := kernel32.MustFindProc("Heap32ListNext")

	kernel32, err := syscall.LoadDLL("kernel32.dll")
	if err != nil {
		return nil, err
	}
	Heap32ListNext, err := kernel32.FindProc("Heap32ListNext")
	if err != nil {
		return nil, err
	}

	snapshot, err := windows.CreateToolhelp32Snapshot(windows.TH32CS_SNAPHEAPLIST, processID)
	if err != nil {
		return nil, err
	}
	defer windows.Close(snapshot)

	var hp HeapList32
	hp.DwSize = unsafe.Sizeof(hp)
	var result []HeapList32

	for {
		r1, _, _ := Heap32ListNext.Call(uintptr(snapshot), uintptr(unsafe.Pointer(&hp)))
		// r1 == 0表示出错
		if r1 == 0 {
			break
		}
		result = append(result, hp)
	}
	return result, nil
}
