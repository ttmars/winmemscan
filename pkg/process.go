package pkg

import (
	"unsafe"

	"golang.org/x/sys/windows"
)

func OpenProcess(processId uint32) (handle windows.Handle, err error) {
	//#define PROCESS_ALL_ACCESS (STANDARD_RIGHTS_REQUIRED | SYNCHRONIZE | 0xffff)
	//#else
	//#define PROCESS_ALL_ACCESS (STANDARD_RIGHTS_REQUIRED | SYNCHRONIZE | 0xfff)

	access := windows.STANDARD_RIGHTS_REQUIRED | windows.SYNCHRONIZE | 0xffff
	//access := windows.STANDARD_RIGHTS_REQUIRED | windows.SYNCHRONIZE | 0xfff
	//access := 0x1F0FFF
	return windows.OpenProcess(uint32(access), false, processId)
}

func GetProcessModules(processID uint32) ([]windows.ModuleEntry32, error) {
	snapshot, err := windows.CreateToolhelp32Snapshot(windows.TH32CS_SNAPMODULE, processID)
	if err != nil {
		return nil, err
	}
	defer windows.Close(snapshot)

	me := windows.ModuleEntry32{}
	me.Size = uint32(unsafe.Sizeof(me))

	var result []windows.ModuleEntry32
	for {
		err = windows.Module32Next(snapshot, &me)
		if err != nil {
			break
		}
		result = append(result, me)
	}
	return result, nil
}

func GetProcessList() ([]windows.ProcessEntry32, error) {
	snapshot, err := windows.CreateToolhelp32Snapshot(windows.TH32CS_SNAPPROCESS, 0)
	if err != nil {
		return nil, err
	}
	defer windows.Close(snapshot)

	pe := windows.ProcessEntry32{}
	pe.Size = uint32(unsafe.Sizeof(pe))

	var result []windows.ProcessEntry32
	for {
		err = windows.Process32Next(snapshot, &pe)
		if err != nil {
			break
		}
		result = append(result, pe)
	}
	return result, nil
}
