package pkg

import (
	"fmt"
	"golang.org/x/sys/windows"
	"log"
)

func PrintProcessHeap(processID uint32, heapID uintptr) {
	hps, err := GetProcessHeap(processID, heapID)
	if err != nil {
		log.Fatal(err)
	}
	fmt.Printf("Heap ID: %v\n", heapID)
	for _, hp := range hps {
		fmt.Printf("%+v\n", hp)
		//fmt.Printf("Block size: %v\n", hp.DwBlockSize)
	}
	fmt.Println()
}

func PrintProcessHeapList(processID uint32) {
	hps, err := GetProcessHeapList(processID)
	if err != nil {
		log.Fatal(err)
	}
	for _, hp := range hps {
		fmt.Printf("0x%-16X %v\n", hp.Th32HeapID, hp.DwFlags)
	}
}

func PrintProcessModules(processID uint32) {
	mes, err := GetProcessModules(processID)
	if err != nil {
		log.Fatal(err)
	}
	for _, me := range mes {
		fmt.Printf("0x%-16X %vkb %v %v\n", me.ModBaseAddr, me.ModBaseSize/1024, Convert(me.Module[:]), Convert(me.ExePath[:]))
	}
}

func PrintProcessList() {
	pes, err := GetProcessList()
	if err != nil {
		log.Fatal(err)
	}
	for _, pe := range pes {
		fmt.Printf("%v %v\n", pe.ProcessID, Convert(pe.ExeFile[:]))
	}
}

func GetPID(processName string) ([]uint32, error) {
	ps, err := GetProcessList()
	if err != nil {
		return nil, err
	}
	var result []uint32
	for _, p := range ps {
		if Convert(p.ExeFile[:]) == processName {
			result = append(result, p.ProcessID)
		}
	}
	return result, nil
}

func Convert(sli []uint16) string {
	return windows.UTF16ToString(sli)
	//var endIndex int
	//for endIndex = 0; endIndex < len(sli); endIndex++ {
	//	if sli[endIndex] == 0 {
	//		break
	//	}
	//}
	//return string(utf16.Decode(sli[:endIndex]))
}
