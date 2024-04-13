package pkg

import (
	"bytes"
	"encoding/binary"
	"errors"
	"fmt"
	"log"
	"os"
	"strconv"
	"strings"
	"unsafe"

	"golang.org/x/sys/windows"
)

type MemScanner struct {
	Bit         int            // 搜索位
	ProcessName string         // 进程名称
	PID         uint32         // 进程PID
	MemFD       *os.File       // 进程内存文件描述符
	PmapItems   []PmapItem     // 可扫描内存段
	Result      []int64        // 当前搜索结果（偏移）
	Handle      windows.Handle // 进程句柄
}

// Flag
// #define LF32_FIXED 0x00000001
// #define LF32_FREE 0x00000002
// #define LF32_MOVEABLE 0x00000004
type PmapItem struct {
	Address uintptr
	Kbytes  uint32 // 字节非kb
	Module  string
	Flag    uint32
}

func NewMemScanner(name string) (*MemScanner, error) {
	scan := &MemScanner{
		Bit:         32,
		ProcessName: name,
	}

	pids, err := GetPID(scan.ProcessName)
	if err != nil {
		return nil, err
	}
	if len(pids) != 1 {
		return nil, errors.New("get pid err")
	}
	scan.PID = pids[0]

	scan.Handle, err = OpenProcess(scan.PID)
	if err != nil {
		log.Fatal(err)
	}

	scan.PmapItems, err = GetPmapItems(scan.PID)
	if err != nil {
		log.Fatal(err)
	}

	return scan, nil
}

func (m *MemScanner) PrintPmap() {
	for _, v := range m.PmapItems {
		fmt.Printf("0x%-16X %-10v %v %v\n", v.Address, v.Kbytes/1024, v.Module, v.Flag)
	}
}

func (m *MemScanner) Close() {
	windows.Close(m.Handle)
}

// 清除扫描结果
func (m *MemScanner) Clear() {
	if m.Result != nil {
		m.Result = m.Result[:0]
	}
}

// 设置搜索类型
func (m *MemScanner) SetBit(b string) {
	bit, err := strconv.ParseInt(b, 10, 8)
	if err != nil {
		return
	}
	if bit == 8 || bit == 16 || bit == 32 || bit == 64 {
		m.Bit = int(bit)
	}
}

// 打印内存段，start起始地址，off偏移，单位：byte
func (m *MemScanner) PrintMem(startStr string, offStr string) {
	startStr = strings.TrimPrefix(startStr, "0x")
	start, err := strconv.ParseInt(startStr, 16, 64)
	if err != nil {
		fmt.Println(err)
		return
	}
	off, err := strconv.ParseInt(offStr, 10, 64)
	if err != nil {
		fmt.Println(err)
		return
	}

	b := make([]byte, off)
	var n uintptr
	err = windows.ReadProcessMemory(m.Handle, uintptr(start), &b[0], uintptr(off), &n)
	if err != nil || int64(n) != off {
		log.Printf("读取失败！%x %v", start, off)
		return
	}
	fmt.Printf("read:%-15v%02x %02x %02x %02x %02x %02x %02x %02x %02x %02x %02X %02X %02X %02X %02X %02X\n", n, 0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15)
	for i := 0; i < int(n); i++ {
		if i%16 == 0 {
			fmt.Println()
			fmt.Printf("0x%-18x", start+int64(i))
		}
		fmt.Printf("%02x ", b[i])
	}
	fmt.Println()
}

func GetPmapItems(processID uint32) ([]PmapItem, error) {
	var result []PmapItem

	mes, err := GetProcessModules(processID)
	if err != nil {
		log.Println("GetProcessModules err")
		return nil, err
	}
	for _, me := range mes {
		Module := Convert(me.ExePath[:])
		if !strings.HasSuffix(strings.ToUpper(Module), ".DLL") {
			result = append(result, PmapItem{
				Address: me.ModBaseAddr,
				Kbytes:  me.ModBaseSize,
				Module:  Module,
			})
		}
	}

	// 读不了最后一段堆内存
	//phlist, err := GetProcessHeapList(processID)
	//if err != nil {
	//	log.Println("GetProcessHeapList err")
	//	return nil, err
	//}
	//
	//for _, ph := range phlist {
	//	heap, err := GetProcessHeap(ph.Th32ProcessID, ph.Th32HeapID)
	//	if err != nil {
	//		log.Println("GetProcessHeap err")
	//		return nil, err
	//	}
	//
	//	for _, block := range heap {
	//		//bs += block.DwBlockSize
	//		if block.DwFlags == 1 {
	//			result = append(result, PmapItem{
	//				Address: block.DwAddress,
	//				Kbytes:  uint32(block.DwBlockSize),
	//				Module:  "heap",
	//				Flag:    block.DwFlags,
	//			})
	//		}
	//	}
	//}

	return result, nil
}

// 打印匹配结果
func (m *MemScanner) PrintResult() {
	fmt.Printf("匹配数量：%v\n", len(m.Result))
	flag := false
	num := len(m.Result)
	if num >= 10 {
		num = 10
		flag = true
	}
	for i := 0; i < num; i++ {
		b := make([]byte, 8)
		//m.MemFD.Seek(m.Result[i], 0)
		//m.MemFD.Read(b)
		windows.ReadProcessMemory(m.Handle, uintptr(m.Result[i]), &b[0], 8, nil)

		fmt.Printf("%-2v0x%-16x% x\n", i, m.Result[i], b)
	}
	if flag {
		fmt.Println("...")
	}
}

// 扫描内存段
func (m *MemScanner) Scan(value string) {
	int8Value, int8ValueErr := strconv.ParseInt(value, 10, 8)
	int16Value, int16ValueErr := strconv.ParseInt(value, 10, 16)
	int32Value, int32ValueErr := strconv.ParseInt(value, 10, 32)
	int64Value, int64ValueErr := strconv.ParseInt(value, 10, 64)

	uint8Value, uint8ValueErr := strconv.ParseUint(value, 10, 8)
	uint16Value, uint16ValueErr := strconv.ParseUint(value, 10, 16)
	uint32Value, uint32ValueErr := strconv.ParseUint(value, 10, 32)
	uint64Value, uint64ValueErr := strconv.ParseUint(value, 10, 64)

	float32Value, float32ValueErr := strconv.ParseFloat(value, 32)
	float64Value, float64ValueErr := strconv.ParseFloat(value, 64)

	// 扫描结果集
	if len(m.Result) > 0 {
		var sli []int64
		b := make([]byte, 8)
		for _, v := range m.Result {
			err := windows.ReadProcessMemory(m.Handle, uintptr(v), &b[0], 8, nil)
			if err != nil {
				log.Println("读取失败！", v)
				return
			}
			switch m.Bit {
			case 8:
				int8V := *(*int8)(unsafe.Pointer(&b[0]))
				uint8V := *(*uint8)(unsafe.Pointer(&b[0]))
				if (int8ValueErr == nil && int8V == int8(int8Value)) || (uint8ValueErr == nil && uint8V == uint8(uint8Value)) {
					sli = append(sli, v)
				}
			case 16:
				int16V := *(*int16)(unsafe.Pointer(&b[0]))
				uint16V := *(*uint16)(unsafe.Pointer(&b[0]))
				if (int16ValueErr == nil && int16V == int16(int16Value)) || (uint16ValueErr == nil && uint16V == uint16(uint16Value)) {
					sli = append(sli, v)
				}
			case 32:
				int32V := *(*int32)(unsafe.Pointer(&b[0]))
				uint32V := *(*uint32)(unsafe.Pointer(&b[0]))
				float32V := *(*float32)(unsafe.Pointer(&b[0]))
				if (int32ValueErr == nil && int32V == int32(int32Value)) || (uint32ValueErr == nil && uint32V == uint32(uint32Value)) || (float32ValueErr == nil && float32V == float32(float32Value)) {
					sli = append(sli, v)
				}
			case 64:
				int64V := *(*int64)(unsafe.Pointer(&b[0]))
				uint64V := *(*uint64)(unsafe.Pointer(&b[0]))
				float64V := *(*float64)(unsafe.Pointer(&b[0]))
				if (int64ValueErr == nil && int64V == int64Value) || (uint64ValueErr == nil && uint64V == uint64Value) || (float64ValueErr == nil && float64V == float64Value) {
					sli = append(sli, v)
				}
			}
		}
		m.Result = sli
		return
	}

	// 扫描所有内存段
	for _, item := range m.PmapItems {
		start := int64(item.Address)
		mem := make([]byte, item.Kbytes)
		var n uintptr
		err := windows.ReadProcessMemory(m.Handle, item.Address, &mem[0], uintptr(item.Kbytes), &n)
		if err != nil || uint32(n) != item.Kbytes {
			log.Printf("读取失败！%v %X %v %v", n, item.Address, item.Kbytes, err)
			return
		}

		// 扫描内存, -8 +2
		for i := 0; i < int(n)-8; i += 2 {
			// fmt.Println(i)
			if m.Bit == 8 {
				int8V := *(*int8)(unsafe.Pointer(&mem[i]))
				uint8V := *(*uint8)(unsafe.Pointer(&mem[i]))
				if (int8ValueErr == nil && int8V == int8(int8Value)) || (uint8ValueErr == nil && uint8V == uint8(uint8Value)) {
					m.Result = append(m.Result, start+int64(i))
				}
			} else if m.Bit == 16 {
				int16V := *(*int16)(unsafe.Pointer(&mem[i]))
				uint16V := *(*uint16)(unsafe.Pointer(&mem[i]))
				if (int16ValueErr == nil && int16V == int16(int16Value)) || (uint16ValueErr == nil && uint16V == uint16(uint16Value)) {
					m.Result = append(m.Result, start+int64(i))
				}
			} else if m.Bit == 32 {
				int32V := *(*int32)(unsafe.Pointer(&mem[i]))
				uint32V := *(*uint32)(unsafe.Pointer(&mem[i]))
				float32V := *(*float32)(unsafe.Pointer(&mem[i]))
				if (int32ValueErr == nil && int32V == int32(int32Value)) || (uint32ValueErr == nil && uint32V == uint32(uint32Value)) || (float32ValueErr == nil && float32V == float32(float32Value)) {
					m.Result = append(m.Result, start+int64(i))
				}
			} else if m.Bit == 64 {
				int64V := *(*int64)(unsafe.Pointer(&mem[i]))
				uint64V := *(*uint64)(unsafe.Pointer(&mem[i]))
				float64V := *(*float64)(unsafe.Pointer(&mem[i]))
				if (int64ValueErr == nil && int64V == int64Value) || (uint64ValueErr == nil && uint64V == uint64Value) || (float64ValueErr == nil && float64V == float64Value) {
					m.Result = append(m.Result, start+int64(i))
				}
			}
		}
	}
}

func (m *MemScanner) Overwrite(idx string, value string) ([]byte, error) {
	if strings.HasSuffix(value, "f") {
		return m.overwriteFloat(idx, value)
	} else {
		return m.overwriteInt(idx, value)
	}
}

// 写入值 int8/int16/int32/int64
func (m *MemScanner) overwriteInt(idx string, value string) ([]byte, error) {
	index, err := strconv.ParseInt(idx, 10, 64)
	if err != nil {
		return nil, err
	}

	if len(m.Result) == 0 || index >= int64(len(m.Result)) {
		return nil, errors.New("empty result or invalid index")
	}

	v, err := strconv.ParseInt(value, 10, m.Bit)
	if err != nil {
		return nil, err
	}

	buf := new(bytes.Buffer)
	switch m.Bit {
	case 8:
		err = binary.Write(buf, binary.LittleEndian, int8(v))
		if err != nil {
			return nil, err
		}
	case 16:
		err = binary.Write(buf, binary.LittleEndian, int16(v))
		if err != nil {
			return nil, err
		}
	case 32:
		err = binary.Write(buf, binary.LittleEndian, int32(v))
		if err != nil {
			return nil, err
		}
	case 64:
		err = binary.Write(buf, binary.LittleEndian, int64(v))
		if err != nil {
			return nil, err
		}
	}

	b := buf.Bytes()
	//m.MemFD.Seek(m.Result[index], 0)
	//_, err = m.MemFD.Write(b)
	var n uintptr
	err = windows.WriteProcessMemory(m.Handle, uintptr(m.Result[index]), &b[0], uintptr(len(b)), &n)
	if err != nil || int(n) != len(b) {
		return nil, err
	}

	return b, nil
}

// 写入值 float32/float64
func (m *MemScanner) overwriteFloat(idx string, value string) ([]byte, error) {
	value = strings.TrimSuffix(value, "f")

	index, err := strconv.ParseInt(idx, 10, 64)
	if err != nil {
		return nil, err
	}

	if len(m.Result) == 0 || index >= int64(len(m.Result)) {
		return nil, errors.New("empty result or invalid index")
	}

	v, err := strconv.ParseFloat(value, m.Bit)
	if err != nil {
		return nil, err
	}

	buf := new(bytes.Buffer)
	switch m.Bit {
	case 32:
		err = binary.Write(buf, binary.LittleEndian, float32(v))
		if err != nil {
			return nil, err
		}
	case 64:
		err = binary.Write(buf, binary.LittleEndian, float64(v))
		if err != nil {
			return nil, err
		}
	}

	b := buf.Bytes()
	//m.MemFD.Seek(m.Result[index], 0)
	//_, err = m.MemFD.Write(b)
	var n uintptr
	err = windows.WriteProcessMemory(m.Handle, uintptr(m.Result[index]), &b[0], uintptr(len(b)), &n)
	if err != nil || int(n) != len(b) {
		return nil, err
	}
	if err != nil || int(n) != len(b) {
		return nil, err
	}

	return b, nil
}
