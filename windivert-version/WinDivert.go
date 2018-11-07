package main

import (
	"C"
	"syscall"
	"unsafe"
)

type WinDivertAddress struct {
	Timestamp int64
	IfIdx     uint32
	SubIfIdx  uint32
	Data      uint8
}

var (
	WindivertDLL                 *syscall.DLL
	WinDivertOpen                *syscall.Proc
	WinDivertClose               *syscall.Proc
	WinDivertRecv                *syscall.Proc
	WinDivertSend                *syscall.Proc
	WinDivertHelperCalcChecksums *syscall.Proc
)

func WindivertInit(Path string) {
	WindivertDLL = syscall.MustLoadDLL(Path)
	WinDivertOpen = WindivertDLL.MustFindProc("WinDivertOpen")
	WinDivertClose = WindivertDLL.MustFindProc("WinDivertClose")
	WinDivertRecv = WindivertDLL.MustFindProc("WinDivertRecv")
	WinDivertSend = WindivertDLL.MustFindProc("WinDivertSend")
	WinDivertHelperCalcChecksums = WindivertDLL.MustFindProc("WinDivertHelperCalcChecksums")
}

func WinDivertCloseGo(Handle uintptr) error {
	Result, _, err := WinDivertClose.Call(Handle)
	if Result != 1 || err.Error() != "The operation completed successfully." {
		return err
	}
	return nil
}

func WinDivertOpenGo(filter string, layer int, priority int, flags int) (uintptr, error) {
	filter_c := C.CString(filter)
	Handle, _, err := WinDivertOpen.Call(uintptr(unsafe.Pointer(filter_c)), uintptr(layer), uintptr(priority), uintptr(flags))
	if err.Error() != "The operation completed successfully." {
		return 0, err
	}
	return Handle, nil
}

func WinDivertRecvGo(Handle uintptr) ([]byte, WinDivertAddress, error) {
	RXLen := 0
	RXPacket := make([]byte, 65535)
	RXAddr := WinDivertAddress{}
	RXAddr.Data = 0
	RXAddr.IfIdx = 0
	RXAddr.SubIfIdx = 0
	RXAddr.Timestamp = 0
	Result, _, err := WinDivertRecv.Call(Handle, uintptr(unsafe.Pointer(&RXPacket[0])), uintptr(65535), uintptr(unsafe.Pointer(&RXAddr)), uintptr(unsafe.Pointer(&RXLen)))
	if Result != 1 || err.Error() != "The operation completed successfully." {
		return []byte(""), RXAddr, err
	}
	RXPacket = RXPacket[:RXLen]
	return RXPacket, RXAddr, nil
}

func WinDivertSendGo(Handle uintptr, TXPacket []byte, TXAddr WinDivertAddress) error {
	TXLen := 0
	Result, _, err := WinDivertSend.Call(Handle, uintptr(unsafe.Pointer(&TXPacket[0])), uintptr(len(TXPacket)), uintptr(unsafe.Pointer(&TXAddr)), uintptr(unsafe.Pointer(&TXLen)))
	if Result != 1 || err.Error() != "The operation completed successfully." {
		return err
	}
	return nil
}

func WinDivertHelperCalcChecksumsGo(Handle uintptr, TXPacket []byte, TXAddr WinDivertAddress) (int, error) {
	Result, _, err := WinDivertHelperCalcChecksums.Call(uintptr(unsafe.Pointer(&TXPacket[0])), uintptr(len(TXPacket)), uintptr(unsafe.Pointer(&TXAddr)), uintptr(0))
	if err.Error() != "The operation completed successfully." {
		return 0, err
	}
	return int(Result), nil
}
