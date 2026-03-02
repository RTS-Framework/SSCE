package ssce

import (
	"syscall"
	"testing"
	"unsafe"

	"github.com/stretchr/testify/require"
	"golang.org/x/sys/windows"
)

func loadShellcode(t *testing.T, sc []byte) uintptr {
	size := uintptr(len(sc))
	mType := uint32(windows.MEM_COMMIT | windows.MEM_RESERVE)
	mProtect := uint32(windows.PAGE_EXECUTE_READWRITE)
	scAddr, err := windows.VirtualAlloc(0, size, mType, mProtect)
	require.NoError(t, err)
	dst := unsafe.Slice((*byte)(unsafe.Pointer(scAddr)), size)
	copy(dst, sc)
	return scAddr
}

// for cross-compile
//
//go:uintptrescapes
func syscallN(proc uintptr, args ...uintptr) (r1, r2 uintptr, err syscall.Errno) {
	return syscall.SyscallN(proc, args...)
}
