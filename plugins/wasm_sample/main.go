package main

import (
	"strings"
	"unsafe"
)

// main is required for compilation
func main() {}

// Host functions exported by the WAF core
//go:wasmimport env log_info
func host_log_info(ptr, size uint32)

//go:wasmimport env log_error
func host_log_error(ptr, size uint32)

func logInfo(msg string) {
	ptr := uintptr(unsafe.Pointer(&[]byte(msg)[0]))
	host_log_info(uint32(ptr), uint32(len(msg)))
}

// malloc allows the host (WAF) to allocate space in the guest's memory
//export malloc
func malloc(size uint32) uintptr {
	buf := make([]byte, size)
	return uintptr(unsafe.Pointer(&buf[0]))
}

// inspect is the WAF-ABI entry point
// It receives a pointer and length of the request string (Method|Path|Body)
//export inspect
func inspect(ptr, size uint32) int32 {
	// Reconstruct the string from memory
	data := *(*string)(unsafe.Pointer(&struct {
		ptr uintptr
		len int
	}{uintptr(ptr), int(size)}))

	// Example Logic: Block any request containing "WASM_BLOCK_TEST"
	if strings.Contains(data, "WASM_BLOCK_TEST") {
		return 100 // High-severity violation
	}

	// Example Logic: Path-specific custom check
	if strings.HasPrefix(data, "GET|/admin/internal") {
		return 50
	}

	return 0 // Clean
}
