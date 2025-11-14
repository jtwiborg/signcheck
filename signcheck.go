package main

import (
	"debug/macho"
	"debug/pe"
	"encoding/binary"
	"fmt"
	"os"
	"path/filepath"
)

func main() {
	if len(os.Args) < 2 {
		fmt.Fprintf(os.Stderr, "Usage: %s <binary-file>\n", filepath.Base(os.Args[0]))
		os.Exit(2)
	}

	filename := os.Args[1]
	
	// Check if file exists
	info, err := os.Stat(filename)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error: %v\n", err)
		os.Exit(2)
	}

	fmt.Printf("File: %s\n", filename)
	fmt.Printf("Size: %d bytes\n", info.Size())

	// Try to detect file type and check signature
	signed, fileType, err := checkSignature(filename)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error checking signature: %v\n", err)
		os.Exit(2)
	}

	fmt.Printf("Type: %s\n", fileType)
	if signed {
		fmt.Println("Signed: Yes")
		os.Exit(0)
	} else {
		fmt.Println("Signed: No")
		os.Exit(1)
	}
}

func checkSignature(filename string) (bool, string, error) {
	// Try to open as PE (Windows) first
	if signed, err := checkPESignature(filename); err == nil {
		return signed, "Windows PE", nil
	}

	// Try to open as Mach-O (macOS)
	if signed, err := checkMachoSignature(filename); err == nil {
		return signed, "macOS Mach-O", nil
	}

	// Try as Fat Mach-O (universal binary)
	if signed, err := checkFatMachoSignature(filename); err == nil {
		return signed, "macOS Universal Binary", nil
	}

	return false, "Unknown", fmt.Errorf("unsupported file format")
}

// checkPESignature checks if a Windows PE file is signed
func checkPESignature(filename string) (bool, error) {
	pefile, err := pe.Open(filename)
	if err != nil {
		return false, err
	}
	defer pefile.Close()

	// Check for security directory in optional header
	var securityDir pe.DataDirectory
	
	switch oh := pefile.OptionalHeader.(type) {
	case *pe.OptionalHeader32:
		if len(oh.DataDirectory) > pe.IMAGE_DIRECTORY_ENTRY_SECURITY {
			securityDir = oh.DataDirectory[pe.IMAGE_DIRECTORY_ENTRY_SECURITY]
		}
	case *pe.OptionalHeader64:
		if len(oh.DataDirectory) > pe.IMAGE_DIRECTORY_ENTRY_SECURITY {
			securityDir = oh.DataDirectory[pe.IMAGE_DIRECTORY_ENTRY_SECURITY]
		}
	default:
		return false, fmt.Errorf("unsupported PE format")
	}

	// If security directory exists and has non-zero size, the file is signed
	return securityDir.Size > 0 && securityDir.VirtualAddress > 0, nil
}

// checkMachoSignature checks if a Mach-O file is signed
func checkMachoSignature(filename string) (bool, error) {
	machoFile, err := macho.Open(filename)
	if err != nil {
		return false, err
	}
	defer machoFile.Close()

	// Look for LC_CODE_SIGNATURE load command
	for _, load := range machoFile.Loads {
		if seg, ok := load.(*macho.Segment); ok {
			if seg.Name == "__LINKEDIT" {
				// Check for code signature by looking for LC_CODE_SIGNATURE command
				// This is indicated by the presence of a code signature in the binary
				return hasCodeSignature(machoFile), nil
			}
		}
	}

	return hasCodeSignature(machoFile), nil
}

// hasCodeSignature checks for LC_CODE_SIGNATURE load command
func hasCodeSignature(machoFile *macho.File) bool {
	// Check if the file has LC_CODE_SIGNATURE by examining load commands
	for _, load := range machoFile.Loads {
		// The Raw field contains the raw load command data
		if data, ok := load.(macho.LoadBytes); ok {
			// First 4 bytes are the command type
			if len(data) >= 4 {
				cmd := machoFile.ByteOrder.Uint32(data[0:4])
				const LC_CODE_SIGNATURE = 0x1d
				if cmd == LC_CODE_SIGNATURE {
					return true
				}
			}
		}
	}
	return false
}

// hasCodeSignatureFromFile checks for LC_CODE_SIGNATURE by reading file directly
func hasCodeSignatureFromFile(filename string) bool {
	f, err := os.Open(filename)
	if err != nil {
		return false
	}
	defer f.Close()

	// Read Mach-O header
	var magic uint32
	if err := binary.Read(f, binary.LittleEndian, &magic); err != nil {
		return false
	}

	// Check magic to determine byte order and architecture
	var byteOrder binary.ByteOrder
	var is64bit bool
	var ncmd uint32

	switch magic {
	case 0xfeedface: // 32-bit big endian
		byteOrder = binary.BigEndian
		is64bit = false
	case 0xcefaedfe: // 32-bit little endian
		byteOrder = binary.LittleEndian
		is64bit = false
	case 0xfeedfacf: // 64-bit big endian
		byteOrder = binary.BigEndian
		is64bit = true
	case 0xcffaedfe: // 64-bit little endian
		byteOrder = binary.LittleEndian
		is64bit = true
	default:
		return false
	}

	f.Seek(0, 0)

	// Read header to get ncmd
	if is64bit {
		// 64-bit header: magic(4) + cputype(4) + cpusubtype(4) + filetype(4) + ncmds(4)
		f.Seek(16, 0)
	} else {
		// 32-bit header: magic(4) + cputype(4) + cpusubtype(4) + filetype(4) + ncmds(4)
		f.Seek(16, 0)
	}
	if err := binary.Read(f, byteOrder, &ncmd); err != nil {
		return false
	}

	// Skip to load commands (after header)
	headerSize := 28
	if is64bit {
		headerSize = 32
	}
	f.Seek(int64(headerSize), 0)

	const LC_CODE_SIGNATURE = 0x1d

	// Iterate through load commands
	for i := uint32(0); i < ncmd; i++ {
		var cmd, cmdsize uint32
		if err := binary.Read(f, byteOrder, &cmd); err != nil {
			return false
		}
		if err := binary.Read(f, byteOrder, &cmdsize); err != nil {
			return false
		}

		if cmd == LC_CODE_SIGNATURE {
			return true
		}

		// Skip to next command
		if cmdsize < 8 {
			return false
		}
		f.Seek(int64(cmdsize-8), 1)
	}

	return false
}

// checkFatMachoSignature checks if a Fat Mach-O (universal binary) is signed
func checkFatMachoSignature(filename string) (bool, error) {
	fatFile, err := macho.OpenFat(filename)
	if err != nil {
		return false, err
	}
	defer fatFile.Close()

	// Check if any of the architectures are signed
	// For a universal binary to be considered signed, at least one arch should be signed
	for _, arch := range fatFile.Arches {
		if hasCodeSignature(arch.File) {
			return true, nil
		}
	}

	return false, nil
}
