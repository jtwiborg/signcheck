# signcheck

A cross-platform tool to check if Windows PE or macOS Mach-O binary files are signed.

## Features

- Checks Windows PE files (.exe, .dll) for Authenticode signatures
- Checks macOS Mach-O binaries for code signatures
- Supports macOS Universal (Fat) binaries
- Returns appropriate exit codes for scripting

## Building

Run the build script to compile for all platforms:

```bash
./build.sh
```

This will generate binaries for:
- Windows (amd64, arm64)
- macOS (amd64, arm64)
- Linux (amd64, arm64)

Output files follow the pattern: `signcheck-<os>-<arch>`

## Usage

```bash
signcheck-<os>-<arch> <binary-file>
```

### Example

```bash
# Check if a macOS binary is signed
./signcheck-macos-arm64 /bin/ls

# Check if a Windows executable is signed
./signcheck-windows-amd64.exe example.exe
```

## Output

The tool displays:
- File path
- File size in bytes
- Binary type (Windows PE, macOS Mach-O, or macOS Universal Binary)
- Signature status (Yes/No)

### Exit Codes

- `0` - Binary is signed
- `1` - Binary is not signed
- `2` - Error (file not found, unsupported format, etc.)

## Example Output

```
File: /bin/ls
Size: 154624 bytes
Type: macOS Universal Binary
Signed: Yes
```

## Notes

- On macOS, Go binaries compiled locally may have ad-hoc signatures by default
- The tool runs on any platform but can only analyze Windows PE and macOS Mach-O files
- Windows PE signature checking validates the presence of the security directory
- macOS signature checking looks for the LC_CODE_SIGNATURE load command
