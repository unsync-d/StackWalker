# Stack Layout Explorer

## Overview

This tool is a small PoC designed to play around and understand the stack layout in running processes, with an emphasis on gathering information from stack traces and investigating local variables. It operates on Windows systems, offering options to display detailed thread information, inspect specific thread stack traces, and analyze the memory layout of functions at runtime.

## Features

- Display stack traces for specific threads.
- Inspect local variables and function parameters within stack frames.
- Periodically refresh stack traces for dynamic analysis.
- Retrieve and list all threads for a given process (PID).
- Sort threads based on TID or start address.
- Resolve function names and module addresses using Microsoft Symbol Server.
- Dynamic symbol resolution for both function names and module addresses.

## Requirements

- Windows OS
- Visual Studio or other compatible C++ compiler
- DbgHelp.dll (comes with Windows SDK)
- Psapi.dll (for process and module information)

## Command Line Options

The tool accepts a variety of command-line options to control its behavior. Below is a breakdown of each option:
Options:

    -p <PID>
    (Required): Specifies the Process ID (PID) of the target process to investigate.

    -t <TID>
    Specifies a specific Thread ID (TID) to investigate. If this is provided, the tool will only focus on the specified thread.

    -m <n seconds>
    Set the interval (in seconds) to refresh the stack trace or thread list dynamically. Useful for observing changes in real time.

    -V
    Verbose output. Displays detailed module information, including the full path to the loaded modules.

    -oA
    Sort threads by their start address before printing them.

    -oI
    Sort threads by TID (Thread ID) before printing them.

## Example Usage:

### Display thread information for a specific process (PID):

```console
StackLayoutExplorer.exe -p 1234
```

### Show stack trace for a specific thread (TID):

```console
StackLayoutExplorer.exe -p 1234 -t 5678
```

### Periodically refresh stack trace every 5 seconds:

```console
StackLayoutExplorer.exe -p 1234 -t 5678 -m 5
```

### Verbose output with sorted thread list by start address:

```console
StackLayoutExplorer.exe -p 1234 -oA -V
```

## Assumptions 
Limitations and Notes
- This tool only works on Windows and assumes a 64-bit architecture (x64).
- The tool relies on Windows APIs and will need to run with appropriate permissions to access the target process and its threads.
- If symbols for functions are not available, the tool will attempt to resolve the closest matching information or show offsets relative to the module.
