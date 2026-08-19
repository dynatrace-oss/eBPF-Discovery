# Delayed VM Detection (DVM)

DVM detects when a managed-runtime library (JVM, .NET CLR) is loaded into a process and reports the event to stdout as a JSON record.

---

## Enabling

```
ebpfdiscoverysrv --enable-dvm [--dvm-interval <seconds>]
```

| Flag | Type | Default | Description |
|------|------|---------|-------------|
| `--enable-dvm` | bool | `false` | Enable DVM detection |
| `--dvm-interval` | int (seconds) | `60` | How often to flush collected events to stdout |

---

## Kernel Event — `DvmEvent`

Defined in `libebpfdiscoveryshared/headers/ebpfdiscoveryshared/DvmTypes.h`.

Emitted by the BPF program through a ring buffer each time a tracked library is loaded into a process.

```c
struct DvmEvent {
    __u64 loadTimeNs;  // library load timestamp — monotonic ns (bpf_ktime_get_ns)
    __u32 pid;         // PID of the process that performed the load
    __u32 libraryType; // one of DvmLibraryType
};
```

### `DvmLibraryType`

```c
enum DvmLibraryType : __u32 {
    DVM_LIBRARY_TYPE_UNKNOWN = 0,
    DVM_LIBRARY_TYPE_JVM     = 1,   // e.g. libjvm.so
    DVM_LIBRARY_TYPE_DOTNET  = 2,   // e.g. libcoreclr.so
};
```

> **Stable ABI.** Numeric values appear verbatim in the JSON output. Do not renumber existing entries; add new runtimes at the end.

---

## Userspace Struct — `DvmLibraryLoad`

Defined in `libebpfdiscovery/headers/ebpfdiscovery/Dvm.h`.

The userspace representation produced from a `DvmEvent`. `loadTimeNs` is converted to clock ticks via `nsToTicks()` (same convention as SLP's `startTs`).

```cpp
struct DvmLibraryLoad {
    pid_t    pid{};         // PID of the loading process
    uint32_t libraryType{}; // DvmLibraryType value
    uint64_t loadTs{};      // load time in clock ticks (/proc clock, SC_CLK_TCK)
};
```

---

## JSON Output Format

Records are written to **stdout**, one JSON object per flush interval. Nothing is written if no events were collected in the interval.

### Schema

```json
{
  "libraryLoads": [
    {
      "pid":         <number>,
      "libraryType": <number>,
      "loadTs":      <number>
    }
  ]
}
```

| Field | Type | Description |
|-------|------|-------------|
| `pid` | integer | PID of the process that loaded the library |
| `libraryType` | integer | Runtime kind — see `DvmLibraryType` table below |
| `loadTs` | integer | Load timestamp in clock ticks (`SC_CLK_TCK` units, same as SLP) |

### `libraryType` values

| Value | Constant | Runtime |
|-------|----------|---------|
| `1` | `DVM_LIBRARY_TYPE_JVM` | Java Virtual Machine (e.g. `libjvm.so`) |
| `2` | `DVM_LIBRARY_TYPE_DOTNET` | .NET CLR (e.g. `libcoreclr.so`) |

### Example

```json
{"libraryLoads":[{"pid":1234,"libraryType":1,"loadTs":4387621},{"pid":5678,"libraryType":2,"loadTs":4387799}]}
```

---

## Implementation Notes

- Follows the `SlpDetectionTask` pattern: `DvmDetectionTask` owns a `Dvm` instance and drives it on a periodic async task.
- The BPF program hooks `kprobe/vfs_open` for library detection and `tracepoint/sched/sched_process_exit` to clean up deduplication state when a process exits.
- Deduplication is per `(pid, libraryId)` — each distinct library file is reported once per process lifetime.
- Shared types (`DvmEvent`, `DvmLibraryType`) live in `libebpfdiscoveryshared` so they are accessible from both BPF C code and userspace C++.

---

## File Map

| Path | Purpose |
|------|---------|
| `libebpfdiscoveryshared/headers/ebpfdiscoveryshared/DvmTypes.h` | Kernel/userspace shared types: `DvmEvent`, `DvmLibraryType` |
| `libebpfdiscoveryskel/src/dvm.bpf.c` | BPF program (`kprobe/vfs_open`, `sched_process_exit`) |
| `libebpfdiscovery/headers/ebpfdiscovery/Dvm.h` | Userspace detection class and `DvmLibraryLoad` struct |
| `libebpfdiscovery/src/Dvm.cpp` | Detection logic and JSON serialisation |
| `libebpfdiscovery/headers/ebpfdiscovery/DvmDetectionTask.h` | Async task wrapper |
| `libebpfdiscovery/src/DvmDetectionTask.cpp` | Async task implementation |
| `ebpfdiscoverysrv/src/main.cpp` | CLI flag wiring (`--enable-dvm`, `--dvm-interval`) |
