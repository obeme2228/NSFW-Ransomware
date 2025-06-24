rule ReflectiveDLL_Injection_and_PrintSpooler_Exploits {
    meta:
        author = "Q/AP3X"
        description = "Detects reflective DLL injection and print spooler CVE exploitation artifacts"
        date = "2025-06-23"
        version = "1.0"

    strings:
        $dll_ext = ".dll"
        $unsigned = "Unsigned"
        $virtualalloc = "VirtualAlloc"
        $writeprocessmemory = "WriteProcessMemory"
        $createremotethread = "CreateRemoteThread"
        $spoolsv = "spoolsv"
        $rpcaddprinter = "RpcAddPrinterDriverEx"
        $sam = "SAM"
        $system = "SYSTEM"
        $security = "SECURITY"
        $icacls = "icacls"
        $takeown = "takeown"
        $spool_drivers = "\\spool\\drivers"

    condition:
        (any of ($dll_ext, $unsigned) and any of ($virtualalloc, $writeprocessmemory, $createremotethread)) or
        any of ($spoolsv, $rpcaddprinter) or
        any of ($sam, $system, $security) or
        (any of ($icacls, $takeown) and $spool_drivers)
}
