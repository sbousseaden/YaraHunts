import "pe"

rule susp_msoffice_addins_wxll {
meta:
 author = "SBousseaden"
 date = "11/10/2020"
 description = "hunt for suspicious MS Office Addins with code injection capabilities"
 reference = "https://twitter.com/JohnLaTwC/status/1315287078855352326"
strings:
 $inj1 = "WriteProcessMemory"
 $inj2 = "NtWriteVirtualMemory"
 $inj3 = "RtlMoveMemory"
 $inj4 = "VirtualAllocEx"
 $inj5 = "NtAllocateVirtualMemory" 
 $inj6 = "NtUnmapViewOfSection"
 $inj7 = "VirtualProtect"
 $inj8 = "NtProtectVirtualMemory"
 $inj9 = "SetThreadContext"
 $inj10 = "NtSetContextThread"
 $inj11 = "ResumeThread"
 $inj12 = "NtResumeThread"
 $inj13 = "QueueUserAPC"
 $inj14 = "NtQueueApcThread"
 $inj15 = "NtQueueApcThreadEx"
 $inj16 = "CreateRemoteThread"
 $inj17 = "NtCreateThreadEx"
 $inj18 = "RtlCreateUserThread"
condition: uint16(0) == 0x5a4d and (pe.exports("wlAutoOpen") or pe.exports("xlAutoOpen")) and 3 of ($inj*)
}
