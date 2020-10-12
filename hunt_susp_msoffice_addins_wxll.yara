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
 $inj6 = "VirtualProtect"
 $inj7 = "NtProtectVirtualMemory"
 $inj8 = "SetThreadContext"
 $inj9 = "NtSetContextThread"
 $inj10 = "ResumeThread"
 $inj11 = "NtResumeThread"
 $inj12 = "QueueUserAPC"
 $inj13 = "NtQueueApcThread"
 $inj14 = "NtQueueApcThreadEx"
 $inj15 = "CreateRemoteThread"
 $inj16 = "NtCreateThreadEx"
 $inj17 = "RtlCreateUserThread"
condition: uint16(0) == 0x5a4d and (pe.exports("wlAutoOpen") or pe.exports("xlAutoOpen")) and 3 of ($inj*)
}
