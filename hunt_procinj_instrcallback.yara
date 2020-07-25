rule hunt_procinj_instrumentationcallback {
meta:
 date = "25-07-2020"
 author = "SBousseaden"
 description = "hunt for possible injection with Instrumentation Callback PE"
 reference = "https://movaxbx.ru/2020/07/24/weaponizing-mapping-injection-with-instrumentation-callback-for-stealthier-process-injection/"
strings:
 $mv1 = "MapViewOfFile3" xor
 $mv2 = "MapViewOfFile3" wide xor
 $mv3 = "NtMapViewOfSectionEx" xor
 $mv4 = "NtMapViewOfSectionEx" wide xor
 $mv5 = {(49 89 CA|4C 8B D1) B8 0F 01 00 00 0F 05 C3} // NtMapViewOfSectionEx
 $spi1 = "NtSetInformationProcess" xor
 $spi2 = "NtSetInformationProcess" wide xor
 $spi3 = {(49 89 CA|4C 8B D1) B8 1C 00 00 00 0F 05 C3} // NtSetInformationProcess
 $picb = {BA 28 00 00 00} // PROCESS_INSTRUMENTATION_CALLBACK_INFORMATION
 $ss1 = {41 52 50 53 55 57 56 54 41 54 41 55 41 56 41 57}  // push stuff
 $ss2 = {41 5F 41 5E 41 5D 41 5C 5C 5E 5F 5D 5B 58 41 5A}  // pop stuff
 $ss3 = {49 89 CA 0F 05 C3} // mov r10, rcx syscall ret
condition: uint16(0)==0x5a4d and $picb and 1 of ($mv*) and 1 of ($spi*) and 1 of ($ss*)
}