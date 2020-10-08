import "pe"
rule tez {
meta:
 author = "SBousseaden"
 description = "hunting rule for necessary exports in a DLL that can be abused for persistence or alike by loading it into lsass via NTDS registry"
 reference = "https://blog.xpnsec.com/exploring-mimikatz-part-1/"
condition: pe.exports("InitializeLsaDbExtension") or pe.exports("InitializeSamDsExtension") // uint16(0) == 0x5a4d and any of ($s*) and not any of ($fp*)
}