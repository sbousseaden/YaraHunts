import "pe"
rule hunt_lsass_ntds_ext {
meta:
 author = "SBousseaden"
 description = "hunting rule for necessary exports in a DLL that can be abused for persistence or alike by loading it into lsass via NTDS registry"
 reference = "https://blog.xpnsec.com/exploring-mimikatz-part-1/"
// FPs can be excluded accordingly
condition: pe.exports("InitializeLsaDbExtension") or pe.exports("InitializeSamDsExtension") 
}
