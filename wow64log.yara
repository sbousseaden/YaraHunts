import "pe"

rule hunt_dllhijack_wow64log {
meta:
 description = "broad hunt for non MS wow64log module"
 author = "SBousseaden"
 reference = "http://waleedassar.blogspot.com/2013/01/wow64logdll.html"
 date = "2020-06-5"
condition: uint16(0)==0x5a4d and (pe.exports("Wow64LogInitialize") or 
 pe.exports("Wow64LogMessageArgList") or 
 pe.exports("Wow64LogSystemService") or 
 pe.exports("Wow64LogTerminate")) 
}