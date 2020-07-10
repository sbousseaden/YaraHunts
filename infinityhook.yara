rule Infinityhook {

meta:
  author = "SBousseaden"
  date = "09/07/2020"
  reference = "https://github.com/everdox/InfinityHook"
  description = "Infinityhook is a legit research PoC to hook NT Syscalls bypassing PatchGuard"

strings:
  $EtwpDebuggerPattern = {00 2C 08 04 38 0C 00}
  $SMV = {00 00 76 66 81 3A 02 18 50 00 75 0E 48 83 EA 08 B8 33 0F 00}
  $KVASCODE = {4B 56 41 53 43 4F 44 45} // migh look for xor and base64
  $CKL = "Circular Kernel Context Logger" wide nocase
  
condition: uint16(0) == 0x5a4d and all of them

}
