rule Truncated_win10_x64_NativeSysCall {
meta: 
  description = "hunt of at least 3 occurences of truncated win10 x64 NativeSyscall" 
  author = "SBousseaden" 
  date = "2020-07-05" 
strings:
// mov r10,rcx
// mov eax,syscall#
// syscall
// ret
    $s1 = {(49 89 CA|4C 8B D1) B8 ?? 00 00 00 0F 05 C3} 
condition: uint16(0)==0x5a4d and #s1 > 3
}
