rule shad0w_LdrLoadDll_hook { 
meta: 
  description = "Shad0w beacon LdrLoadDll hook" 
  author = "SBousseaden" 
  reference = "https://github.com/bats3c/shad0w" 
  date = "2020-06-06" 
strings:
  $s1 = "LdrLoadD"
  $s2 = "SetPr"
  $s3 = "Policy"
  $s4 = {B8 49 BB DE AD C0} // LdrLoadDll hook
condition: uint16(0) == 0x5a4d and all of ($s*)  
}
