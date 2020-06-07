import "pe"

rule MaliciousDLLGenerator { 
meta: 
  description = "MaliciousDLLGenerator default decoder and export name" 
  author = "SBousseaden" 
  reference = "https://github.com/Mr-Un1k0d3r/MaliciousDLLGenerator" 
  date = "2020-06-07" 
strings:
  $decoder = {E8 00 00 00 00 5B 48 31 C0 48 89 C1 B1 80 48 83 C3 11 48 F7 14 CB E2 FA 48 83 C3 08 53 C3} // decoder
condition: uint16(0) == 0x5a4d and $decoder and pe.exports("Init") and pe.number_of_exports == 2
}















