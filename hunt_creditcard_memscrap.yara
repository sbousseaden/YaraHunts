rule hunt_common_credit_card_memscrapper {
meta:
 description = "Hunting rule for possible CC data memory scrapper"
 author = "SBousseaden"
 date = "17/07/2020"
strings:
 $api1 = "NtOpenProcess"
 $api2 = "NtQueryVirtualMemory"
 $api3 = "NtReadVirtualMemory"
// https://stackoverflow.com/questions/9315647/regex-credit-card-number-tests
 $cc1 = "^3[47][0-9]{13}$" // Amex Card
 $cc2 = "^(6541|6556)[0-9]{12}$" // BCGlobal
 $cc3 = "^389[0-9]{11}$" // Carte Blanche Card
 $cc4 = "^3(?:0[0-5]|[68][0-9])[0-9]{11}$" //Diners Club Card
 $cc5 = "^65[4-9][0-9]{13}|64[4-9][0-9]{13}|6011[0-9]{12}|(622(?:12[6-9]|1[3-9][0-9]|[2-8][0-9][0-9]|9[01][0-9]|92[0-5])[0-9]{10})$" //Discover Card
 $cc6 = "^63[7-9][0-9]{13}$" // Insta Payment Card
 $cc7 = "^(?:2131|1800|35\\d{3})\\d{11}$" // JCB Card
 $cc8 = "^9[0-9]{15}$" // KoreanLocalCard
 $cc9 = "^(6304|6706|6709|6771)[0-9]{12,15}$" //Laser Card
 $cc10 = "^(5018|5020|5038|6304|6759|6761|6763)[0-9]{8,15}$" // Maestro Card
 $cc11 = "^(5[1-5][0-9]{14}|2(22[1-9][0-9]{12}|2[3-9][0-9]{13}|[3-6][0-9]{14}|7[0-1][0-9]{13}|720[0-9]{12}))$" //Mastercard
 $cc12 = "^(6334|6767)[0-9]{12}|(6334|6767)[0-9]{14}|(6334|6767)[0-9]{15}$" //Solo Card
 $cc13 = "^(4903|4905|4911|4936|6333|6759)[0-9]{12}|(4903|4905|4911|4936|6333|6759)[0-9]{14}|(4903|4905|4911|4936|6333|6759)[0-9]{15}|564182[0-9]{10}|564182[0-9]{12}|564182[0-9]{13}|633110[0-9]{10}|633110[0-9]{12}|633110[0-9]{13}$" //Switch Card
 $cc14 = "^(62[0-9]{14,17})$" //Union Pay Card
 $cc15 = "^4[0-9]{12}(?:[0-9]{3})?$" //Visa Card
 $cc16 = "^(?:4[0-9]{12}(?:[0-9]{3})?|5[1-5][0-9]{14})$" //Visa Master Card
condition: uint16(0) == 0x5a4d and 1 of ($cc*) and all of ($api*)
}