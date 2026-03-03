.code64

jmp next

{{if .Switch.A}}
push {{.Reg.rcx}}
{{end}}

{{if .Switch.B}}
xor {{.Reg.rsi}}, {{.Reg.rcx}}
{{end}}

{{if .Switch.C}}
xor {{.Reg.rdx}}, {{.DWORD.D}}
{{end}}

{{if .Switch.D}}
mov {{.Reg.rdi}}, {{.WORD.E}}
{{end}}

{{if .Switch.E}}
ror {{.Reg.rcx}}, {{.Less32.A}}
{{end}}

{{if .Switch.F}}
rol {{.Reg.rbx}}, {{.Less32.B}}
{{end}}

{{if .Switch.G}}
xor {{.Reg.rax}}, {{.Reg.rdi}}
{{end}}

{{if .Switch.H}}
mov {{.Reg.rax}}, {{.Reg.rbx}}
{{end}}

{{if .Switch.I}}
push {{.Reg.rdi}}
{{end}}

{{if .Switch.J}}
mov {{.Reg.rbp}}, {{.QWORD.E}}
{{end}}

{{if .Switch.K}}
sub {{.Reg.rbp}}, {{.DWORD.A}}
{{end}}

next:
