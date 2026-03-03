.code32

jmp next

{{if .Switch.A}}
push {{.Reg.ecx}}
{{end}}

{{if .Switch.B}}
xor {{.Reg.esi}}, {{.Reg.ecx}}
{{end}}

{{if .Switch.C}}
xor {{.Reg.edx}}, {{.DWORD.D}}
{{end}}

{{if .Switch.D}}
mov {{.Reg.edi}}, {{.WORD.E}}
{{end}}

{{if .Switch.E}}
ror {{.Reg.ecx}}, {{.Less32.A}}
{{end}}

{{if .Switch.F}}
rol {{.Reg.ebx}}, {{.Less32.B}}
{{end}}

{{if .Switch.G}}
xor {{.Reg.eax}}, {{.Reg.edi}}
{{end}}

{{if .Switch.H}}
mov {{.Reg.eax}}, {{.Reg.ebx}}
{{end}}

{{if .Switch.I}}
push {{.Reg.edi}}
{{end}}

{{if .Switch.J}}
sub {{.Reg.ebp}}, {{.WORD.E}}
{{end}}

next:
