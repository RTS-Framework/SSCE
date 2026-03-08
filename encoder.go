package ssce

import (
	"bytes"
	cr "crypto/rand"
	"encoding/binary"
	"errors"
	"fmt"
	"maps"
	"math"
	"math/rand"
	"slices"
	"strings"
	"text/template"
	"time"

	"github.com/For-ACGN/go-keystone"
)

var (
	registerX86 = []string{
		"eax", "ebx", "ecx", "edx",
		"ebp", "esi", "edi",
	}

	registerX64 = []string{
		"rax", "rbx", "rcx", "rdx",
		"rbp", "rsi", "rdi",
	}
)

// Encoder is a simple shellcode encoder.
type Encoder struct {
	rand *rand.Rand

	// assembler engine
	ase32 *keystone.Engine
	ase64 *keystone.Engine

	// context arguments
	arch int
	opts *Options
	key  []byte

	// stub key for xor stubs
	stubKey any

	// save and restore context
	contextSeq []int

	// for select random register
	regBox []string
}

// Options contains options about encode shellcode.
type Options struct {
	// the number of iterate.
	NumIterate int `toml:"num_iterate" json:"num_iterate"`

	// the size of the garbage instruction at tail.
	NumTailInst int `toml:"num_tail_inst" json:"num_tail_inst"`

	// only use the mini loader, not use loader
	// for erase shellcode and more feature.
	MinifyMode bool `toml:"minify_mode" json:"minify_mode"`

	// save and restore context after call shellcode.
	SaveContext bool `toml:"save_context" json:"save_context"`

	// erase loader instruction and shellcode after call it.
	EraseInst bool `toml:"erase_inst" json:"erase_inst"`

	// disable iterator, not recommend.
	NoIterator bool `toml:"no_iterator" json:"no_iterator"`

	// disable garbage instruction, not recommend.
	NoGarbage bool `toml:"no_garbage" json:"no_garbage"`

	// specify a random seed for encoder.
	RandSeed int64 `toml:"rand_seed" json:"rand_seed"`

	// trim the seed at the tail of output.
	TrimSeed bool `toml:"trim_seed" json:"trim_seed"`

	// specify the x86 mini decoder template.
	MiniDecoderX86 string `toml:"mini_decoder_x86" json:"mini_decoder_x86"`

	// specify the x64 mini decoder template.
	MiniDecoderX64 string `toml:"mini_decoder_x64" json:"mini_decoder_x64"`

	// specify the x86 loader template.
	LoaderX86 string `toml:"loader_x86" json:"loader_x86"`

	// specify the x64 loader template.
	LoaderX64 string `toml:"loader_x64" json:"loader_x64"`

	// specify the x86 junk code templates.
	JunkCodeX86 []string `toml:"junk_code_x86" json:"junk_code_x86"`

	// specify the x64 junk code templates.
	JunkCodeX64 []string `toml:"junk_code_x64" json:"junk_code_x64"`
}

// Context contains the output and context data in Encode.
type Context struct {
	Output      []byte `json:"output"`
	Seed        int64  `json:"seed"`
	NumIterate  int    `json:"num_iterate"`
	MinifyMode  bool   `json:"minify_mode"`
	NoGarbage   bool   `json:"no_garbage"`
	SaveContext bool   `json:"save_context"`
	EraseInst   bool   `json:"erase_inst"`
}

// NewEncoder is used to create a simple shellcode encoder.
func NewEncoder() *Encoder {
	var seed int64
	buf := make([]byte, 8)
	_, err := cr.Read(buf)
	if err == nil {
		seed = int64(binary.LittleEndian.Uint64(buf)) // #nosec G115
	} else {
		seed = time.Now().UTC().UnixNano()
	}
	encoder := Encoder{
		rand: rand.New(rand.NewSource(seed)), // #nosec
	}
	return &encoder
}

// Encode is used to encode input shellcode to a unique shellcode.
func (e *Encoder) Encode(shellcode []byte, arch int, opts *Options) (ctx *Context, err error) {
	defer func() {
		if r := recover(); r != nil {
			err = errors.New(fmt.Sprint(r))
		}
	}()
	if len(shellcode) == 0 {
		return nil, errors.New("empty shellcode")
	}
	switch arch {
	case 32, 64:
	default:
		return nil, fmt.Errorf("unsupported architecture: %d", arch)
	}
	if opts == nil {
		opts = new(Options)
	}
	e.arch = arch
	e.opts = opts
	// initialize keystone engine
	err = e.initAssembler()
	if err != nil {
		return nil, fmt.Errorf("failed to initialize assembler: %s", err)
	}
	// set random seed
	seed := opts.RandSeed
	if seed == 0 {
		seed = e.rand.Int63()
	}
	e.rand.Seed(seed)
	// encode the raw shellcode and add loader
	output, err := e.addLoader(shellcode)
	if err != nil {
		return nil, err
	}
	// insert mini decoder at the prefix
	output, err = e.addMiniDecoder(output)
	if err != nil {
		return nil, err
	}
	// iterate the encoding of the pre-decoder and part of the shellcode
	numIter := opts.NumIterate
	if numIter < 1 {
		numIter = 2 + e.rand.Intn(4)
	}
	if opts.NoIterator {
		numIter = 0
	}
	for i := 0; i < numIter; i++ {
		output, err = e.addMiniDecoder(output)
		if err != nil {
			return nil, err
		}
	}
	// padding garbage at the tail
	if !opts.NoGarbage {
		times := 8 + e.rand.Intn((numIter+1)*4)
		size := e.rand.Intn(16 * times)
		output = append(output, e.randBytes(size)...)
	}
	// append garbage data to tail for prevent brute-force
	output = append(output, e.randBytes(opts.NumTailInst)...)
	// append garbage data to the output shellcode prefix
	output = append(e.garbageInst(), output...)
	// append the random seed to tail
	if !opts.TrimSeed {
		buf := binary.BigEndian.AppendUint64(nil, uint64(seed)) // #nosec G115
		output = append(output, buf...)
	}
	// build encode context for test and debug
	ctx = &Context{
		Output:      output,
		Seed:        seed,
		NumIterate:  numIter,
		MinifyMode:  opts.MinifyMode,
		NoGarbage:   opts.NoGarbage,
		SaveContext: opts.SaveContext,
		EraseInst:   opts.EraseInst,
	}
	return ctx, nil
}

func (e *Encoder) initAssembler() error {
	var (
		ase *keystone.Engine
		err error
	)
	switch e.arch {
	case 32:
		if e.ase32 != nil {
			return nil
		}
		ase, err = keystone.NewEngine(keystone.ARCH_X86, keystone.MODE_32)
		if err != nil {
			return err
		}
		e.ase32 = ase
	case 64:
		if e.ase64 != nil {
			return nil
		}
		ase, err = keystone.NewEngine(keystone.ARCH_X86, keystone.MODE_64)
		if err != nil {
			return err
		}
		e.ase64 = ase
	default:
		panic("unreachable code")
	}
	return ase.Option(keystone.OPT_SYNTAX, keystone.OPT_SYNTAX_INTEL)
}

func (e *Encoder) assemble(src string) ([]byte, error) {
	if strings.Contains(src, "<no value>") {
		return nil, errors.New("invalid register in assembly source")
	}
	if strings.Contains(src, "<nil>") {
		return nil, errors.New("invalid usage in assembly source")
	}
	switch e.arch {
	case 32:
		return e.ase32.Assemble(src, 0)
	case 64:
		return e.ase64.Assemble(src, 0)
	default:
		panic("unreachable code")
	}
}

func (e *Encoder) addLoader(shellcode []byte) ([]byte, error) {
	if e.opts.MinifyMode {
		return shellcode, nil
	}
	var loader string
	switch e.arch {
	case 32:
		loader = e.getLoaderX86()
	case 64:
		loader = e.getLoaderX64()
	}
	asm, sc, err := e.buildLoader(loader, shellcode)
	if err != nil {
		return nil, err
	}
	inst, err := e.assemble(asm)
	if err != nil {
		return nil, err
	}
	return append(inst, sc...), nil
}

func (e *Encoder) buildLoader(loader string, shellcode []byte) (string, []byte, error) {
	// append instructions for "IV" about encoder
	shellcode = append(e.garbageInst(), shellcode...)
	// append instructions to tail for prevent brute-force
	tail := e.randBytes(64 + len(shellcode)/40)
	shellcode = append(shellcode, tail...)
	// generate crypto key for shellcode decoder
	cryptoKey := e.randBytes(32)
	var (
		stubKey   any
		eraserLen int
	)
	switch e.arch {
	case 32:
		stubKey = e.rand.Uint32()
		eraserLen = len(eraserX86) + e.rand.Intn(len(cryptoKey))
		shellcode = encrypt32(shellcode, cryptoKey)
	case 64:
		stubKey = e.rand.Uint64()
		eraserLen = len(eraserX64) + e.rand.Intn(len(cryptoKey))
		shellcode = encrypt64(shellcode, cryptoKey)
	}
	e.key = cryptoKey
	e.stubKey = stubKey
	// parse loader template
	tpl, err := template.New("loader").Funcs(template.FuncMap{
		"db":  toDB,
		"hex": toHex,
		"igi": e.insertGarbageInst,
	}).Parse(loader)
	if err != nil {
		return "", nil, fmt.Errorf("invalid assembly source template: %s", err)
	}
	ctx := loaderCtx{
		StubKey:        stubKey,
		DecoderStub:    e.decoderStub(),
		EraserStub:     e.eraserStub(),
		CryptoKeyStub:  e.cryptoKeyStub(),
		CryptoKeyLen:   len(cryptoKey),
		ShellcodeLen:   len(shellcode),
		EraserLen:      eraserLen,
		EraseShellcode: e.opts.EraseInst,
	}
	if e.opts.SaveContext {
		ctx.SaveContext = e.saveContext()
		ctx.RestoreContext = e.restoreContext()
	}
	// build source from template and assemble it
	buf := bytes.NewBuffer(make([]byte, 0, 4096))
	err = tpl.Execute(buf, &ctx)
	if err != nil {
		return "", nil, fmt.Errorf("failed to build assembly source: %s", err)
	}
	return buf.String(), shellcode, nil
}

func (e *Encoder) addMiniDecoder(input []byte) ([]byte, error) {
	var miniDecoder string
	switch e.arch {
	case 32:
		miniDecoder = e.getMiniDecoderX86()
	case 64:
		miniDecoder = e.getMiniDecoderX64()
	}
	asm, body, err := e.buildMiniDecoder(miniDecoder, input)
	if err != nil {
		return nil, err
	}
	inst, err := e.assemble(asm)
	if err != nil {
		return nil, err
	}
	return append(inst, body...), nil
}

func (e *Encoder) buildMiniDecoder(decoder string, input []byte) (string, []byte, error) {
	// parse mini decoder template
	tpl, err := template.New("mini_decoder").Funcs(template.FuncMap{
		"db":  toDB,
		"hex": toHex,
		"igi": e.insertGarbageInst,
		"igs": e.insertGarbageInstShort,
	}).Parse(decoder)
	if err != nil {
		return "", nil, fmt.Errorf("invalid assembly source template: %s", err)
	}
	seed := e.rand.Uint32()
	key := e.rand.Uint32()
	body := e.xsrl(input, seed, key)
	numLoopMaskA := e.rand.Int31()
	numLoopMaskB := e.rand.Int31()
	numLoopStub := int32(len(body)/4) ^ numLoopMaskA ^ numLoopMaskB // #nosec G115
	offsetT := e.rand.Int31n(math.MaxInt32/4 - 4096)
	offsetA := e.rand.Int31n(math.MaxInt32/4 - 8192)
	offsetS := offsetT + offsetA
	ctx := miniDecoderCtx{
		Seed: seed,
		Key:  key,

		NumLoopStub:  numLoopStub,
		NumLoopMaskA: numLoopMaskA,
		NumLoopMaskB: numLoopMaskB,

		OffsetT: offsetT,
		OffsetA: offsetA,
		OffsetS: offsetS,

		Reg: e.buildRandomRegisterMap(),
	}
	// add padding data at tail of mini decoder
	if !e.opts.MinifyMode {
		ctx.Padding = true
		ctx.PadData = e.randBytes(8 + e.rand.Intn(48))
	}
	// build source from template and assemble it
	buf := bytes.NewBuffer(make([]byte, 0, 512))
	err = tpl.Execute(buf, &ctx)
	if err != nil {
		return "", nil, fmt.Errorf("failed to build assembly source: %s", err)
	}
	return buf.String(), body, nil
}

func (e *Encoder) getMiniDecoderX86() string {
	if e.opts.MiniDecoderX86 != "" {
		return e.opts.MiniDecoderX86
	}
	return defaultMiniDecoderX86
}

func (e *Encoder) getMiniDecoderX64() string {
	if e.opts.MiniDecoderX64 != "" {
		return e.opts.MiniDecoderX64
	}
	return defaultMiniDecoderX64
}

func (e *Encoder) getLoaderX86() string {
	if e.opts.LoaderX86 != "" {
		return e.opts.LoaderX86
	}
	return defaultLoaderX86
}

func (e *Encoder) getLoaderX64() string {
	if e.opts.LoaderX64 != "" {
		return e.opts.LoaderX64
	}
	return defaultLoaderX64
}

func (e *Encoder) randBytes(n int) []byte {
	buf := make([]byte, n)
	_, _ = e.rand.Read(buf)
	return buf
}

func (e *Encoder) buildRandomRegisterMap() map[string]string {
	var reg []string
	switch e.arch {
	case 32:
		reg = slices.Clone(registerX86)
	case 64:
		reg = slices.Clone(registerX64)
	}
	e.regBox = reg
	register := make(map[string]string, 16)
	switch e.arch {
	case 32:
		for _, reg := range registerX86 {
			register[reg] = e.selectRegister()
		}
	case 64:
		for _, reg := range registerX64 {
			register[reg] = e.selectRegister()
		}
		e.buildLowBitRegisterMap(register)
	}
	return register
}

func (e *Encoder) buildLowBitRegisterMap(register map[string]string) {
	// build register map about low dword
	low := make(map[string]string, len(register))
	for reg, act := range register {
		low[toRegDWORD(reg)] = toRegDWORD(act)
	}
	maps.Copy(register, low)
}

// selectRegister is used to make sure each register will be selected once.
func (e *Encoder) selectRegister() string {
	idx := e.rand.Intn(len(e.regBox))
	reg := e.regBox[idx]
	// remove selected register
	e.regBox = append(e.regBox[:idx], e.regBox[idx+1:]...)
	return reg
}

func (e *Encoder) insertGarbageInst() string {
	if e.opts.NoGarbage {
		return ""
	}
	return ";" + toDB(e.garbageInst())
}

func (e *Encoder) insertGarbageInstShort() string {
	if e.opts.NoGarbage {
		return ""
	}
	return ";" + toDB(e.garbageInstShort())
}

// Close is used to close shellcode encoder.
func (e *Encoder) Close() error {
	if e.ase32 != nil {
		err := e.ase32.Close()
		if err != nil {
			return err
		}
	}
	if e.ase64 != nil {
		err := e.ase64.Close()
		if err != nil {
			return err
		}
	}
	return nil
}
