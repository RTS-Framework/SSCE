package ssce

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"runtime"
	"testing"
	"unsafe"

	"github.com/For-ACGN/go-keystone"
	"github.com/davecgh/go-spew/spew"
	"github.com/stretchr/testify/require"
)

func TestEncoder(t *testing.T) {
	encoder := NewEncoder()

	t.Run("x86", func(t *testing.T) {
		asm := ".code32\n"
		asm += "mov eax, dword ptr [esp+4]\n"
		asm += "mov dword ptr [eax], 0x86\n"
		asm += "mov eax, 0x86\n"
		asm += "ret\n"
		engine, err := keystone.NewEngine(keystone.ARCH_X86, keystone.MODE_32)
		require.NoError(t, err)
		shellcode, err := engine.Assemble(asm, 0)
		require.NoError(t, err)
		err = engine.Close()
		require.NoError(t, err)

		opts := &Options{
			EraseInst:  true,
			NoIterator: true,
			NoGarbage:  true,
		}
		ctx, err := encoder.Encode(shellcode, 32, opts)
		require.NoError(t, err)
		spew.Dump(ctx)

		num := bytes.Count(ctx.Output, []byte{0x00, 0x00, 0x00})
		require.Less(t, num, 2)
		num = bytes.Count(ctx.Output, []byte{0xFF, 0xFF, 0xFF})
		require.Less(t, num, 1)

		if runtime.GOOS != "windows" || runtime.GOARCH != "386" {
			return
		}
		addr := loadShellcode(t, ctx.Output)
		var val int
		ret, _, _ := syscallN(addr, (uintptr)(unsafe.Pointer(&val)))
		require.Equal(t, 0x86, int(ret))
		require.Equal(t, 0x86, val)

		// check shellcode is erased
		sc := unsafe.Slice((*byte)(unsafe.Pointer(addr)), len(ctx.Output))
		require.False(t, bytes.Contains(sc, shellcode))

		spew.Dump(sc)
		num = bytes.Count(sc, []byte{0x00, 0x00, 0x00})
		require.Less(t, num, 2)
		num = bytes.Count(sc, []byte{0xFF, 0xFF, 0xFF})
		require.Less(t, num, 1)
	})

	t.Run("x64", func(t *testing.T) {
		asm := ".code64\n"
		asm += "mov qword ptr [rcx], 0x64\n"
		asm += "mov rax, 0x64\n"
		asm += "ret\n"
		engine, err := keystone.NewEngine(keystone.ARCH_X86, keystone.MODE_64)
		require.NoError(t, err)
		shellcode, err := engine.Assemble(asm, 0)
		require.NoError(t, err)
		err = engine.Close()
		require.NoError(t, err)

		opts := &Options{
			EraseInst:  true,
			NoIterator: true,
			NoGarbage:  true,
		}
		ctx, err := encoder.Encode(shellcode, 64, opts)
		require.NoError(t, err)
		spew.Dump(ctx)

		testFindSignature(t, ctx.Output)

		if runtime.GOOS != "windows" || runtime.GOARCH != "amd64" {
			return
		}
		addr := loadShellcode(t, ctx.Output)
		var val int
		ret, _, _ := syscallN(addr, (uintptr)(unsafe.Pointer(&val)))
		require.Equal(t, 0x64, int(ret))
		require.Equal(t, 0x64, val)

		// check shellcode is erased
		sc := unsafe.Slice((*byte)(unsafe.Pointer(addr)), len(ctx.Output))
		require.False(t, bytes.Contains(sc, shellcode))
		testFindSignature(t, sc)
	})

	t.Run("invalid arch", func(t *testing.T) {
		shellcode := []byte{0x90}
		ctx, err := encoder.Encode(shellcode, 123, nil)
		require.EqualError(t, err, "unsupported architecture: 123")
		require.Nil(t, ctx)
	})

	err := encoder.Close()
	require.NoError(t, err)
}

func TestMinifyMode(t *testing.T) {
	encoder := NewEncoder()

	t.Run("x86", func(t *testing.T) {
		asm := ".code32\n"
		asm += "mov eax, dword ptr [esp+4]\n"
		asm += "mov dword ptr [eax], 0x86\n"
		asm += "mov eax, 0x86\n"
		asm += "ret\n"
		engine, err := keystone.NewEngine(keystone.ARCH_X86, keystone.MODE_32)
		require.NoError(t, err)
		shellcode, err := engine.Assemble(asm, 0)
		require.NoError(t, err)
		err = engine.Close()
		require.NoError(t, err)

		opts := &Options{
			MinifyMode: true,
			NoIterator: true,
			NoGarbage:  true,
		}
		ctx, err := encoder.Encode(shellcode, 32, opts)
		require.NoError(t, err)
		spew.Dump(ctx)

		num := bytes.Count(ctx.Output, []byte{0x00, 0x00, 0x00})
		require.Less(t, num, 2)
		num = bytes.Count(ctx.Output, []byte{0xFF, 0xFF, 0xFF})
		require.Less(t, num, 1)

		if runtime.GOOS != "windows" || runtime.GOARCH != "386" {
			return
		}
		addr := loadShellcode(t, ctx.Output)
		var val int
		ret, _, _ := syscallN(addr, (uintptr)(unsafe.Pointer(&val)))
		require.Equal(t, 0x86, int(ret))
		require.Equal(t, 0x86, val)
	})

	t.Run("x64", func(t *testing.T) {
		asm := ".code64\n"
		asm += "mov qword ptr [rcx], 0x64\n"
		asm += "mov rax, 0x64\n"
		asm += "ret\n"
		engine, err := keystone.NewEngine(keystone.ARCH_X86, keystone.MODE_64)
		require.NoError(t, err)
		shellcode, err := engine.Assemble(asm, 0)
		require.NoError(t, err)
		err = engine.Close()
		require.NoError(t, err)

		opts := &Options{
			MinifyMode: true,
			NoIterator: true,
			NoGarbage:  true,
		}
		ctx, err := encoder.Encode(shellcode, 64, opts)
		require.NoError(t, err)
		spew.Dump(ctx)

		testFindSignature(t, ctx.Output)

		if runtime.GOOS != "windows" || runtime.GOARCH != "amd64" {
			return
		}
		addr := loadShellcode(t, ctx.Output)
		var val int
		ret, _, _ := syscallN(addr, (uintptr)(unsafe.Pointer(&val)))
		require.Equal(t, 0x64, int(ret))
		require.Equal(t, 0x64, val)
	})

	err := encoder.Close()
	require.NoError(t, err)
}

func TestSpecificSeed(t *testing.T) {
	t.Run("init", func(t *testing.T) {
		asm := ".code32\n"
		asm += "mov eax, dword ptr [esp+4]\n"
		asm += "mov dword ptr [eax], 0x86\n"
		asm += "mov eax, 0x86\n"
		asm += "ret\n"
		engine, err := keystone.NewEngine(keystone.ARCH_X86, keystone.MODE_32)
		require.NoError(t, err)
		shellcode, err := engine.Assemble(asm, 0)
		require.NoError(t, err)
		err = engine.Close()
		require.NoError(t, err)

		opts := &Options{
			SaveContext: true,
			EraseInst:   true,
		}

		encoder1 := NewEncoder()
		ctx1, err := encoder1.Encode(shellcode, 32, opts)
		require.NoError(t, err)

		opts.RandSeed = ctx1.Seed
		encoder2 := NewEncoder()
		ctx2, err := encoder2.Encode(shellcode, 32, opts)
		require.NoError(t, err)
		require.Equal(t, ctx1, ctx2)

		ctx3, err := encoder1.Encode(shellcode, 32, opts)
		require.NoError(t, err)
		require.Equal(t, ctx1, ctx3)

		seed := binary.BigEndian.Uint64(ctx3.Output[len(ctx3.Output)-8:])
		require.Equal(t, uint64(opts.RandSeed), seed)

		err = encoder1.Close()
		require.NoError(t, err)
		err = encoder2.Close()
		require.NoError(t, err)
	})

	t.Run("x86", func(t *testing.T) {
		asm := ".code32\n"
		asm += "mov eax, dword ptr [esp+4]\n"
		asm += "mov dword ptr [eax], 0x86\n"
		asm += "mov eax, 0x86\n"
		asm += "ret\n"
		engine, err := keystone.NewEngine(keystone.ARCH_X86, keystone.MODE_32)
		require.NoError(t, err)
		shellcode, err := engine.Assemble(asm, 0)
		require.NoError(t, err)
		err = engine.Close()
		require.NoError(t, err)

		opts := &Options{
			SaveContext: true,
			EraseInst:   true,
			RandSeed:    1234,
		}

		encoder1 := NewEncoder()
		ctx1, err := encoder1.Encode(shellcode, 32, opts)
		require.NoError(t, err)
		encoder2 := NewEncoder()
		ctx2, err := encoder2.Encode(shellcode, 32, opts)
		require.NoError(t, err)
		require.Equal(t, ctx1, ctx2)

		ctx3, err := encoder1.Encode(shellcode, 32, opts)
		require.NoError(t, err)
		require.Equal(t, ctx1, ctx3)

		seed := binary.BigEndian.Uint64(ctx3.Output[len(ctx3.Output)-8:])
		require.Equal(t, uint64(1234), seed)

		err = encoder1.Close()
		require.NoError(t, err)
		err = encoder2.Close()
		require.NoError(t, err)
	})

	t.Run("x64", func(t *testing.T) {
		asm := ".code64\n"
		asm += "mov qword ptr [rcx], 0x64\n"
		asm += "mov rax, 0x64\n"
		asm += "ret\n"
		engine, err := keystone.NewEngine(keystone.ARCH_X86, keystone.MODE_64)
		require.NoError(t, err)
		shellcode, err := engine.Assemble(asm, 0)
		require.NoError(t, err)
		err = engine.Close()
		require.NoError(t, err)

		opts := &Options{
			SaveContext: true,
			EraseInst:   true,
			RandSeed:    1234,
		}

		encoder1 := NewEncoder()
		ctx1, err := encoder1.Encode(shellcode, 64, opts)
		require.NoError(t, err)
		encoder2 := NewEncoder()
		ctx2, err := encoder2.Encode(shellcode, 64, opts)
		require.NoError(t, err)
		require.Equal(t, ctx1, ctx2)

		ctx3, err := encoder1.Encode(shellcode, 64, opts)
		require.NoError(t, err)
		require.Equal(t, ctx1, ctx3)

		seed := binary.BigEndian.Uint64(ctx3.Output[len(ctx3.Output)-8:])
		require.Equal(t, uint64(1234), seed)

		err = encoder1.Close()
		require.NoError(t, err)
		err = encoder2.Close()
		require.NoError(t, err)
	})
}

func TestEncoderFuzz(t *testing.T) {
	encoder := NewEncoder()

	t.Run("x86", func(t *testing.T) {
		asm := ".code32\n"
		asm += "mov eax, dword ptr [esp+4]\n"
		asm += "mov dword ptr [eax], 0x86\n"
		asm += "mov eax, 0x86\n"
		asm += "ret\n"
		engine, err := keystone.NewEngine(keystone.ARCH_X86, keystone.MODE_32)
		require.NoError(t, err)
		shellcode, err := engine.Assemble(asm, 0)
		require.NoError(t, err)
		err = engine.Close()
		require.NoError(t, err)

		opts := &Options{
			SaveContext: true,
			EraseInst:   true,
		}

		for i := 0; i < 100; i++ {
			ctx, err := encoder.Encode(shellcode, 32, opts)
			require.NoError(t, err)

			fmt.Println("seed:", ctx.Seed)
			testFindSignature(t, ctx.Output)

			if runtime.GOOS != "windows" || runtime.GOARCH != "386" {
				continue
			}
			addr := loadShellcode(t, ctx.Output)
			var val int
			_, _, _ = syscallN(addr, (uintptr)(unsafe.Pointer(&val)))
			require.Equal(t, 0x86, val)

			// check shellcode is erased
			sc := unsafe.Slice((*byte)(unsafe.Pointer(addr)), len(ctx.Output))
			require.False(t, bytes.Contains(sc, shellcode))
			testFindSignature(t, sc)
		}
	})

	t.Run("x64", func(t *testing.T) {
		asm := ".code64\n"
		asm += "mov qword ptr [rcx], 0x64\n"
		asm += "mov rax, 0x64\n"
		asm += "ret\n"
		engine, err := keystone.NewEngine(keystone.ARCH_X86, keystone.MODE_64)
		require.NoError(t, err)
		shellcode, err := engine.Assemble(asm, 0)
		require.NoError(t, err)
		err = engine.Close()
		require.NoError(t, err)

		opts := &Options{
			SaveContext: true,
			EraseInst:   true,
		}

		for i := 0; i < 100; i++ {
			ctx, err := encoder.Encode(shellcode, 64, opts)
			require.NoError(t, err)

			fmt.Println("seed:", ctx.Seed)
			testFindSignature(t, ctx.Output)

			if runtime.GOOS != "windows" || runtime.GOARCH != "amd64" {
				continue
			}
			addr := loadShellcode(t, ctx.Output)
			var val int
			ret, _, _ := syscallN(addr, (uintptr)(unsafe.Pointer(&val)))
			require.Equal(t, int(addr), int(ret))
			require.Equal(t, 0x64, val)

			// check shellcode is erased
			sc := unsafe.Slice((*byte)(unsafe.Pointer(addr)), len(ctx.Output))
			require.False(t, bytes.Contains(sc, shellcode))
			testFindSignature(t, sc)
		}
	})

	err := encoder.Close()
	require.NoError(t, err)
}

func testFindSignature(t *testing.T, data []byte) {
	msg := "found signature\n"
	msg += spew.Sdump(data)
	require.Less(t, bytes.Count(data, []byte{0x00, 0x00, 0x00}), 4, msg)
	require.Less(t, bytes.Count(data, []byte{0xFF, 0xFF, 0xFF}), 4, msg)
}
