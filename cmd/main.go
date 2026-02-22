package main

import (
	"encoding/hex"
	"flag"
	"fmt"
	"os"
	"path/filepath"

	"github.com/RTS-Framework/SSCE"
)

var (
	arch   int
	opts   ssce.Options
	jcx86  string
	jcx64  string
	hexIn  bool
	hexOut bool
	in     string
	out    string
)

func init() {
	flag.IntVar(&arch, "arch", 64, "set the architecture")
	flag.IntVar(&opts.NumIterate, "iter", 0, "set the number of iterate")
	flag.IntVar(&opts.NumTailInst, "tail", 0, "set the number of the garbage inst at tail")
	flag.BoolVar(&opts.MinifyMode, "minify", false, "use minify mode, it is not recommend")
	flag.BoolVar(&opts.SaveContext, "safe", false, "save and restore context after call shellcode")
	flag.BoolVar(&opts.EraseInst, "erase", false, "erase shellcode after call it")
	flag.BoolVar(&opts.NoIterator, "no-iter", false, "no iterator, it is not recommend")
	flag.BoolVar(&opts.NoGarbage, "no-garbage", false, "no garbage, it is not recommend")
	flag.Int64Var(&opts.RandSeed, "seed", 0, "specify a random seed for encoder")
	flag.BoolVar(&opts.TrimSeed, "trim-seed", false, "trim the seed at the tail of output")
	flag.StringVar(&opts.MiniDecoderX86, "md-x86", "", "specify the x86 mini decoder template file path")
	flag.StringVar(&opts.MiniDecoderX64, "md-x64", "", "specify the x64 mini decoder template file path")
	flag.StringVar(&opts.LoaderX86, "ldr-x86", "", "specify the x86 loader template file path")
	flag.StringVar(&opts.LoaderX64, "ldr-x64", "", "specify the x64 loader template file path")
	flag.StringVar(&jcx86, "junk-x86", "", "specify the x86 junk template directory path")
	flag.StringVar(&jcx64, "junk-x64", "", "specify the x64 junk template directory path")
	flag.BoolVar(&hexIn, "hex-in", false, "input shellcode with hex format")
	flag.BoolVar(&hexOut, "hex-out", false, "output shellcode with hex format")
	flag.StringVar(&in, "i", "", "set input shellcode file path")
	flag.StringVar(&out, "o", "", "set output shellcode file path")
	flag.Parse()
}

func main() {
	if in == "" {
		flag.Usage()
		return
	}
	if out == "" {
		switch arch {
		case 32:
			out = "output_x86.bin"
		case 64:
			out = "output_x64.bin"
		}
	}

	shellcode, err := os.ReadFile(in) // #nosec
	checkError(err)
	fmt.Printf("read input shellcode from \"%s\"\n", in)
	if hexIn {
		shellcode, err = hex.DecodeString(string(shellcode))
		checkError(err)
	}
	fmt.Println("raw shellcode size:", len(shellcode))

	opts.MiniDecoderX86 = loadMiniDecoderTemplate(opts.MiniDecoderX86)
	opts.MiniDecoderX64 = loadMiniDecoderTemplate(opts.MiniDecoderX64)
	opts.LoaderX86 = loadLoaderTemplate(opts.LoaderX86)
	opts.LoaderX64 = loadLoaderTemplate(opts.LoaderX64)
	opts.JunkCodeX86 = loadJunkCodeTemplate(jcx86)
	opts.JunkCodeX64 = loadJunkCodeTemplate(jcx64)

	encoder := ssce.NewEncoder()
	ctx, err := encoder.Encode(shellcode, arch, &opts)
	checkError(err)
	fmt.Println("==============Context===============")
	fmt.Println("output size: ", len(ctx.Output))
	fmt.Println("random seed: ", ctx.Seed)
	fmt.Println("num iterate: ", ctx.NumIterate)
	fmt.Println("minify mode: ", ctx.MinifyMode)
	fmt.Println("no garbage:  ", ctx.NoGarbage)
	fmt.Println("save context:", ctx.SaveContext)
	fmt.Println("erase inst:  ", ctx.EraseInst)
	fmt.Println("====================================")

	if hexOut {
		ctx.Output = []byte(hex.EncodeToString(ctx.Output))
	}
	err = os.WriteFile(out, ctx.Output, 0600)
	checkError(err)
	fmt.Printf("write output shellcode to \"%s\"\n", out)

	err = encoder.Close()
	checkError(err)
}

func loadMiniDecoderTemplate(path string) string {
	if path == "" {
		return ""
	}
	fmt.Println("load custom mini decoder template:", path)
	template, err := os.ReadFile(path) // #nosec
	checkError(err)
	return string(template)
}

func loadLoaderTemplate(path string) string {
	if path == "" {
		return ""
	}
	fmt.Println("load custom loader template:", path)
	template, err := os.ReadFile(path) // #nosec
	checkError(err)
	return string(template)
}

func loadJunkCodeTemplate(dir string) []string {
	if dir == "" {
		return nil
	}
	fmt.Println("load custom junk code template directory:", dir)
	files, err := os.ReadDir(dir)
	checkError(err)
	templates := make([]string, 0, len(files))
	for _, file := range files {
		if file.IsDir() {
			continue
		}
		data, err := os.ReadFile(filepath.Join(dir, file.Name())) // #nosec
		checkError(err)
		templates = append(templates, string(data))
	}
	return templates
}

func checkError(err error) {
	if err != nil {
		fmt.Println(err)
		os.Exit(1)
	}
}
