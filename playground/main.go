//go:build js && wasm

package main

import (
	"fmt"
	"syscall/js"
)

func main() {
	fmt.Println("PSBT Playground WASM loaded")

	js.Global().Set("psbtPing", js.FuncOf(func(this js.Value, args []js.Value) any {
		return `{"ok":true,"message":"pong"}`
	}))

	select {}
}
