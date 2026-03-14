GOROOT_WASM_EXEC := $(shell go env GOROOT)/lib/wasm/wasm_exec.js

.PHONY: wasm serve clean

wasm: copy-wasm-exec
	cd .. && GOOS=js GOARCH=wasm go build -o playground/psbt.wasm ./playground/

copy-wasm-exec:
	cp "$(GOROOT_WASM_EXEC)" ./wasm_exec.js

serve: wasm
	go run server.go

clean:
	rm -f psbt.wasm wasm_exec.js
