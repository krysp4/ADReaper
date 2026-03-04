BINARY  := adreaper
VERSION := 1.0.0
LDFLAGS := -ldflags="-s -w -X adreaper/internal/output.Version=$(VERSION)"

.PHONY: all build linux windows clean tidy test

all: linux

## Instala dependencias
tidy:
	go mod tidy

## Build para Linux (entorno real de pentesting)
linux:
	GOOS=linux GOARCH=amd64 go build $(LDFLAGS) -o dist/$(BINARY)-linux-amd64 .

## Build para Windows (desarrollo)
windows:
	GOOS=windows GOARCH=amd64 go build $(LDFLAGS) -o dist/$(BINARY)-windows-amd64.exe .

## Build local (OS actual)
build:
	go build $(LDFLAGS) -o dist/$(BINARY) .

## Tests unitarios
test:
	go test ./... -v

## Limpia artefactos
clean:
	rm -rf dist/
