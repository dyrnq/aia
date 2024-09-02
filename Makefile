tidy:
	GOPROXY=https://goproxy.io,direct go mod tidy -v
build:
	GOPROXY=https://goproxy.io,direct CGO_ENABLED=0 go build -v -o aia cmd/main.go

run: tidy build
	./aia --listen :5980 --apisix-config example.txt --apisix-reload-cmd "ps aux"

