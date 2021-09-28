COMMIT_SHA := $(shell git rev-parse --short HEAD 2>&1)

export JAEGER_AGENT_HOST = localhost
export JAEGER_AGENT_PORT = 6831
export JAEGER_SAMPLER_TYPE = const
export JAEGER_SAMPLER_PARAM = 1

run:
	@go run ./ -deploy ./config/config.yml

run-uninstall:
	@go run ./ -deploy ./config/config.yml -uninstall

build-windows:
	@go build -ldflags="-H windows" -o ./build/simba-cert.exe
		
test:
	@echo "Testing ..."
	@go test -failfast -cover ./...

