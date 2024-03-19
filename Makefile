build:
	@go build -o build/blocker

run: build
	@./bin/blocker

test:
	@go test -v ./...