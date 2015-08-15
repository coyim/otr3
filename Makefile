default: deps lint test

lint:
	golint ./...

test:
	go test -v ./... -cover

deps:
	./deps.sh

cover:
	go test . -coverprofile=coverage.out
	go tool cover -html=coverage.out
