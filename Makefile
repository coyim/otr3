default: deps lint test

lint:
	golint ./...

test:
	go test -v ./... -cover

deps:
	./deps.sh
