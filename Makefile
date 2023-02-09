default: deps lint test

lint:
	golint . ./compat ./sexp

test:
	go test -cover -v ./...

test-slow:
	make -C ./compat libotr-compat

ci: lint test test-slow

deps:
	go install golang.org/x/lint/golint
	go install golang.org/x/tools/cmd/cover
#	go get github.com/golangci/golangci-lint/...
	go install github.com/securego/gosec/v2/cmd/gosec

deps-ci: deps
	go install github.com/mattn/goveralls

run-cover:
	go test . -coverprofile=coverage.out

coveralls: run-cover
	goveralls -coverprofile=coverage.out

cover: run-cover
	go tool cover -html=coverage.out

#lint-aggregator:
#	golangci-lint run

gosec:
	gosec ./...
