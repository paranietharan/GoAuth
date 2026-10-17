.PHONY: all build run migrate-up migrate-down migrate-drop seed test test-race test-integration lint docker-up docker-down clean

# Build binaries
build:
	@mkdir -p bin
	go build -o bin/server cmd/server/main.go
	go build -o bin/migrate database/cmd/main.go
	@echo "Build complete: bin/server, bin/migrate"

# Run server locally
run:
	go run cmd/server/main.go

# Migrations & Seeding
migrate-up:
	go run database/cmd/main.go -migrate up

migrate-down:
	go run database/cmd/main.go -migrate down

migrate-drop:
	go run database/cmd/main.go -migrate drop

seed:
	go run database/cmd/main.go -seed

# Testing
test:
	go test -v ./...

test-race:
	go test -v -race ./...

test-integration:
	go test -v -race ./tests/integration/...

# Code Quality & Linting
lint:
	@which golangci-lint > /dev/null || (echo "golangci-lint not installed. Run: go install github.com/golangci/golangci-lint/cmd/golangci-lint@latest" && exit 1)
	golangci-lint run ./...

# Docker operations
docker-up:
	docker compose up -d --build

docker-down:
	docker compose down -v

# Clean artifacts
clean:
	rm -rf bin/ *.out coverage.html test.log
