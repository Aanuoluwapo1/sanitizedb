.PHONY: up down proto-gen test-rust test-go test-java

up:
	docker compose up --build

down:
	docker compose down -v

proto-gen:
	cd packages/proto && buf generate

test-rust:
	cd services/stream-engine && cargo test

test-go:
	cd services/orchestrator-cli && go test ./...

test-java:
	cd services/governance-core && mvn test
