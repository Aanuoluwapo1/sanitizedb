FROM golang:1.23-alpine AS builder
WORKDIR /workspace/services/orchestrator-cli

COPY services/orchestrator-cli ./
RUN go mod tidy && CGO_ENABLED=0 GOOS=linux go build -o /usr/local/bin/sanitizedb ./cmd/sanitizedb

FROM alpine:3.20
RUN adduser -D -u 10001 sanitizedb
USER 10001
COPY --from=builder /usr/local/bin/sanitizedb /usr/local/bin/sanitizedb
COPY services/orchestrator-cli/examples/policy.yaml /etc/sanitizedb/policy.yaml
EXPOSE 8080
ENTRYPOINT ["/usr/local/bin/sanitizedb", "serve"]
