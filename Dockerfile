FROM golang:alpine AS builder

WORKDIR /build

RUN apk add --no-cache git ca-certificates tzdata

COPY go.mod go.sum ./
RUN go mod download

COPY . .

RUN CGO_ENABLED=0 GOOS=linux go build -ldflags="-w -s" -o /build/server cmd/server/main.go
RUN CGO_ENABLED=0 GOOS=linux go build -ldflags="-w -s" -o /build/migrate database/cmd/main.go

FROM alpine:latest

WORKDIR /app

RUN apk add --no-cache ca-certificates tzdata

COPY --from=builder /build/server /app/server
COPY --from=builder /build/migrate /app/migrate
COPY --from=builder /build/internal/notification/email/templates /app/internal/notification/email/templates
COPY --from=builder /build/database/migrations /app/database/migrations
COPY --from=builder /build/entrypoint.sh /app/entrypoint.sh

RUN chmod +x /app/entrypoint.sh

ENTRYPOINT ["/app/entrypoint.sh"]
CMD ["/app/server"]
