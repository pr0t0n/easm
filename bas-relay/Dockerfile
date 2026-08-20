FROM golang:1.22 AS builder
WORKDIR /app
COPY go.mod go.sum ./
RUN go mod download
COPY main.go .
RUN CGO_ENABLED=0 GOOS=linux go build -o /bas-relay .

FROM debian:bookworm-slim
COPY --from=builder /bas-relay /usr/local/bin/bas-relay
ENTRYPOINT ["/usr/local/bin/bas-relay"]
