FROM golang:1.24.4 AS builder

WORKDIR /app

COPY go.mod go.sum ./
RUN go mod download
COPY . .

RUN go build -o spuddns .

FROM debian:bookworm-slim

RUN apt update
RUN apt install -y ca-certificates

COPY --from=builder /app/spuddns /spuddns

ENTRYPOINT ["/spuddns", "/etc/spuddns.json"]
