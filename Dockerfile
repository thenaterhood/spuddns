FROM golang:1.24.4 AS builder

WORKDIR /app

COPY go.mod go.sum ./
RUN go mod download
COPY . .

RUN go build

FROM alpine:3.22.0

COPY --from=builder /app/spuddns /spuddns
ENTRYPOINT ["/spuddns", "/etc/spuddns.json"]
