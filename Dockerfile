# syntax=docker/dockerfile:1
FROM golang:1.26-alpine3.23 AS build
WORKDIR /src
COPY go.mod ./
COPY . .
RUN CGO_ENABLED=0 GOOS=linux go build -trimpath -ldflags="-s -w" -o /out/zentcontainer ./cmd/zentcontainer

FROM alpine:3.23
RUN apk add --no-cache ca-certificates tzdata sqlite docker-cli docker-cli-compose
COPY --from=build /out/zentcontainer /zentcontainer
RUN chmod 0755 /zentcontainer && mkdir -p /opt/zentcontainer
EXPOSE 9443 9444
HEALTHCHECK --interval=30s --timeout=5s --start-period=10s --retries=3 CMD wget -q -O- http://127.0.0.1:9443/api/setup >/dev/null || exit 1
ENTRYPOINT ["/zentcontainer"]
