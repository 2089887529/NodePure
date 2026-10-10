FROM golang:1.26-alpine AS builder
WORKDIR /src
COPY go.mod go.sum ./
RUN go mod download
COPY . .
RUN CGO_ENABLED=0 go build -trimpath -ldflags="-s -w" -o /out/nodepure ./cmd/server

FROM alpine:3.23
RUN apk add --no-cache ca-certificates \
    && addgroup -g 10001 nodepure && adduser -D -u 10001 -G nodepure nodepure \
    && mkdir /app /secrets && chown nodepure:nodepure /app /secrets
COPY --from=builder /out/nodepure /app/nodepure
WORKDIR /app
USER 10001:10001
ENV NODEPURE_HOST=0.0.0.0 NODEPURE_PORT=8099 MIHOMO_BIN=/kernels/mihomo NODEPURE_PASSWORD_HASH_FILE=/secrets/password.hash
EXPOSE 8099
HEALTHCHECK --interval=30s --timeout=3s CMD wget -q --spider http://127.0.0.1:8099/ || exit 1
ENTRYPOINT ["/app/nodepure"]
