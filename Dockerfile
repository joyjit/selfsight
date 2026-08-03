# syntax=docker/dockerfile:1

# Multi-stage build: build the React dashboard, embed it into the Go binary,
# ship a tiny final image. The same binary also runs bare on any Linux box.

# --- web: build the dashboard into web/dist ---
FROM node:20-alpine AS web
WORKDIR /src/web
COPY web/package.json web/package-lock.json* ./
RUN npm ci || npm install
COPY web/ ./
RUN npm run build

# --- go: build the server with the dashboard embedded ---
FROM golang:1.25-alpine AS build
WORKDIR /src
COPY go.mod go.sum ./
RUN go mod download
COPY . .
# Bring in the freshly built dashboard so go:embed picks it up.
COPY --from=web /src/web/dist ./web/dist
RUN CGO_ENABLED=0 go build -trimpath -ldflags="-s -w" -o /out/selfsight ./cmd/selfsight

# --- final: minimal runtime ---
FROM alpine:3.20
RUN apk add --no-cache ca-certificates && \
    mkdir -p /config /data
COPY --from=build /out/selfsight /usr/local/bin/selfsight

# /config holds the user's config.yaml; /data holds device config backups.
VOLUME ["/config", "/data"]
EXPOSE 8080
ENTRYPOINT ["/usr/local/bin/selfsight"]
CMD ["serve", "--config", "/config/config.yaml", "--data", "/data"]
