FROM golang:1.27.3 AS build

WORKDIR /src
COPY go.mod go.sum ./
RUN --mount=type=cache,target=/go/pkg/mod \
    go mod download

COPY . .
RUN --mount=type=cache,target=/go/pkg/mod \
    --mount=type=cache,target=/root/.cache/go-build \
    CGO_ENABLED=0 \
    go build -trimpath -o /out/app .

FROM alpine:3.24.3

RUN addgroup -S -g 65532 nonroot && \
    adduser -S -D -H -u 65532 -s /sbin/nologin -G nonroot nonroot

WORKDIR /app
COPY --from=build /out/app .

USER 65532:65532
ENTRYPOINT ["/app/app"]
