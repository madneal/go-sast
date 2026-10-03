FROM golang:1.25-alpine AS build

WORKDIR /src
COPY go.mod main.go ./
RUN CGO_ENABLED=0 GOOS=linux go build -trimpath -ldflags='-s -w' -o /out/go-sast .

FROM alpine:3.22

RUN adduser -D -u 10001 sast
COPY --from=build /out/go-sast /usr/local/bin/go-sast
USER sast
ENTRYPOINT ["/usr/local/bin/go-sast"]
CMD ["--path", "/workspace", "--fail-on-findings"]
