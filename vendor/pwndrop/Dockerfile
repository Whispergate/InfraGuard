FROM golang:1.21-alpine AS builder

RUN apk add --no-cache git

WORKDIR /src
RUN git clone https://github.com/kgretzky/pwndrop.git .
RUN GOARCH=amd64 go build -ldflags="-s -w" -o ./build/pwndrop -mod=vendor main.go

FROM alpine:3.19

RUN apk add --no-cache ca-certificates

WORKDIR /pwndrop
COPY --from=builder /src/build/pwndrop /pwndrop/pwndrop
COPY --from=builder /src/www /pwndrop/www

VOLUME ["/pwndrop/data"]
EXPOSE 80 443

ENTRYPOINT ["/pwndrop/pwndrop"]
