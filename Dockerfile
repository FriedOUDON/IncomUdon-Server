FROM golang:1.22-alpine AS build
WORKDIR /src
COPY go.mod .
COPY *.go ./
RUN go build -o /out/incomudon-server .

FROM alpine:3.19
RUN addgroup -S -g 10001 app && adduser -S -D -H -u 10001 -G app -s /sbin/nologin app
USER 10001:10001
COPY --from=build /out/incomudon-server /usr/local/bin/incomudon-server
EXPOSE 50000/udp
ENTRYPOINT ["/usr/local/bin/incomudon-server"]
