FROM golang:1.22-alpine AS build
WORKDIR /src
COPY go.mod .
COPY main.go .
RUN go build -o /out/incomudon-server ./main.go

FROM alpine:3.19
RUN adduser -D -H -s /sbin/nologin app
USER app
COPY --from=build /out/incomudon-server /usr/local/bin/incomudon-server
EXPOSE 50000/udp
ENTRYPOINT ["/usr/local/bin/incomudon-server"]
