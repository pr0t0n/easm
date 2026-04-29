FROM golang:1.24 as builder
WORKDIR /build
RUN git clone https://github.com/xalgord/xalgorix.git .
RUN make install

FROM debian:bullseye-slim
COPY --from=builder /go/bin/xalgorix /usr/local/bin/xalgorix
RUN apt-get update && apt-get install -y ca-certificates && rm -rf /var/lib/apt/lists/*
ENTRYPOINT ["xalgorix"]
