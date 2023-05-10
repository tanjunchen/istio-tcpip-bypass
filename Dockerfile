FROM docker.io/tanjunchen/golang:1.17 AS allbuild

RUN apt-get update && apt-get install -y \
    make \
    clang \
    llvm \
    libbpf-dev \
    bpftool


WORKDIR /go/src
COPY . /go/src/
ENV GO111MODULE=on
ENV GOPROXY=https://goproxy.cn
RUN go mod download
RUN go generate && go build -o load-bypass .

FROM docker.io/tanjunchen/distroless-static:latest
COPY --from=allbuild /go/src/load-bypass /bpf/

WORKDIR /bpf
ENTRYPOINT ["./load-bypass"]
