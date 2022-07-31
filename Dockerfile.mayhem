FROM --platform=linux/amd64 ubuntu:18.04 as builder

RUN apt-get update
RUN DEBIAN_FRONTEND=noninteractive apt-get install -y build-essential

COPY . /repo
WORKDIR /repo/trunk
RUN make -j8

FROM ubuntu:18.04 as package
COPY --from=builder /repo/trunk/tscancode /
