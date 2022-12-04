FROM --platform=linux/amd64 ubuntu:18.04 as builder

RUN apt-get update
RUN DEBIAN_FRONTEND=noninteractive apt-get install -y build-essential clang

COPY . /repo
WORKDIR /repo/trunk
RUN make -j8
RUN clang++ /repo/mayhem/fuzz_simplifyPath.cpp -fsanitize=fuzzer,address -I /repo/trunk/common/ /repo/trunk/common/*.o /repo/trunk/lib/*.o /repo/trunk/externals/tinyxml/tinyxml2.o -o /fuzz

FROM ubuntu:18.04 as package
COPY --from=builder /repo/trunk/tscancode /
COPY --from=builder /fuzz /fuzz_simplifyPath
