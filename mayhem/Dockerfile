FROM --platform=linux/amd64 ubuntu:22.04 as builder

RUN apt-get update
RUN DEBIAN_FRONTEND=noninteractive apt-get install -y build-essential clang \
    cmake \
    libboost-dev \
    libboost-filesystem-dev libboost-regex-dev libboost-system-dev libboost-locale-dev \
    libgoogle-glog-dev \
    libgtest-dev \
    libyaml-cpp-dev \
    libleveldb-dev \
    libmarisa-dev

RUN apt install -y git

# Manually install libopencc
RUN git clone https://github.com/BYVoid/OpenCC.git
WORKDIR OpenCC/
RUN apt install -y doxygen
RUN make
RUN make install

# Build librime
COPY . /repo
WORKDIR /repo
RUN make -j8
RUN make install
RUN clang++ /repo/mayhem/fuzz_CompareVersionString.cpp -fsanitize=fuzzer,address -I /repo/src/rime/algo/ -I /repo/src -I /repo/build/src/ -lrime -o /fuzz

FROM ubuntu:22.04 as package

RUN apt-get update
RUN apt install -y \
    libboost-dev \
    libboost-filesystem-dev libboost-regex-dev libboost-system-dev libboost-locale-dev \
    libgoogle-glog-dev \
    libyaml-cpp-dev \
    libleveldb-dev \
    libmarisa-dev cmake python-is-python3 doxygen build-essential git

# Manually install libopencc
RUN git clone https://github.com/BYVoid/OpenCC.git
WORKDIR OpenCC/
RUN apt install -y doxygen
RUN make -j8
RUN make install

COPY --from=builder /lib/x86_64-linux-gnu/librime.so.1 /deps/
COPY --from=builder /fuzz /fuzz_CompareVersionString
ENV LD_LIBRARY_PATH=/deps

