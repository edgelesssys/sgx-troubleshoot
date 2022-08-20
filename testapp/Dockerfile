FROM ubuntu:20.04 AS build
RUN apt-get update && DEBIAN_FRONTEND=noninteractive apt-get install -y \
  build-essential \
  clang-10 \
  cmake \
  git \
  libssl-dev \
  ninja-build
COPY oe.patch /
RUN git clone --depth=1 -bv0.18.2 https://github.com/openenclave/openenclave \
  && cd openenclave \
  && git submodule update --init --recursive --depth=1 \
  && patch -p1 < /oe.patch \
  && mkdir /oebuild \
  && cd /oebuild \
  && cmake -GNinja -DCMAKE_BUILD_TYPE=Release -DBUILD_TESTS=OFF -DENABLE_REFMAN=OFF /openenclave \
  && ninja install
COPY CMakeLists.txt helloworld.edl testapp/
COPY enclave testapp/enclave
COPY host testapp/host
WORKDIR build
RUN cmake -DCMAKE_BUILD_TYPE=MinSizeRel /testapp && make

FROM ubuntu:20.04
RUN apt-get update && apt-get install -y --no-install-recommends ca-certificates gnupg libcurl4 wget \
  && wget -qO- https://download.01.org/intel-sgx/sgx_repo/ubuntu/intel-sgx-deb.key | apt-key add \
  && echo 'deb [arch=amd64] https://download.01.org/intel-sgx/sgx_repo/ubuntu focal main' >> /etc/apt/sources.list \
  && wget -qO- https://packages.microsoft.com/keys/microsoft.asc | apt-key add \
  && echo 'deb [arch=amd64] https://packages.microsoft.com/ubuntu/20.04/prod focal main' >> /etc/apt/sources.list \
  && apt-get update && apt-get install -y --no-install-recommends \
  libsgx-dcap-ql \
  libsgx-launch \
  && apt-get install -d az-dcap-client libsgx-dcap-default-qpl
COPY --from=build build/host/testapp_host build/enclave/enclave.signed build/enclave/enclave_debug.signed /
COPY entry.sh /
ENTRYPOINT ["/entry.sh"]
