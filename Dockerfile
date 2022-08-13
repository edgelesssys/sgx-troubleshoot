FROM golang:1.16 AS build
WORKDIR /build
COPY --from=ghcr.io/edgelesssys/sgx-troubleshoot/testapp testapp_host enclave.signed enclave_debug.signed ./
COPY go.mod go.sum main.go testapp.go ./
RUN CGO_ENABLED=0 go build -tags testapp -ldflags "-X main.timestamp=$(date +%s)"

FROM scratch
COPY --from=build build/sgx-troubleshoot /
