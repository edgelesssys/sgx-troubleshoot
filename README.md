# SGX troubleshooting

This tool collects system information that can be helpful to diagnose SGX issues.

Note that this tool may print errors that are not relevant for your particular system.

Get it with:

```sh
wget https://github.com/edgelesssys/sgx-troubleshoot/releases/latest/download/sgx-troubleshoot
chmod +x sgx-troubleshoot
```

For full diagnostics, run:

```sh
./sgx-troubleshoot -v -test-all
```

## Roadmap

Future versions of this tool will point out specific problems and explain how to fix them.

## Build from source

```sh
export DOCKER_BUILDKIT=1
docker build -t ghcr.io/edgelesssys/sgx-troubleshoot/testapp testapp
docker build -o. .
```
