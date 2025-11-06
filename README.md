# TRDP Lightweight Manager

A minimal C++ web server that exposes a browser UI for basic TRDP stack control. The application allows you to start and stop communication, upload XML configuration, edit the outgoing payload, and observe incoming payload values in a table.

## Building

The build requires that the [TCNopen TRDP stack](https://www.tcnopen.eu/) headers and libraries are available on the system. The CMake project looks for them under `/usr`, `/usr/local`, and `/opt/tcnopen` by default.

```bash
cmake -S . -B build
cmake --build build
```

## Running

```bash
./build/trdp_manager
```

By default the server listens on `http://0.0.0.0:8080`. Open the URL in a browser to access the dashboard.

The web UI expects TRDP XML files that describe `<Publisher>` and/or `<Subscriber>` elements with attributes `comId`, `datasetId`, and optional timing/network settings. When a configuration is loaded the server establishes real TRDP sessions using the installed stack, subscribes to incoming PD messages, and publishes the edited payload using the configured dataset definition.
