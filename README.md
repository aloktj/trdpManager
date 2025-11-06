# TRDP Lightweight Manager

A minimal C++ web server that exposes a browser UI for basic TRDP stack control. The application allows you to start and stop communication, upload XML configuration, edit the outgoing payload, and observe incoming payload values in a table.

## Building

```bash
cmake -S . -B build
cmake --build build
```

## Running

```bash
./build/trdp_manager
```

By default the server listens on `http://0.0.0.0:8080`. Open the URL in a browser to access the dashboard.

> **Note**
> Integrations with the actual TCNopen TRDP stack are stubbed in `TrdpManager`. Replace the TODO comments with real stack calls when the library is available in your environment.
