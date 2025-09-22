# ssh-ify

A simple SSH tunnel proxy server with user management and WebSocket support.

## Features
- SSH Websocket tunnel proxy
- Simple user management
- Password authentication
- Works with SSH clients like HTTP Injector, DarkTunnel, and Tunn

## Installation

```sh
go install github.com/ayanrajpoot10/ssh-ify/cmd/ssh-ify@latest
```

## Usage

### Start the server
```sh
./ssh-ify
```

### Add a user
```sh
./ssh-ify add-user username password
```

### List users
```sh
./ssh-ify list-users
```

## License
This project is licensed under the [MIT License](LICENSE).
