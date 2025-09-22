# ssh-ify

A modern SSH tunnel proxy server with user management, password authentication, WebSocket and TLS support, written in Go.

---

## Table of Contents
- [Features](#features)
- [Architecture](#architecture)
- [Installation](#installation)
- [Usage](#usage)
  - [Running the Server](#running-the-server)
  - [User Management](#user-management)
- [Configuration](#configuration)
- [Security](#security)
- [Contributing](#contributing)
- [License](#license)

---

## Features
- **SSH Tunnel Proxy**: Securely forward TCP connections over SSH.
- **WebSocket Support**: SSH-over-WebSocket for browser and cloud compatibility.
- **TLS/HTTPS**: Built-in support for TLS with self-signed certificate generation.
- **User Management**: Add, remove, enable, disable, and list users via CLI or interactive shell.
- **Password Authentication**: Secure bcrypt-hashed password storage and validation.
- **Atomic User Database**: JSON-based, thread-safe, and backup-capable user database.
- **Graceful Shutdown**: Handles OS signals and cleans up all active sessions.
- **Extensible & Modular**: Clean Go codebase, easy to extend and maintain.

---

## Architecture
- **cmd/ssh-ify/main.go**: CLI entrypoint for server and user management.
- **internal/ssh/**: SSH server config, authentication, and channel handling.
- **internal/tunnel/**: TCP/TLS/WebSocket server, session management, and relaying.
- **internal/usermgmt/**: User database and management logic.
- **pkg/certgen/**: Self-signed certificate and key generation utilities.

---

## Technical Details

### How ssh-ify Handles Client Connections and Proxies Traffic

1. **Listening for Connections:**
   - The server listens on TCP port 80 (for plain TCP/WebSocket) and 443 (for TLS/HTTPS).
   - Incoming connections are accepted and wrapped in a `Session` object.

2. **Protocol Detection & Upgrade:**
   - The server inspects the initial client request to determine if it is a plain TCP, HTTP, or WebSocket upgrade request.
   - If a WebSocket upgrade is requested, the server responds with the appropriate handshake and upgrades the connection.

3. **SSH Server Initialization:**
   - For each new session, an in-process SSH server is initialized using a host key (auto-generated if missing).
   - The SSH server uses password authentication, backed by a bcrypt-hashed user database (`users.json`)

4. **Authentication:**
   - The SSH handshake is performed over the (optionally upgraded) connection.
   - The user must authenticate with a valid username and password.
   - Only enabled users can authenticate.

5. **Channel Handling & Port Forwarding:**
   - After authentication, the SSH server accepts only `direct-tcpip` channels (standard for SSH port forwarding).
   - The client requests a target host/port; the server establishes a TCP connection to the target.
   - Data is relayed bidirectionally between the SSH channel and the target TCP connection using goroutines for concurrency.

6. **Session Management & Cleanup:**
   - Each active session is tracked and can be gracefully shut down on server exit or signal.
   - All resources (client, target, SSH connections) are properly closed after use.

### How ssh-ify Uses SSH

- **In-Process SSH Server:**
  - Uses `golang.org/x/crypto/ssh` to implement a full SSH server inside the Go process.
  - Handles authentication, channel negotiation, and port forwarding natively.

- **Password Authentication:**
  - Custom password callback validates credentials against the user database.
  - No SSH keys are required for clients; only username/password.

- **Port Forwarding:**
  - Only `direct-tcpip` (standard SSH port forwarding) is supported for security and simplicity.
  - The server acts as a proxy, forwarding traffic between the SSH client and the requested target host/port.

- **WebSocket Support:**
  - SSH protocol can be tunneled over WebSocket, allowing browser-based or cloud-native SSH clients to connect.

> **Note:** Accounts created with ssh-ify work seamlessly with all SSH-over-WebSocket clients, including popular tools like HTTP Injector, DarkTunnel, and [Tunn](https://github.com/ayanrajpoot10/tunn) (my own SSH WebSocket client), as well as similar apps. Simply use your ssh-ify username and password in your preferred client, set the WebSocket host/port, and connect securely through the proxy.

---

## Installation

### Prerequisites
- Go 1.24+

### Build
```sh
git clone https://github.com/ayanrajpoot10/ssh-ify.git
cd ssh-ify
go build -o ssh-ify ./cmd/ssh-ify
```

---

## Usage


### Running the Server
Start the SSH tunnel proxy server (listens on port 80 for TCP/WS, 443 for TLS):
```sh
./ssh-ify
```

#### Run as a Background Process
To keep the server running after closing the terminal:

- **On Linux/macOS:**
  ```sh
  sudo nohup ./ssh-ify > output.log 2>&1 &
  ```
  This will start `ssh-ify` in the background and redirect all output to `output.log`.

### User Management
Manage users via CLI commands:

- Add user:
  ```sh
  ./ssh-ify add-user <username> <password>
  ```
- Remove user:
  ```sh
  ./ssh-ify remove-user <username>
  ```
- List users:
  ```sh
  ./ssh-ify list-users
  ```
- Enable/Disable user:
  ```sh
  ./ssh-ify enable-user <username>
  ./ssh-ify disable-user <username>
  ```
- Interactive shell:
  ```sh
  ./ssh-ify user-mgmt
  ```

---

## Configuration
- **Listening Address/Port**: Defaults to 0.0.0.0:80 (TCP/WS) and 0.0.0.0:443 (TLS).
- **TLS Certificates**: Auto-generated as `cert.pem` and `key.pem` if not present.
- **User Database**: Stored as `users.json` in the working directory.
- **Host SSH Key**: Auto-generated as `host_key` if not present.
- **Default User**: Can be automatically created using environment variables (see below).

### Environment Variables
You can automatically create a default user account by setting environment variables:

- `SSH_IFY_DEFAULT_USER`: Username for the default account
- `SSH_IFY_DEFAULT_PASSWORD`: Password for the default account

---

## Security
- Passwords are hashed with bcrypt.
- User accounts can be enabled/disabled.
- All sensitive files (keys, certs, user DB) are stored with restricted permissions.
- Supports secure tunnels over both SSH and TLS.

---

## Contributing
Pull requests are welcome! Please open an issue to discuss major changes or new features before submitting a PR.

---


## License
This project is licensed under the [MIT License](LICENSE).

---

## Acknowledgements
- Built with Go and [golang.org/x/crypto/ssh](https://pkg.go.dev/golang.org/x/crypto/ssh)
- Inspired by open-source SSH and tunnel projects.
