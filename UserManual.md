# MinRAT Server: User Manual

## Table of Contents

1. [Introduction](#introduction)
2. [Prerequisites](#prerequisites)
3. [Installation](#installation)
4. [Configuration](#configuration)
5. [Starting the Server](#starting-the-server)
6. [Starting the Client](#starting-the-client)
7. [Client Commands and Protocol](#client-commands-and-protocol)

   * [LOGIN](#login)
   * [CREATE_USER](#create_user)
   * [DELETE_USER](#delete_user)
   * [LIST](#list)
   * [GET](#get)
   * [PUT](#put)
   * [MKDIR](#mkdir)
   * [DELETE](#delete)
   * [QUIT](#quit)
8. [Session Management](#session-management)
9. [Cleanup and Shutdown](#cleanup-and-shutdown)
10. [Known Issues](#known-issues)

---

## Introduction

MinRAT is a simple C-based file server offering remote directory listing, file retrieval, upload, and directory creation via a custom protocol over TCP. It handles multiple concurrent clients using threads, enforces session-based authentication, and protects against path traversal.

## Prerequisites

* Linux environment (tested on Ubuntu 22.04+)
* GCC or compatible C compiler
* POSIX threads library (pthread)
* Valgrind (optional, for memory-checking)

## Installation

1. **Build the server**:

   ```bash
   cd MinRAT
   make
   ```
3. **Verify the executable**:
   The binary `capstone` should appear in `bin/`.

## Configuration

* **Server directory**: Default to the root directory of the binary (`bin`). Override with `-d <PATH>`.
* **Port**: Default 8080. Override with `-p <port>`.
* **Session timeout**: Default 120 seconds (2 min). Override with `-t <seconds>`.

## Starting the Server

```bash
./capstone -d /path/to/dir -p 8080 -t 120
```

* `-d`: root directory served
* `-p`: listening port
* `-t`: session timeout (in seconds)

On launch, you should see:

```
SERVER: Waiting for connections...
```

## Starting the Client

To start the client, simply run the `client.py` script in the same directory as `client_shell.py`  and `protocol_handler.py`.
The client may execute commands from startup on the CLI or from its internal shell. If no port or host are passed, the defaults of the client (localhost, 8080) will be used.

```bash
python3 client.py --host localhost --port 8080
```

* `--host`: root directory served 
* `--port`: listening port
* `<command>`: Command you want to be execute on startup (optional)

On launch, you should see:

```
MinRAT Interactive Client Shell. Type 'help' or '?' for command list.

MinRAT>
```

## Client Commands and Protocol

All commands are sent as ASCII text lines terminated by `\n`. The server responds with status codes and data frames.
All path commands on the server must resolve to inside the server home directory or the command will fail to execute.
Additionally, the commands `delete`, `ls`, and `mkdir` have local and remote versions. The local version will execute on the client machine, while the remote version will execute on the server. The client will execute the command locally if the command is prefixed with `l_`.

### LOGIN

```
login <username> <password>
```

* Begins a session. On success, returns `Login successful. Session ID: <ID>.`.

### CREATE_USER

```
create_user <username> <password> <permission>
```
* Creates a user with the given parameters. A user can only create a user with a permission level equal to or lower than its own.
* On success, returns ` `

### DELETE_USER

```
delete_user <username>
```

* Delete the user with the given username. A user can only be deleted by a user with an equal to or higher permission level.
* On success, returns ` `

### LIST

```
ls <directory>
```

* Returns directory contents on server. The flag `--path` allows the client to specify the path inside the server directory to list.
* Response: `Displaying content... ` followed by `<target dir>\n` entries. If there are more than two files, the server will ask the client if it would like to fetch more content from the directory. 

### GET

```
get <src> <dst>
```

* Retrieves a file from the server at `<src>` and places it at `<dst>`. 
* On success, returns `File '<file>', Size <file size> downloaded successfully.`

### PUT

```
put <src> <dst>
```

* Retrieves a file from the client at `<src>` and places it at `<dst>` on the server.
* On success, returns `File '<file>', Size <file size> downloaded successfully.`

### MKDIR

```
mkdir <dir_path>
```

* Creates directory on the server.
* On success, returns `Directory '<dir name>' successfully created.`

### DELETE

```
delete <file_path>
```

* Deletes the file or directory at the given file path on the server.
* On success, returns `File '<file>' deleted successfully.`

### QUIT

```
quit
```

* Closes session and connection.

## Session Management

* Upon successful LOGIN, server generates a `session_id` which is held by the cloent.
* Each subsequent command must include a valid, unexpired `session_id`.
* Sessions expire after `<timeout>` seconds of inactivity.
* On expiry, client must re-login to build a new session and sessionID


## Cleanup and Shutdown

* Press **Ctrl+C** to trigger SIGINT handler.
* Server will:

  1. Close active connections.
  2. Free all allocated memory (sessions, buffers).
  3. Exit gracefully.


## Known Issues

* I know of no issues currently present in the server or client. If you are presented with a bug, please report it to me.


*End of User Manual*
