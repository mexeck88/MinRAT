#!/usr/bin/env python3

""" Client.py

Python client code for the MinRAT project.

This code is responsible for connecting to the server, sending commands,
and receiving responses.

Utilizes the Argparse library for command line argument parsing
and the Cmd library for interactive command handling.

Author: 2LT Matt Eckert

Date: 08APR2024

"""

import signal
import sys
import argparse
from client_shell import ClientShell


def handle_sigint(_signal, _frame):
    """
    Handle SIGINT signal
    """
    print("\nReceived SIGINT. Exiting gracefully...")
    sys.exit(0)

signal.signal(signal.SIGINT, handle_sigint)

def parse_cli_args(args, host, port):
    """
    This function is executed on startup and parses the command line arguments.
    Its intent is to allow full functionality of the client without needing
    to enter the interactive shell.
    """
    parser = argparse.ArgumentParser(description="Client CLI to interact with server")

    subparsers = parser.add_subparsers(title="Commands", dest="command", required=True)

    parser_put = subparsers.add_parser("put", help="Put a file to the server")
    parser_put.add_argument("src", help="Source file path")
    parser_put.add_argument("dst", help="Destination file path")

    parser_get = subparsers.add_parser("get", help="Get a file from the server")
    parser_get.add_argument("src", help="Source file path")
    parser_get.add_argument("dst", help="Destination file path")

    parser_help = subparsers.add_parser("help", help="Show help for a command")
    parser_help.add_argument("command", nargs="?", help="Command to show help for")

    parser_quit = subparsers.add_parser("quit", help="Quit the client")
    parser_quit.set_defaults(command="quit")

    parser_delete = subparsers.add_parser("delete", help="Delete a file on the server")
    parser_delete.add_argument("path", help="Path to the file on the server")

    parser_l_delete = subparsers.add_parser("l_delete", help="Delete a file on the " \
    "local machine")
    parser_l_delete.add_argument("path", help="Path to the file on the local machine")

    parser_ls = subparsers.add_parser("ls", help="List files on the server")
    parser_ls.add_argument("path", nargs="?", default=None, help="Path to list files from")

    parser_l_ls = subparsers.add_parser("l_ls", help="List files on the local machine")
    parser_l_ls.add_argument("path", nargs="?", default=None, help="Path to list files from")

    parser_mkdir = subparsers.add_parser("mkdir", help="Create a directory on the server")
    parser_mkdir.add_argument("path", help="Path to create the directory on the server")

    parser_l_mkdir = subparsers.add_parser("l_mkdir", help="Create a directory on " \
    "the local machine")
    parser_l_mkdir.add_argument("path", help="Path to create the directory on the " \
    "local machine")

    parser_login = subparsers.add_parser("login", help="Login to the server")
    parser_login.add_argument("username", help="Username for login")
    parser_login.add_argument("password", help="Password for login")

    parser_create_user = subparsers.add_parser("create_user", help="Create a new " \
    "user on the server")
    parser_create_user.add_argument("username", help="Username for the new user")
    parser_create_user.add_argument("password", help="Password for the new user")
    parser_create_user.add_argument("permission", help="Permission level for the " \
    "new user [READ, READ/WRITE, ADMIN]")

    parser_delete_user = subparsers.add_parser("delete_user", help="Delete a user " \
    "on the server")
    parser_delete_user.add_argument("username", help="Username of the user to delete")

    cli_args = parser.parse_args(args)
    shell = ClientShell(host, port)

    cmd_method = getattr(shell, f"do_{cli_args.command}")

    if cmd_method is None:
        print(f"Error: Command '{cli_args.command}' not recognized.")
        sys.exit(1)

    cmd_args = {key: value for key, value in vars(cli_args).items() if key
not in ["command"] and value is not None}
    cmd_line = " ".join(cmd_args.values())
    cmd_method(cmd_line)
    shell.cmdloop()


def main():
    """
    Main Client Driver Function.
    Handles command line arguments and dispatches to the appropriate
    handler functions.
    """

    cli_parser = argparse.ArgumentParser(description="MinRAT Client",
usage="""client.py --host <host> --port <port> <command> [<args>]

Commands:

    User Management:
    ------------------
    login <username> <password>                    Login to the server with <username> and <password>
    create_user <username> <password> <permission> Create a new user on the server with <username> and <password> and \
permission level equal to or below the current user [READ, READ/WRITE, ADMIN]
    delete_user <username>                         Delete a user on the server with <username> and permission level \
equal to or below the current user
    ------------------

    Client Actions:
    ------------------
    get <src> <dst>        Get a file from the server
    put <src> <dst>        Put a file to the server
    help [opt: command]    Show help for a command
    quit/exit              Exit the client
    delete <path>          Delete a file on the server at <path>
    l_delete <path>        Delete a file on the local machine at <path>
    ls <optional path>     List files on the server at <path>
    l_ls <optional path>   List files on the local machine at <path>
    mkdir <path>           Create a directory on the server at <path>
    l_mkdir <path>         Create a directory on the local machine at <path>
    -------------------
                                     """)

    cli_parser.add_argument("--host", type=str, default="localhost",
help="Server hostname or IP address")
    cli_parser.add_argument("--port", type=int, default=8080, help="Server port number")

    cli_parser.add_argument("subcommand", nargs=argparse.REMAINDER, help="Command to execute")

    args = cli_parser.parse_args()

    # Check for valid args

    if args.host == "localhost":
        print("WARNING: deafult host 'Localhost' is being used. This may " \
        "not be the intended host. Please specify " \
        "a host when launching the client.")

    if args.port == 8080:
        print("WARNING: deafult port '8080' is being used. This may not be " \
        "the intended port. Please specify a " \
        "port when launching the client.")

    if args.host is None or args.port is None:
        print("Error: Host and port must be specified.")
        sys.exit(1)

    if args.port < 1 or args.port > 65535:
        print("Error: Port must be between 1 and 65535.")
        sys.exit(1)

    if args.host == "":
        print("Error: Host cannot be empty.")
        sys.exit(1)

    #check subcommand in parse func

    if args.subcommand:
        parse_cli_args(args.subcommand, args.host, args.port)
    else:
        shell = ClientShell(args.host, args.port)
        shell.cmdloop()

if __name__ == "__main__":

    signal.signal(signal.SIGINT, handle_sigint)
    main()
