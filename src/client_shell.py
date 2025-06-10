"""
client_shell.py

This module contains the ClientShell class, which is responsible for handling
the client-side shell operations. It provides methods to execute commands, manage
the shell environment, and handle user input and output. The class is designed to
interact with the server and perform various operations based on user commands.
"""

import argparse
import os
import cmd
import struct
from protocol_handler import send_recv_packet_to_sever, parse_get_packet, parse_ls_packet

class ClientShell(cmd.Cmd):
    """
    ClientShell class to handle client-side shell operations. It inherents from cmd.Cmd
    and provides methods to execute commands, manage the shell environment, and handle
    user input and output.
    """

    intro = "\nMinRAT Interactive Client Shell. Type 'help' or '?' for command list.\n"
    prompt = "MinRAT> "

    def __init__(self, host, port):
        super().__init__()
        self.host = host
        self.port = port
        self.session_id = None
        self.ls_cur_pos = 0 # used to keep track of the current position in the ls output

    def emptyline(self):
        """
        Override the default behavior of repeating the last command when an empty line is entered.
        """
        print("No command entered. Type 'help' or '?' for a list of commands.")

    def default(self, line):
        """
        Handle unrecognized commands
        """
        print(f"Unrecognized command: {line}. Type 'help' for a list of commands.")

    def do_get(self, args):
        """
        Handle the GET command
        """
        # Parse the arguments
        parser = argparse.ArgumentParser(prog="get")
        parser.add_argument("src", help="Source file path")
        parser.add_argument("dst", help="Destination file path")

        try:
            parsed_args = parser.parse_args(args.split())
            server_filename = parsed_args.src
            client_dst = parsed_args.dst

            file_dst = os.path.join(client_dst, server_filename)
            file_dst = os.path.realpath(file_dst)

            # Build out server request packet make sure they are in network byte order
            get_opcode = 0x04 # unint8_t
            reserved = 0x00 # unint8_t
            src_len = len(server_filename) # unint16_t

            if self.session_id is None:
                raise ValueError("Session ID is not set. Please login first.")

            session_id = self.session_id # unint32_t

            # use Struct to pack the data into a packet
            packet = struct.pack("!B B H I", get_opcode, reserved, 
                                 src_len, session_id) + server_filename.encode()

            # Send packet to server
            response = send_recv_packet_to_sever(self.host, self.port, packet)

            # Handle server response
            if response is None:
                raise ValueError("No response from server.")

            retcode, content_len, content = parse_get_packet(response) # Parse the response packet

            # Write the received data to the destination file

            if 0x01 == retcode:
                with open(file_dst, "w", encoding="utf-8") as file:
                    file.write(content)
                print(f"File '{server_filename}', Size {content_len} downloaded successfully.")
            elif 0x02 == retcode:
                print("Session Error: Session ID was invalid or expired.")
            elif 0x03 == retcode:
                print("Permission Error: You do not have permission to access this file.")
            elif 0xff == retcode:
                print("Server Error: An error occurred on the server.")

        except SystemExit:
            print("Error: Incorrect Arguments for GET command. Use 'help get' "
            "for more information.")

        except Exception as err:
            print(f"Error: {err}.")

    def do_put(self, args):
        """
        Handle the PUT command
        """
        # Parse the arguments
        parser = argparse.ArgumentParser(prog="put")
        parser.add_argument("src", help="Source file path")
        parser.add_argument("dst", help="Destination file path")

        try:
            parsed_args = parser.parse_args(args.split())
            client_filename = parsed_args.src
            server_dst = parsed_args.dst

            dest_filepath = server_dst+client_filename

            # Build out server request packet make sure they are in network byte order
            put_opcode = 0x06 # unint8_t

            print("If the file exists on the server, would you like to overwrite it? (y/n)")
            overwrite = input().strip().lower()

            if 'y' == overwrite:
                overwrite = 0x01 # unint8_t
            elif 'n' == overwrite:
                overwrite = 0x00
            else:
                raise ValueError("Invalid input. Please enter 'y' or 'n'.")

            # Verify the file is no a directory
            if os.path.isdir(client_filename):
                raise ValueError("Source file is a directory. Please provide a file path.")

            src_len = len(dest_filepath) # unint16_t

            if self.session_id is None:
                raise ValueError("Session ID is not set. Please login first.")

            session_id = self.session_id # unint32_t

            file_content_len = os.path.getsize(client_filename) # unint32_t
            if file_content_len > 1016:
                raise ValueError("File size exceeds maximum limit.")

            # use Struct to pack the data into a packet
            packet = struct.pack("!B B H I I", put_opcode, overwrite, src_len,
session_id, file_content_len) + dest_filepath.encode()

            with open(client_filename, "rb") as file:
                file_content = file.read(file_content_len)
                packet += file_content

            # Send packet to server
            response = send_recv_packet_to_sever(self.host, self.port, packet)

            # Handle server response
            if response is None:
                raise ValueError("No response from server.")

            retcode = response[0] # Parse the response packet

            # Write the received data to the destination file

            if 0x01 == retcode:
                print(f"File '{client_filename}', Size {file_content_len} uploaded successfully.")
            elif 0x02 == retcode:
                print("Session Error: Session ID was invalid or expired.")
            elif 0x03 == retcode:
                print("Permission Error: You do not have permission to access this file.")
            elif 0x05 == retcode:
                print("File Error: File already exists on the server.")
            elif 0xff == retcode:
                print("Server Error: An error occurred on the server.")

        except SystemExit:
            print("Error: Incorrect Arguments for PUT command. Use 'help put' "
            "for more information.")

        except Exception as err:
            print(f"Error: {err}.")

    def do_help(self, arg):
        """
        Handle the HELP command
        """
        commands = {
        "login": "Login to the server. Usage: login <username> <password>",
        "create_user": "Create a new user on the server. Usage: <username> "
        "<password> <permission> [r, rw, admin]",
        "delete_user": "Delete a user on the server. Usage: delete_user <username>",
        "get": "Get a file from the server. Usage: get <src> <dst>",
        "put": "Put a file to the server. Usage: put <src> <dst>",
        "delete": "Delete a file on the server. Usage: delete <path>",
        "l_delete": "Delete a file on the local machine. Usage: l_delete <path>",
        "ls": "List files on the server at <path> (optional). Usage: ls [--path <path>]",
        "l_ls": "List files on the local machine at <path> (optional). Usage: "
        "l_ls [--path <path>]",
        "mkdir": "Create a directory on the server. Usage: mkdir <path>",
        "l_mkdir": "Create a directory on the local machine. Usage: l_mkdir <path>",
        "help": "Show help for a command. Usage: help [command]",
        "quit": "Exit the client",
    }

        if not arg.strip():
            # Display a list of all commands
            print("Available commands:")
            for command, description in commands.items():
                print(f"  {command:<12} {description}")
        else:
            # Display help for a specific command
            command = arg.strip()
            if command in commands:
                print(f"{command}: {commands[command]}")
            else:
                print(f"Unknown command: {command}. Type 'help' to see the \
list of available commands.")

    def do_quit(self):
        """
        Handle the QUIT command
        """
        print("Exiting the client shell.")
        return True

    def do_delete(self, args):
        """
        Handle the DELETE command
        """
        parser = argparse.ArgumentParser(prog="delete")
        parser.add_argument("path", help="Path to the file to delete on server")

        try:
            parsed_args = parser.parse_args(args.split())

            opcode = 0x02 # unint8_t
            reserved = 0x00 # unint8_t
            filename = parsed_args.path
            filename_len = len(filename) # unint16_t

            if self.session_id is None:
                raise ValueError("Session ID is not set. Please login first.")

            session_id = self.session_id # unint32_t

            # use Struct to pack the data into a packet
            packet = struct.pack("!B B H I", opcode, reserved, filename_len,
session_id) + filename.encode()

            # Send packet to server
            response = send_recv_packet_to_sever(self.host, self.port, packet)

            # Handle server response
            if response is None:
                raise ValueError("No response from server.")

            retcode = response[0] # Parse the response packet

            # Write the received data to the destination file

            if 0x01 == retcode:
                print(f"File '{filename}' deleted successfully.")
            elif 0x02 == retcode:
                print("Session Error: Session ID was invalid or expired.")
            elif 0x03 == retcode:
                print("Permission Error: You do not have permission to delete this file.")
            elif 0xff == retcode:
                print("Server Error: An internal error occurred on the server.")

        except SystemExit:
            print("Error: Incorrect Arguments for DELETE command. Use "
            "'help delete' for more information.")

        except Exception as err:
            print(f"Error: {err}. Use 'help login' for more information.")


    def do_l_delete(self, args):
        """
        Handle the L_DELETE command
        """
        parser = argparse.ArgumentParser(prog="l_delete")
        parser.add_argument("path", help="Path to the file to delete on local machine")

        try:
            parsed_args = parser.parse_args(args.split())

            if os.path.exists(parsed_args.path):
                os.remove(parsed_args.path)
                print(f"File '{parsed_args.path}' deleted successfully.")
            else:
                print(f"File '{parsed_args.path}' does not exist.")

        except SystemExit:
            print("Error: Incorrect Arguments for L_DELETE command. " \
            "Use 'help l_delete' for more information.")

        except Exception as err:
            print(f"Error: {err}.")

    def do_ls(self, args):
        """
        Handle the LS command
        """
        # probably need to do a loop that checks if there is more content
        # left and then asks if the user wants more
        parser = argparse.ArgumentParser(prog="ls")
        parser.add_argument("--path", help="Path to the directory to list on server")
        self.ls_cur_pos = 0 # reset the current position for ls command

        b_continue = True
        while b_continue:
            try:
                parsed_args = parser.parse_args(args.split())

                opcode = 0x03 # unint8_t
                reserved = 0x00 # unint8_t
                cur_pos = self.ls_cur_pos # unint16_t

                if parsed_args.path:
                    dir_path = parsed_args.path
                else:
                    dir_path = "/"

                dir_path_len = len(dir_path) # unint16_t

                if self.session_id is None:
                    raise ValueError("Session ID is not set. Please login first.")

                session_id = self.session_id # unint32_t

                # use Struct to pack the data into a packet
                packet = struct.pack("!B B H I I", opcode, reserved, dir_path_len,
session_id, cur_pos) + dir_path.encode()

                # Send packet to server
                response = send_recv_packet_to_sever(self.host, self.port, packet)

                # Handle server response
                if response is None:
                    raise ValueError("No response from server.")

                retcode, content_len, message_len, cur_pos, content = parse_ls_packet(response) # Parse the response packet
                self.ls_cur_pos = cur_pos
                

                print(f"Displaying content... {content_len} bytes received, \
{message_len} bytes of message, current position: {cur_pos}")

                if content_len == 1:
                    b_continue = False
                    raise ValueError("No content available at specified " \
                    "path")

                if 0x02 == retcode:
                    raise ValueError("Session Error: Session ID was " \
                    "invalid or expired")
                elif 0x03 == retcode:
                    raise ValueError("Permission Error: You do not have " \
                    "permission to access this directory")
                elif 0xff == retcode:
                    raise ValueError("Server Error: An error occurred " \
                    "on the server")
                elif 0x00 == retcode:
                    raise ValueError("No content available at specified " \
                    "path")


                # unpack content

                file_1_name = None
                file_1_type = None
                file_2_name = None
                file_2_type = None

                content = content.split(b'\x00')

                if content[1] != b'': #Check for second file
                    if content[0][0] == 0x01:
                        file_1_type = "File"
                    elif content[0][0] == 0x02:
                        file_1_type = "Directory"

                    if content[1][0] == 0x01:
                        file_2_type = "File"
                    elif content[1][0] == 0x02:
                        file_2_type = "Directory"

                    file_1_name = content[0][1:].decode()
                    file_2_name = content[1][1:].decode()
                else:
                    if content[0][0] == 0x01:
                        file_1_type = "File"
                    elif content[0][0] == 0x02:
                        file_1_type = "Directory"

                    file_1_name = content[0][1:].decode()

                # Write the received data to the destination file

                if 0x01 == retcode:
                    print(f"Directory listing for '{dir_path}':\n \
{file_1_name} --- {file_1_type}\n {file_2_name} --- {file_2_type}")

                    if cur_pos < content_len-1:
                        print("More content available. Do you want " \
                        "to fetch more? (y/n)")
                        user_input = input().strip().lower()
                        if user_input == 'y':
                            b_continue = True
                        elif user_input == 'n':
                            b_continue = False
                        else:
                            print("Invalid input. Please enter 'y' "
                            "or 'n'.")
                            b_continue = False
                    else:
                        print("No more content available.")
                        b_continue = False

            except SystemExit:
                print("Error: Incorrect Arguments for LS command. Use "
                "'help ls' for more information.")
                b_continue = False
            except Exception as err:
                print(f"Error: {err}.")
                b_continue = False


    def do_l_ls(self, args):
        """
        Handle the L_LS command
        """
        parser = argparse.ArgumentParser(prog="l_ls")
        parser.add_argument("--path", help="Path to the directory to list " \
        "on client")

        try:
            parsed_args = parser.parse_args(args.split())

            if parsed_args.path:
                if not os.path.exists(parsed_args.path):
                    raise ValueError(f"Path '{parsed_args.path}' does not exist.")
                if not os.path.isdir(parsed_args.path):
                    raise ValueError(f"Path '{parsed_args.path}' is not a directory.")
                dir_path = parsed_args.path
            else:
                dir_path = os.getcwd()

            files = os.listdir(dir_path)
            print(f"Files in '{dir_path}':")
            for file in files:
                print(file)

        except SystemExit:
            print("Error: Incorrect Arguments for L_LS command. " \
            "Use 'help l_ls' for more information.")
        except Exception as err:
            print(f"Error: {err}.")



    def do_mkdir(self, args):
        """
        Handle the MKDIR command
        """
        parser = argparse.ArgumentParser(prog="mkdir")
        parser.add_argument("path", help="Path to the directory to create on server")

        try:
            parsed_args = parser.parse_args(args.split())

            opcode = 0x05 # unint8_t
            reserved = 0x00 # unint8_t and uint32_t
            dirname = parsed_args.path
            dirname_len = len(dirname) # unint16_t

            if self.session_id is None:
                raise ValueError("Session ID is not set. Please login first.")

            session_id = self.session_id # unint32_t

            # use Struct to pack the data into a packet
            packet = struct.pack("!B B H I I", opcode, reserved, dirname_len,\
session_id, reserved) + dirname.encode()

            # Send packet to server
            response = send_recv_packet_to_sever(self.host, self.port, packet)

            # Handle server response
            if response is None:
                raise ValueError("No response from server.")

            retcode = response[0]

            # Write the received data to the destination file

            if 0x01 == retcode:
                print(f"Directory '{dirname}' successfully created.")
            elif 0x02 == retcode:
                print("Session Error: Session ID was invalid or expired.")
            elif 0x03 == retcode:
                print("Permission Error: You do not have permission to create directories.")
            elif 0x05 == retcode:
                print("File Error: File already exists on the server.")
            elif 0xff == retcode:
                print("Server Error: An internal error occurred on the server.")

        except SystemExit:
            print("Error: Incorrect Arguments for MKDIR command. " \
            "Use 'help mkdir' for more information.")

        except Exception as err:
            print(f"Error: {err}.")


    def do_l_mkdir(self, args):
        """
        Handle the L_MKDIR command
        """
        parser = argparse.ArgumentParser(prog="l_mkdir")
        parser.add_argument("path", help="Path to the directory to create on client")

        try:
            parsed_args = parser.parse_args(args.split())

            dir_path = parsed_args.path

            if 0 == os.system(f"mkdir -p {dir_path}"):
                print(f"Directory '{dir_path}' successfully created.")
            else:
                raise ValueError(f"Failed to create directory '{dir_path}'.")

        except SystemExit:
            print("Error: Incorrect Arguments for L_MKDIR command. " \
            "Use 'help l_mkdir' for more information.")
        except Exception as err:
            print(f"Error: {err}.")

    def do_login(self, args):
        """
        Handle the LOGIN command
        """
        parser = argparse.ArgumentParser(prog="login")
        parser.add_argument("username", help="Username for login")
        parser.add_argument("password", help="Password for login")

        try:
            parsed_args = parser.parse_args(args.split())

            username = parsed_args.username
            password = parsed_args.password
            username_len = len(username) # unint16_t
            password_len = len(password) # unint16_t
            user_flag = 0x00 # unint8_t / Login flag
            reserved = 0x0000 # unint16_t

            # Build out server request packet make sure they are in network byte order
            user_opcode = 0x01 # unint8_t
            session_id = 0x00000000 # unint32_t / No session ID for login request



            # use Struct to pack the data into a packet
            packet = struct.pack("!B B H H H I", user_opcode, user_flag, reserved,
username_len, password_len, session_id) + username.encode() + password.encode()

            # Send packet to server
            response = send_recv_packet_to_sever(self.host, self.port, packet)

            # Handle server response
            if response is None:
                raise ValueError("No response from server.")

            retcode = response[0]

            if retcode == 0x01:
                # Extract the session ID from the response
                self.session_id = struct.unpack("!I", response[2:6])[0]
                print(f"Login successful. Session ID: {self.session_id}.")
            elif retcode == 0xff:
                print("Server Error: LOGIN FAILED, username or " \
                "password may be incorrect or the user may not exist.")

        except SystemExit:
            print("Error: Incorrect Arguments for LOGIN command. " \
            "Use 'help login' for more information.")

        except Exception as err:
            print(f"Error: {err}.")

    def do_create_user(self, args):
        """
        Handle the CREATE_USER command
        """
        parser = argparse.ArgumentParser(prog="create_user")
        parser.add_argument("username", help="Username for the new user")
        parser.add_argument("password", help="Password for the new user")
        parser.add_argument("permission", help="Permission level for the new user [r, rw, admin]")

        try:
            parsed_args = parser.parse_args(args.split())

            username = parsed_args.username
            password = parsed_args.password
            permission_name = parsed_args.permission
            permission = 0x00
            username_len = len(username) # unint16_t
            password_len = len(password) # unint16_t

            if permission_name == "r":
                permission = 0x01 # unint8_t
            elif permission_name == "rw":
                permission = 0x02
            elif permission_name == "admin":
                permission = 0x03

            if self.session_id is None:
                raise ValueError("Session ID is not set. Please login first.")

            session_id = self.session_id # unint32_t

            # Build out server request packet make sure they are in network byte order
            create_user_opcode = 0x01 # unint8_t
            reserved = 0x0000 # unint16_t

            # use Struct to pack the data into a packet
            packet = struct.pack("!B B H H H I", create_user_opcode, permission, reserved,
username_len, password_len, session_id) + username.encode() + password.encode()

            # Send packet to server
            response = send_recv_packet_to_sever(self.host, self.port, packet)

            # Handle server response
            if response is None:
                raise ValueError("No response from server.")

            retcode = response[0] # Parse the response packet

            if 0x01 == retcode:
                print(f"User '{username}' created successfully with \
                      permission '{permission_name}'.")
            elif 0x02 == retcode:
                print("Session Error: Session ID was invalid or expired.")
            elif 0x03 == retcode:
                print("Permission Error: You do not have permission to create this user.")
            elif 0x04 == retcode:
                print("User Error: User already exists.")
            elif 0xff == retcode:
                print("Server Error: An error occurred on the server.")

        except SystemExit:
            print("Error: Incorrect Arguments for CREATE_USER command. " \
            "Use 'help create_user' for more information.")

        except Exception as err:
            print(f"Error: {err}.")

    def do_delete_user(self, args):
        """
        Handle the DELETE_USER command
        Only an admin user can delete another user.
        """
        parser = argparse.ArgumentParser(prog="delete_user")
        parser.add_argument("username", help="Username of the user to delete")

        try:
            parsed_args = parser.parse_args(args.split())

            username = parsed_args.username
            username_len = len(username) # unint16_t

            if self.session_id is None:
                raise ValueError("Session ID is not set. Please login as admin first.")

            session_id = self.session_id # unint32_t

            # Build out server request packet make sure they are in network byte order
            user_opcode = 0x01 # unint8_t
            delete_user_flag = 0xff # unint8_t / Delete user flag
            reserved = 0x0000 # unint16_t
            password_len = 0x00 # unint16_t / No password for delete user request

            # use Struct to pack the data into a packet
            packet = struct.pack("!B B H H H I", user_opcode,
delete_user_flag, reserved, username_len, password_len, session_id) + username.encode()

            # Send packet to server
            response = send_recv_packet_to_sever(self.host, self.port, packet)

            # Handle server response
            if response is None:
                raise ValueError("No response from server.")

            retcode = response[0] # Parse the response packet

            if 0x01 == retcode:
                print(f"User '{username}' deleted successfully.")
            elif 0x02 == retcode:
                print("Session Error: Session ID was invalid or expired.")
            elif 0x03 == retcode:
                print("Permission Error: You do not have permission to delete this user.")
            elif 0x05 == retcode:
                print("Server Error: User can not delete themselves.")
            elif 0xff == retcode:
                print("Server Error: An error occurred on the server.")

        except SystemExit:
            print("Error: Incorrect Arguments for DELETE_USER command. " \
            "Use 'help delete_user' for more information.")

        except Exception as err:
            print(f"Error: {err}.")


    do_exit = do_quit

# END OF FILE
