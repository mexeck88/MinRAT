""" protocol_handler.py

This module contains the ProtocolHandler class, which is responsible for handling the outgoing
and incoming data packets for the MinRAT Server. It provides a methods to structure and send 
the relevent data packets for the server. It also provides methods to parse and handle the incoming data packets
from the server.
"""

import socket
import struct

def send_recv_packet_to_sever(host, port, packet):
    """
    Sends a packet to the server.
    :param host: The server's hostname or IP address.
    :param port: The server's port number.
    :param packet: The packet to send.
    """
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as client_socket:
            client_socket.connect((host, port))
            client_socket.settimeout(15) # prevent infinite wait for response

            # Check packet size
            if len(packet) > 2048:
                raise ValueError("Packet size exceeds maximum limit of 2048 bytes.")

            client_socket.sendall(packet)
            response = client_socket.recv(2048)

    except Exception as e:
        print(f"Error sending packet to server: {e}")
        return None
    
    return response


# Only need to parse the packets that aren't just a ret code from the server.

def parse_ls_packet(response):
    """
    Parses the LS packet received from the server.
    :param response: The response packet from the server.
    :return: A tuple containing the return code, content length, and content.
    """
    CONTENT_LEN_OFFSET = 4
    MESSAGE_LEN_OFFSET = 8
    CUR_POS_OFFSET = 12
    CONTENT_OFFSET= 16

    try:
        retcode = response[0]
        content_len = struct.unpack("!I", response[CONTENT_LEN_OFFSET:MESSAGE_LEN_OFFSET])[0]
        message_len = struct.unpack("!I", response[MESSAGE_LEN_OFFSET:CUR_POS_OFFSET])[0]
        cur_pos = struct.unpack("!I", response[CUR_POS_OFFSET:CONTENT_OFFSET])[0]
        content = response[CONTENT_OFFSET:CONTENT_OFFSET + content_len]
        return retcode, content_len, message_len, cur_pos, content
    except Exception as e:
        print(f"Error parsing ls packet: {e}")
        return None, None, None, None, None


def parse_get_packet(response):
    """
    Parses the get packet received from the server.
    :param response: The response packet from the server.
    :return: A tuple containing the return code, content length, and content.
    """
    # Offsets for the packet structure
    CONTENT_LEN_OFFSET = 2
    CONTENT_OFFSET = 6

    try:
        retcode = response[0]

        if retcode == 0xff:
            return retcode, None, None
        content_len = struct.unpack("!I", response[CONTENT_LEN_OFFSET:CONTENT_OFFSET])[0]
        content = response[CONTENT_OFFSET:CONTENT_OFFSET + content_len].decode('utf-8')
        return retcode, content_len, content
    except Exception as e:
        print(f"Error parsing user packet: {e}")
        return None, None, None
