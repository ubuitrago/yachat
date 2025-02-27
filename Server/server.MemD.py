import socket
import argparse
import sys
import textwrap
import logging
import threading
from dataclasses import dataclass

# Return Codes
RETURN_CODES = {
    0: "Exited normally.",
    1: "Failed TCP connection with Server.",
    2: "Server not started?",
}
# Member Class for creating member objects
@dataclass
class Member:
    """Encapsulated Identity Data for each member of the Chat Room"""
    screen_name: str
    ip: str
    port: int

# Global list shared by all threads
members_list: list[Member] = []

def format_return_codes(codes):
    header = "|--------------------------------------------------|"
    # Header line for table
    table_lines = [
        header,
        "|  Code |             Description                  |",
        header
    ]

    for code, description in codes.items():
        table_lines.append(f"|   {code:<3} |\t{description:<35}|")
    table_lines.append(header)
    return "\n".join(table_lines)

def populate_member_list(datagram: tuple[str,str,int]):
    """Manages reference to the global members_list
        Insert members into 2D dataclass table
        [ Member(screen_name, IP, PORT), Member() ]
    """
    members_list.append(Member(screen_name=datagram[0], ip=datagram[1], port=datagram[2]))
    logger.debug("member_list -> %s\n",members_list)

def send_join_protocol(new_member: Member) -> bool:
    """Notification sent to ALL Chatter clients over their 
    UDP ports to let them know that a new member has entered the chatroom. [UDP]"""
    # Establish UDP Socket
    udp_sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    join = f"JOIN {new_member.screen_name} {new_member.ip} {new_member.port}\n"
    for member in members_list:
        logger.debug("Broadcasting JOIN to: %s", member)
        try:
            udp_sock.sendto(join.encode(),(member.ip,member.port))
        except Exception as e:
            logger.debug(e)
            return False
    return True

def servant(connection_socket:socket.socket, return_address:int):
    # Expect to recieve HELO protocol message
    msg = connection_socket.recv(4096)

    if msg == b"":
        logger.debug("Client closed connection")
        return
    else:
        msg_list = msg.decode().split()
        # Parse HELO protocol
        if len(msg_list) == 4 and "HELO" == msg_list[0]:
            new_screen_name = msg_list[1]
            if not any(member.screen_name == new_screen_name for member in members_list):
                # Populate Members List
                populate_member_list((new_screen_name,return_address,msg_list[3]))
                # Send ACPT
                acpt = "ACPT "
                for index, member in enumerate(members_list):
                    if index != len(members_list) - 1:
                        acpt += f"{member.screen_name} {member.ip} {member.port}:"
                    else:
                        acpt += f"{member.screen_name} {member.ip} {member.port}\n"
                connection_socket.send(acpt.encode())
                # Send JOIN
                send_join_protocol(members_list[members_list.index(Member.screen_name == new_screen_name)])
            else:
                # Send RJCT
                rjct = f"RJCT {screen_name}\n"
                connection_socket.send(rjct.encode())
                connection_socket.close()
                return
        # Block 

def start_server(accept_port:int = 7676):
    welcome_sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    try:
        welcome_sock.bind(("",accept_port))
    except socket.error as message:
        print(f"Bind failed. Error Code: {str(message[0])} Message {message[1]}")
        sys.exit()
    logger.debug("Binded to Welcome Port")
    # Listen for incoming connections
    logger.debug("Welcome socket listening...")
    while True:
        welcome_sock.listen(9)
        c, addr = welcome_sock.accept()
        # Spawn a new thread to handle the client
        client_handler = threading.Thread(target=servant, args=(c, addr))
        client_handler.start()

if __name__ == "__main__":
    # Color & Terminal formatting
    MAGENTA = "\033[35m"
    RED    = "\033[31m"
    YELLOW = "\033[33m"
    RESET  = "\033[0m"
    # Init argparse
    parser = argparse.ArgumentParser(prog="Chatter Server",
                                    formatter_class=argparse.RawDescriptionHelpFormatter,
                                    usage="server.MemD.py [port]",
                                    description="Memmbership Server for YaChat",
                                    epilog=textwrap.dedent(f"This server manages member connections.\n\nReturn Codes:\n{format_return_codes(RETURN_CODES)}")
                                    )
    parser.add_argument(
        "port",
        type=int,
        help="Port to Welcome Client Connections"
    )
    parser.add_argument(
        "-d",
        action="store_true",
        help="Debug level logging"
    )
    args = parser.parse_args()
    # Init logger for Debugging
    logging.basicConfig(
        level="DEBUG" if args.d else "INFO",
        format=f"{YELLOW}%(asctime)s{RESET} - {RED}%(levelname)s{RESET} - {MAGENTA}%(message)s{RESET}"
    )

    logger = logging.getLogger("ClientLogger")
    # Validate Port Provided
    try:
        memd_port = int(args.port)
    except (ValueError) as e:
        print(e)
        sys.exit(1)

    start_server(accept_port=memd_port)