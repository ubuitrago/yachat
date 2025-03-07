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
    """Formatting method for help menu"""
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

def populate_member_list(datagram: tuple[str,str,int]) -> Member:
    """Manages reference to the global members_list
        Insert members into 2D dataclass table
        [ Member(screen_name, IP, PORT), Member() ]
    """
    new_member = Member(screen_name=datagram[0], ip=datagram[1], port=datagram[2])
    members_list.append(new_member)
    logger.debug("member_list -> %s\n",members_list)
    return new_member

def read_line(conn: socket.socket) -> str:
    """Reads from conencted socket until newline character encountered"""
    buffer = b""
    while True:
        chunk = conn.recv(4096)
        if not chunk:
            # Client closed connection or error
            raise ConnectionError("Socket closed before newline")
        buffer += chunk
        if b"\n" in chunk:
            break
    # Return entire line as string
    return buffer.decode()

def send_broadcasting_protocols(self_member: Member, protocol: str) -> bool:
    """Notification sent to ALL Chatter clients over their 
    UDP ports to let them know that a new member has entered the chatroom,
    OR to let them know that a member has left.[UDP]
    
    Parameters:
        self_member (Member): Member data object triggering the JOIN or EXIT
        protocol (str): JOIN or EXIT

    Return:
        bool
    """
    if protocol not in ["JOIN","EXIT"]:
        logger.error("Protocol %s not recognized", protocol)
        return False
    # Establish UDP Socket
    udp_sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    if protocol == "EXIT":
        proto = f"{protocol} {self_member.screen_name}\n"
        # Broadcast to self_member first since they're waiting on server approval
        udp_sock.sendto(proto.encode(), (self_member.ip,self_member.port))
        logger.debug("EXIT ACKNOWLEDGED")
    else:
        proto = f"{protocol} {self_member.screen_name} {self_member.ip} {self_member.port}\n"
    # Broadcast to all members
    for member in members_list:
        logger.debug("Broadcasting %s to: %s", protocol, member)
        try:
            udp_sock.sendto(proto.encode(),(member.ip,member.port))
        except Exception as e:
            logger.error(e)
        
    udp_sock.close()
    return True

def servant(connection_socket:socket.socket, return_address:str):
    # Expect to recieve HELO protocol message
    msg = read_line(connection_socket)
    logger.debug("Server Recieved: %s",msg)

    if msg == b"":
        logger.debug("Client closed connection")
        return
    else:
        msg_list = msg.split()
        # Parse HELO protocol
        if len(msg_list) == 4 and "HELO" == msg_list[0]:
            logger.debug("RECV:%s", msg_list)
            new_screen_name = msg_list[1]
            if not any(member.screen_name == new_screen_name for member in members_list):
                # Populate Members List
                new_member = populate_member_list((new_screen_name,return_address,int(msg_list[3])))
                # Send ACPT
                acpt = "ACPT "
                for index, member in enumerate(members_list):
                    if index != len(members_list) - 1:
                        acpt += f"{member.screen_name} {member.ip} {member.port}:"
                    else:
                        acpt += f"{member.screen_name} {member.ip} {member.port}\n"
                connection_socket.send(acpt.encode())
                logger.debug("SEND:%s", acpt)
                # Send JOIN
                if not send_broadcasting_protocols(new_member,"JOIN"):
                    logger.debug("Unable to send JOIN to all members")
            else:
                # Send RJCT
                rjct = f"RJCT {new_screen_name}\n"
                connection_socket.send(rjct.encode())
                connection_socket.close()
                return
    # Block and waiting on EXIT protocol
    while True:
        exit_msg = connection_socket.recv(32)
        if exit_msg.decode().strip() != "EXIT":
            continue
        else:
            # Remove member from Global List
            try:
                old_member = members_list.pop(members_list.index(new_member))
            except IndexError as e:
                logger.debug("Could not remove member. %s", e)
            # Send EXIT to ALL members
            if not send_broadcasting_protocols(old_member,"EXIT"):
                logger.debug("Unable to send EXIT to all members")
            else:
                connection_socket.close()
                break
    return

def start_server(accept_port:int = 7676):
    welcome_sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    try:
        welcome_sock.bind(("",accept_port))
    except socket.error as message:
        print(f"Bind failed. Error {message}")
        sys.exit()
    logger.debug("Binded to Welcome Port")
    # Listen for incoming connections
    logger.debug("Welcome socket listening...")
    while True:
        welcome_sock.listen(9)
        c, addr = welcome_sock.accept()
        client_ip, client_tcp_port = addr
        logger.debug("Client %s", client_ip)
        # Spawn a new thread to handle the client
        client_handler = threading.Thread(target=servant, args=(c, client_ip))
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