"""
YaChat, a simple yet powerful client chat application
"""
import socket
import argparse
import sys
import string
import logging
import threading
from dataclasses import dataclass
import select
# Threading Sync
event = threading.Event()
@dataclass
class Member:
    """Encapsulated Identity Data for each member of the ChatterChatRoom"""
    screen_name: str
    ip: str
    port: int

members_list: list[Member] = []

#Exceptions
class ScreenNameException(Exception):
    '''For identifying bad screen_names'''

# Color & Terminal formatting
MAGENTA = "\033[35m"
RED    = "\033[31m"
YELLOW = "\033[33m"
RESET  = "\033[0m"
# Helper methods
def contains_whitespace(s):
    """Quick check of spaces in screen names"""
    return True in [c in s for c in string.whitespace]

def get_local_ip() -> str:
    """Return the primary local IP address (IPv4) of this machine."""
    try:
        # Create a temporary UDP socket
        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as s:
            # This "connect" doesn't actually send packets,
            # but allows the OS to determine the default interface.
            s.connect(("8.8.8.8", 80))
            return s.getsockname()[0]
    except Exception:
        # Fallback if we cannot connect to the internet
        return "127.0.0.1"
    
def read_sock(sock) -> str:
    """
    Read from the socket until you see a newline.
    Returns the entire line (str)
    """
    chunks = []
    while True:
        chunk = sock.recv(4096)
        print(chunk)
        if not chunk:
            # Server closed the connection or error
            raise ConnectionError("Server closed connection unexpectedly.")
        chunks.append(chunk)
        # Check if we have a newline
        if b"\n" in chunk:
            break
    data = b"".join(chunks).decode()
    return data

def tcp_server_connect(server_ip: str, server_port: int, screen_name:str) \
        -> tuple[str, socket.socket, socket.socket]:
    """Establishes initial TCP connection to MemD server"""
    #client_ip = socket.gethostbyname(socket.gethostname())
    client_ip = get_local_ip()
    # Create an INET, STREAMing socket
    server_sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    try:
        server_sock.connect((server_ip, server_port))
        logger.debug("Connection successful...")
    except socket.error as e:
        logger.error("Failed to connect: %s", e)
        sys.exit(1)
    # Create UDP Port
    # client_ip = server_sock.getpeername()
    udp_sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    logger.debug("Client IP: %s",client_ip)
    udp_sock.bind((client_ip, 0))
    _, udp_port = udp_sock.getsockname()
    logger.debug("UDP: %s",udp_port)

    # Protocol HELO
    # Send Screen name, IP, and UDP PORT
    msg = f"HELO {screen_name} {client_ip} {udp_port}\n"
    sent = server_sock.send(msg.encode())

    if sent <= 0:
        logger.error("TCP Socket busted")
    else:
        logger.debug("Waiting for ACPT...")

    # Parse ACPT Protocol with specialized method
    data = read_sock(server_sock)
    logger.debug("Recv: %s", data)
    return data, udp_sock, server_sock

def populate_member_list(datagram: tuple[str,str,int]):
    """Manages reference to the global members_list
        Insert members into 2D dataclass table
        [ Member(screen_name, IP, PORT), Member() ]
    """
    members_list.append(Member(screen_name=datagram[0], ip=datagram[1], port=datagram[2]))
    logger.debug("member_list -> %s\n",members_list)

def receive_protocols(screen_name: str, udp_sock:socket.socket) -> None:
    """Thread for reading UDP socket on client and managing INCOMING protocols"""
    while True:
        ready, _, _ = select.select([udp_sock], [], [], 1.0)  # Timeout of 1 sec
        if ready:
            data,_ = udp_sock.recvfrom(4096)
            data = data.decode()
            if not data:
                continue
            else:
                protocol: str = data[0:4]
            # Protocol check
            # if protocol == "ACPT":
            #     in_room = data[5:].split(":") # Format for processing
            #     for person in in_room:
            #         new_screen_name, ip, port = person.split()
            #         logger.debug("person: %s", new_screen_name)
            #         logger.info("%s in room ,:~)", new_screen_name)
            #         populate_member_list((new_screen_name, ip, int(port)))
            if protocol == "JOIN":
                # person: ['<screen_name>', '<IP>', '<Port>']
                new_screen_name, ip, port = data[5:].split() # Format for processing
                if new_screen_name != screen_name:
                    populate_member_list((new_screen_name, ip, int(port)))
                logger.debug("%s Member List -> %s", new_screen_name, members_list)
                logger.info("%s joined the room!", new_screen_name)

            elif protocol == "MESG":
                msg = data[5:].split(":")
                logger.info("%s:%s",msg[0],msg[1])

            elif protocol == "EXIT":
                leaving_screen_name = data[5:].strip()
                try:
                    for index, member in enumerate(members_list):
                        if member.screen_name == leaving_screen_name:
                            removed_member = members_list.pop(index)
                            logger.debug(removed_member)
                    logger.info("%s has left the ChatterRoom!", leaving_screen_name)
                except Exception as e:
                    logger.error(e)
                if leaving_screen_name == screen_name:
                    # Close thread to allow main program flow termination
                    break
        else:
            continue
    event.set()

def send_protocols(screen_name:str, udp_sock:socket.socket, udp_port:int, server_sock:socket.socket):
    """Thread for writing to UDP sockets and managing OUTGOING protocols"""
    reading_input = True
    while reading_input:
        #print("(EXIT to quit) || Message >> ", end="", flush=True)
        # ready, _, _ = select.select([sys.stdin], [], [], 1.0)  # Check for input every 1 sec
        user_message = sys.stdin.readline().strip()
        if not user_message:
            logger.info("No message typed, try again..?")
            continue
        elif user_message == "EXIT":
            user_message += "\n"
            server_sock.send(user_message.encode())
            # exit loop and wait for event set by the receiving thread, i.e. server responded
            reading_input = False
        # Legit message
        elif len(user_message.strip()) > 0:
            # Broadcast message to all members
            for member in members_list:
                msg_to_send = f"MESG {screen_name}: {user_message}\n"
                try:
                    logger.debug("Broadcasting to: %s", member)
                    udp_sock.sendto(msg_to_send.encode(), (member.ip,member.port))
                except Exception as e:
                    logger.error(e)
        else: continue
    event.wait()

def main(**kwargs):
    screen_name = kwargs["screen_name"]
    memd_server = "127.0.0.1" if kwargs["memd_host"] == "localhost" else kwargs["memd_host"]
    memd_connect_port = kwargs["memd_tcp_port"]
    # First attempt
    data, udp_sock, server_sock = tcp_server_connect(memd_server,memd_connect_port,screen_name)
    # Successive attempts
    while data.startswith("RJCT"):
        logger.error("screen_name is already in use!\n")
        screen_name = input("Try another screen_name (type 'exit' to quit) >> ")
        if screen_name.lower() == "exit":
            logger.info("¯\_(ツ)_/¯ Chatter terminating ¯\_(ツ)_/¯")
            sys.exit(3)
        else:
            data, udp_sock, server_sock = tcp_server_connect(memd_server,memd_connect_port,screen_name)
            continue
    # Admitted into Chatroom   
    if data.startswith("ACPT"):
        # Add all members to global list
        in_room = data[5:].split(":") # Format for processing
        for person in in_room:
            new_screen_name, ip, port = person.split()
            logger.debug("person: %s", new_screen_name)
            if new_screen_name != screen_name:
                logger.info("%s in room ,:~)", new_screen_name)
            populate_member_list((new_screen_name, ip, int(port)))
        # Start the receiving thread
        recv_thread = threading.Thread(target=receive_protocols, args=(screen_name, udp_sock), daemon=True)
        recv_thread.start()
        # Start the sending thread
        _, udp_port = udp_sock.getsockname()
        send_thread = threading.Thread(target=send_protocols, args=(screen_name, udp_sock, udp_port, server_sock))
        send_thread.start()

    else:
        logger.debug("!!!Server may have terminated unexpectedly!!!(╯°□°）╯︵ ┻━┻")
        sys.exit(2)

    # teardown
    send_thread.join()
    logger.info("(¬‿¬)Client is shutting down...")
    udp_sock.close()

if __name__ == "__main__":
    LOGO = """
#####################################
 __     __    _____ _           _   
 \ \   / /   / ____| |         | |  
  \ \_/ /_ _| |    | |__   __ _| |_ 
   \   / _` | |    | '_ \ / _` | __|
    | | (_| | |____| | | | (_| | |_ 
    |_|\__,_|\_____|_| |_|\__,_|\__| 
#####################################                                                                                       
"""
    parser = argparse.ArgumentParser(prog="Chatter client",
                                     formatter_class=argparse.RawDescriptionHelpFormatter,
                                     description="Communicate with friends in the YaChat Room",
                                     epilog="The Chatter Server manages member connections. This is a client which conforms to its usage protocol.\n" +
                                        "|------------------|\n"+
                                        "|   RETURN CODES   |\n"+
                                        "|------------------|\n"+
                                        "| 0:Exited normally.\n"+
                                        "| 1:Failed TCP connection with Server.\n"+
                                        "| 2:Server not started?\n"+
                                        "| 3:Client closed connection before joining ChatterRoom.\n"
                                    )

    parser.add_argument(
        "screen_name",
        type=str,
        help="Screen name (string) NO WHITESPACE",
    )
    parser.add_argument(
        "memd_server_hostname",
        type=str,
        help="MemD server hostname (string)",
    )
    parser.add_argument(
        "memd_welcome_tcp_port",
        type=int,  # argparse will ensure this is converted to integer
        help="MemD welcome TCP port (integer)",
    )
    parser.add_argument(
        "--level",
        choices=["DEBUG", "INFO", "WARNING", "ERROR", "CRITICAL"],
        help="Set logging level (default: INFO)",
        default="INFO"
    )

    args = parser.parse_args()
    logging.basicConfig(
        level=getattr(logging, args.level),  # Convert string to logging level
        format=f"{YELLOW}%(asctime)s{RESET} - {RED}%(levelname)s{RESET} - {MAGENTA}%(message)s{RESET}"
    )

    logger = logging.getLogger("ClientLogger")
    # Validate args
    if contains_whitespace(args.screen_name):
        raise ScreenNameException("screen_name contains whitespace. It must not have spaces in it.")
    print(LOGO)
    main(screen_name=args.screen_name, memd_host=args.memd_server_hostname, memd_tcp_port=args.memd_welcome_tcp_port)