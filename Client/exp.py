import socket
import argparse
import sys
import string
import logging
import threading
import select
import curses
from dataclasses import dataclass

# Global threading event
event = threading.Event()

@dataclass
class Member:
    """Encapsulated Identity Data for each member of the ChatterChatRoom"""
    screen_name: str
    ip: str
    port: int

members_list: list[Member] = []

# Exceptions
class ScreenNameException(Exception):
    """For identifying bad screen_names"""

# Helper methods
def contains_whitespace(s):
    """Quick check of spaces in screen names"""
    return any(c in string.whitespace for c in s)

def tcp_server_connect(server_ip: str, server_port: int, screen_name: str) \
        -> tuple[str, socket.socket, socket.socket]:
    """Establishes initial TCP connection to MemD server"""
    client_ip = socket.gethostbyname(socket.gethostname())
    server_sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    try:
        server_sock.connect((server_ip, server_port))
        logger.debug("Connection successful...")
    except socket.error as e:
        logger.error("Failed to connect: %s", e)
        sys.exit(1)

    # Create UDP socket
    udp_sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    udp_sock.bind(("0.0.0.0", 0))
    _, udp_port = udp_sock.getsockname()
    logger.debug("UDP: %s", udp_port)

    # Send HELO message
    msg = f"HELO {screen_name} {client_ip} {udp_port}\n"
    sent = server_sock.send(msg.encode())
    if sent <= 0:
        logger.error("TCP Socket busted")

    data = server_sock.recv(4096).decode()
    logger.debug("Recv: %s", data)
    return data, udp_sock, server_sock

def populate_member_list(datagram: tuple[str, str, int]):
    """Adds a member to the members_list"""
    members_list.append(Member(screen_name=datagram[0], ip=datagram[1], port=datagram[2]))
    logger.debug("member_list -> %s\n", members_list)

def receive_protocols(screen_name: str, udp_sock: socket.socket, chat_win):
    """Thread for reading UDP socket and displaying messages"""
    while True:
        ready, _, _ = select.select([udp_sock], [], [], 1.0)
        if ready:
            data, _ = udp_sock.recvfrom(4096)
            data = data.decode()
            if not data:
                continue

            protocol: str = data[:4]
            if protocol == "ACPT":
                in_room = data[5:].split(":")
                for person in in_room:
                    new_screen_name, ip, port = person.split()
                    populate_member_list((new_screen_name, ip, int(port)))
                    chat_win.addstr(f"{new_screen_name} joined the room!\n")
                    chat_win.refresh()

            elif protocol == "JOIN":
                # person: ['<screen_name>', '<IP>', '<Port>']
                new_screen_name, ip, port = data[5:].split() # Format for processing
                populate_member_list((new_screen_name, ip, int(port)))
                chat_win.addstr(f"{new_screen_name} has joined the chat. \n")

            elif protocol == "MESG":
                msg = data[5:].split(":")
                chat_win.addstr(f"{msg[0]}: {msg[1]}\n")
                chat_win.refresh()

            elif protocol == "EXIT":
                leaving_screen_name = data[5:].strip()
                members_list[:] = [m for m in members_list if m.screen_name != leaving_screen_name]
                chat_win.addstr(f"{leaving_screen_name} has left the chat.\n")
                chat_win.refresh()
                if leaving_screen_name == screen_name:
                    break
    event.set()

def chat_interface(stdscr, screen_name, udp_sock, udp_port, server_sock):
    """Curses-based Chat UI"""
    curses.curs_set(1)
    stdscr.clear()
    height, width = stdscr.getmaxyx()

    # Create separate windows for chat messages and input
    chat_height = height - 3
    input_height = 3
    chat_win = curses.newwin(chat_height, width, 0, 0)
    input_win = curses.newwin(input_height, width, chat_height, 0)

    # chat_win.scrollok(True)
    chat_win.box()

    input_win.addstr(1, 1, "Type your message: ", curses.A_BOLD)
    input_win.refresh()

    # Start receiving messages in a separate thread
    recv_thread = threading.Thread(target=receive_protocols, args=(screen_name, udp_sock, chat_win), daemon=True)
    recv_thread.start()

    while True:
        input_win.clear()
        input_win.addstr(1, 1, "Type your message: ", curses.A_BOLD)
        input_win.refresh()

        # Get user input
        user_message = input_win.getstr(1, 20, 60).decode('utf-8').strip()

        if not user_message:
            continue
        elif user_message.upper() == "EXIT":
            server_sock.send("EXIT\n".encode())
            break
        else:
            for member in members_list:
                msg_to_send = f"MESG {screen_name}: {user_message}\n"
                udp_sock.sendto(msg_to_send.encode(), (member.ip, member.port))
            chat_win.addstr(f"You: {user_message}\n")
            chat_win.refresh()

    event.wait()

def main(**kwargs):
    screen_name = kwargs["screen_name"]
    memd_server = "127.0.0.1" if kwargs["memd_host"] == "localhost" else kwargs["memd_host"]
    memd_connect_port = kwargs["memd_tcp_port"]

    data, udp_sock, server_sock = tcp_server_connect(memd_server, memd_connect_port, screen_name)

    while data.startswith("RJCT"):
        logger.error("Screen name already in use!")
        screen_name = input("Try another screen name (type 'exit' to quit) >> ")
        if screen_name.lower() == "exit":
            sys.exit(3)
        data, udp_sock, server_sock = tcp_server_connect(memd_server, memd_connect_port, screen_name)

    if data.startswith("ACPT"):
        curses.wrapper(chat_interface, screen_name, udp_sock, udp_sock.getsockname(), server_sock)

    logger.info("Client is shutting down...")
    udp_sock.close()

if __name__ == "__main__":
    parser = argparse.ArgumentParser(prog="Chatter client",
                                     formatter_class=argparse.RawDescriptionHelpFormatter,
                                     description="Communicate with friends in the YaChat Room",
                                     epilog="| RETURN CODES |\n"
                                            "| 0: Exited normally.\n"
                                            "| 1: Failed TCP connection.\n"
                                            "| 2: Server not started?\n"
                                            "| 3: Client quit before joining.\n"
                                            "| 4: Unknown error."
                                    )

    parser.add_argument("screen_name", type=str, help="Screen name (no whitespace)")
    parser.add_argument("memd_server_hostname", type=str, help="MemD server hostname")
    parser.add_argument("memd_welcome_tcp_port", type=int, help="MemD welcome TCP port")
    parser.add_argument("--level", choices=["DEBUG", "INFO", "WARNING", "ERROR", "CRITICAL"],
                        default="INFO", help="Set logging level (default: INFO)")

    args = parser.parse_args()
    logging.basicConfig(level=getattr(logging, args.level),
                        format="%(asctime)s - %(levelname)s - %(message)s")
    logger = logging.getLogger("ClientLogger")

    if contains_whitespace(args.screen_name):
        raise ScreenNameException("Screen name must not contain whitespace.")

    main(screen_name=args.screen_name, memd_host=args.memd_server_hostname, memd_tcp_port=args.memd_welcome_tcp_port)
