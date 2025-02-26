import socket
import argparse
import sys
import textwrap
import logging
from _thread import *
import threading
from dataclasses import dataclass

# Return Codes
RETURN_CODES = {
    0: "Exited normally.",
    1: "Failed TCP connection with Server.",
    2: "Server not started?",
}
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

def servant_thread(connection_socket):
    pass

def start_server(accept_port:int = 7676):
    welcome_sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    try:
        welcome_sock.bind(("",accept_port))
    except socket.error as message:
        print(f"Bind failed. Error Code: {str(message[0])} Message {message[1]}")
        sys.exit()
    logger.debug("Binded to Welcome Port")
    # Listen for incoming connections
    while True:
        welcome_sock.listen(9)
        logger.debug("Welcome socket listening...")
        c, addr = welcome_sock.accept()
        start_new_thread(servant_thread, (c,))

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