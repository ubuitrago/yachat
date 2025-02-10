# yachat
YaChat - A Simple Chat App written in Python

## Running Client
* Start the ChatSystem.jar provided 
>`java -cp ChatSystem.jar server.YMemD 7676`
* Run the Client with the LAN IP (192.168.<>.<>) of the machine the server runs on
>`python3 YaChat.py uriel 192.168.1.214 7676`
* For the help menu
> `python3 YaChat.py -h`
__NOTE__: For DEBUG level logging, use the flag "--level DEBUG"

## Usage
Once the client connects with the server and is successfully admitted, the cursor will appear at the bottom of the terminal. Type in your message and press return. To leave the Chat Room, type and return "EXIT". 

<img src=./Usage-Demo.png></img>