# Medical Blockchain Proof of Concept

This project is a used as a proof of concept for my final year dissertation written in python.

### Installation

This project requires [Python](https://www.python.org/download/releases/3.0/) v3.0+ to run.

Install the dependencies.

```sh
$ cd Medical-Blockchain-PoC
$ chmod +x requirements.sh
$ sudo ./requirements.sh
```

To start a genesis node
```sh
$ python3 node_multilayer_singlemaster.py master #port1# #port2#
```
Example:
```sh
$ python3 node_multilayer_singlemaster.py master 30000 40000
```

To start a node:

Edit the node.py script and change the address variable to the genesis nodes IP on line 38 and the port to one of the ports you specified when starting the genesis node on line 39 before starting the node.

Example:
```sh
host = "192.168.1.20"
port = 3000
```
Start Node:
```sh
$ python3 node.py
```

### Commands

The commands below are used to manage the node and to monitor the node.

| Command | Description |
| ------ | ------ |
| get network | lists the whole blockchain network on boths ports |
| get peers | lists all nodes connected |
| get chain | lists each block in the blockchain |
| create txs-auto | creates text based block |
| send document | sends all files in the upload folder (This isn't included but can be created) |
| clear | clears the terminal |

### Paper
You can read my paper on this project using the link below when it becomes available!
[Currently Unavailable](#)
### Warranty and Support

This project doesn't include any warranty or support but if you have any suggestions or ideas, give me a shout at [@TwidsDev](https://twitter.com/twidsdev).

The installation or writeup isn't 100% clear to understand, let me know and I'll try and make it clear and easy to understand for everyone.

License
----

GNU GPLv3
