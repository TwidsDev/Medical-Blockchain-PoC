# -*- coding: utf-8 -*-

from blockchain import Blockchain
# from wallet import Wallet
# from transaction import Transaction
from uuid import uuid4
import py2p
import socket
import threading
import time
import sys
import json

import os
# PARAMETERS 

# Import Cryptography library
import Crypto
from Crypto.PublicKey import RSA
from Crypto import Random
from Crypto.Hash import SHA512
from Crypto.Signature import PKCS1_v1_5
from Crypto.Cipher import PKCS1_OAEP
import base64

# Import pickle
import pickle
from GetKeysServer import RSAmain

# Generate a globally unique address for this Node
node_identifier = str(uuid4()).replace('-', '')

# Instantiate the Blockchain
blockchain = Blockchain()

# Instantiate P2P variables
peersList = []
sock1 = None
sock2 = None
sock = None
addr = None
addr1 = None
addr2 = None

# THREADS

class UpdatePeersListThread(object):
    def __init__(self, mode):
        self.mode = mode
        thread = threading.Thread(target=self.run, args=())
        thread.daemon = True
        thread.start()

    def run(self):
        start = True
        GenerateKeys()
        loadChain("load")
        # run forever
        while True:
            time.sleep(1)

            # reinitializing the peersList
            peersList = []

            if mode == 'master':
                # populating the peersList
                for socket in sock1.routing_table.values():
                    peerAddr = socket.addr[0] + ":" + str(socket.addr[1])
                    if not peerAddr in peersList:
                        peersList.append(peerAddr)

                for socket in sock2.routing_table.values():
                    peerAddr = socket.addr[0] + ":" + str(socket.addr[1])
                    if not peerAddr in peersList:
                        peersList.append(peerAddr)

                #  assigning peersList array to node's peers
                blockchain.peers = peersList

            if self.mode == 'slave':
                # populating the peersList
                for socket in sock.routing_table.values():
                    peerAddr = socket.addr[0] + ":" + str(socket.addr[1])
                    if not peerAddr in peersList:
                        peersList.append(peerAddr)

                #  assigning peersList array to node's peers
                blockchain.peers = peersList

            if start and self.mode == 'slave':
                # in the start, getting the chains from the network and adopting the longest chain
                sock.send('hello consensus', addr)
                start = False

class MiningThread(object):
    def __init__(self, mode):
        self.mode = mode
        thread = threading.Thread(target=self.run, args=())
        thread.daemon = True
        thread.start()


    def run(self):
        
        # run forever
        while True:
            time.sleep(15)
            # Running the proof of work algorithm to get the next proof
            last_block = blockchain.last_block
            proof = blockchain.proof_of_work(last_block)

            # Forge the new Block by adding it to the Chain
            previous_hash = blockchain.hash(last_block)
            block = blockchain.new_block(proof= proof, previous_hash=previous_hash)

            # calling consensus
            if self.mode == 'master':
                # ? !!! CONSENSUS AMONG NETWORKS !!! ?
                sock1.send('hello consensus', addr1)
                sock2.send('hello consensus', addr2)
            else:
                sock.send('hello consensus', addr)
# FUNCTIONS
def loadChain(state):
    if state == "load":
        try:
            f=open("blockchain.txt",'rb')
            blockchain.chain=pickle.load(f)
            f.close()
        except:
            pass
        
    elif state == "save":
        f=open("blockchain.txt",'wb')
        pickle.dump(blockchain.chain, f)
        f.close()
    else:
        print("Please enter valid state")

def GenerateKeys():
        try:
            f=open("PrivateKeyServer.txt","r")
            importPK=f.read()
            f.close()
            privateKey=RSA.importKey(importPK)
            return privateKey
        except:
            RSAmain()

        try:
            f=open("PublicKeyServer.txt","rb")
            importPBK=f.read()
            f.close()
        except:
            RSAmain()

def encrypt_private_key(a_message, private_key):
    encryptor = PKCS1_OAEP.new(private_key)
    encrypted_msg = encryptor.encrypt(a_message)
    #print(encrypted_msg)
    encoded_encrypted_msg = base64.b64encode(encrypted_msg)
    #print(encoded_encrypted_msg)
    return encoded_encrypted_msg

def decrypt_public_key(encoded_encrypted_msg, public_key):
    encryptor = PKCS1_OAEP.new(public_key)
    decoded_encrypted_msg = base64.b64decode(encoded_encrypted_msg)
    #print(decoded_encrypted_msg)
    decoded_decrypted_msg = encryptor.decrypt(decoded_encrypted_msg)
    #print(decoded_decrypted_msg)
    return decoded_decrypted_msg
# Message handler method for P2P messaging
def msgHandler(msg, handler):
    '''
    msg.packets[0] = type
    msg.packets[1] = flag
    msg.packets[2] = msg
    msg.packets[3] = hash code of the sender
    '''
    packets = msg.packets

    # # -----------------------------------------------------------------------------------------
    # # CONSENSUS: Regular check (in hello messages)
    # # if the number if the recived chains are equal to the number of the peers in the network
    # # call the resolve algorithm because it means that all the chains were received by the node
    # if len(blockchain.peer_chains) == len(blockchain.peers):
    #     if blockchain.resolve_conflicts():
    #         print("chain replaced with the longer received chain")
    #         for i in range(0, len(blockchain.chain)):
    #             print(blockchain.chain[i]['index'], blockchain.chain[i]['previous_hash'])
    #     # clearing the chains array
    #     blockchain.peer_chains = []
    # # -----------------------------------------------------------------------------------------

    if packets[1] == "hello consensus":
        senderAddr = packets[2]
        print(senderAddr + " has just been connected.")
        
        f=open("PublicKeyServer.txt","rb")
        importPBK=f.read()
        print(importPBK)
        print(blockchain.peers)
        for peer in blockchain.peers:
            senderAddr = peer
            sock1.send("PK", [senderAddr, importPBK])
                
    
    elif packets[1] == "PK":
        address = packets[2][0] #Get IP and port from packet
        address = address.split(":", 1)[0] #Remove port number leaving just the IP
        sent_publickey = packets[2][1] #Get PublicKey
        print("\nPublic Key Received from " + address + "\n")
        print(str(sent_publickey) + "\n")
        f=open(address + ".txt", "w")
        f.write(sent_publickey.decode("UTF-8"))
        f.close
        print("PublicKey has been written to " +address+".txt")
    # MINE
    elif packets[1] == "mine":
        # Receiving a reward for finding the proof
        # The sender is "0" to signify that this Node has mined a new coin

        # Running the proof of work algorithm to get the next proof
        last_block = blockchain.last_block
        proof = blockchain.proof_of_work(last_block)

        # Forging the new Block by adding it to the Chain
        previous_hash = blockchain.hash(last_block)
        block = blockchain.new_block(proof=proof, previous_hash=previous_hash)

        # calling consensus
        sock.send('consensus', blockchain.chain)
        sock1.send('consensus', blockchain.chain)
        sock2.send('consensus', blockchain.chain)

    # must be called in the node initialization and after the mining 
    elif packets[1] == "consensus":
        blockchain.peer_chains.append(packets[2])
        sock.send('chain', blockchain.chain)

    # if the chain request has received
    elif packets[1] == "chain":
        # received peer chains are added to the chain array to be used for the consensus
        blockchain.peer_chains.append(packets[2])

    elif packets[1] == "txs":
        blockchain.add_new_unvalidated_transaction(packets[2])
        print("TX Added: ", packets[2])

    elif packets[1] == "peers":
        print(packets[2])

    elif packets[1] == "ping":
        print(packets[2] + " has sent a ping!")

    elif packets[1] == "fetch chain":
        sock1.send('fetch chain', blockchain.chain)
        sock2.send('fetch chain', blockchain.chain)

    # If we receive a disconnect message we delete this peer from the list
    elif packets[1] == "disconnected":
        # remove the peer from the list after the disconnect msg has received
        print(packets[2] + " disconnected.")

    else:
        print("Invalid Command\n")
        pass

# MAIN
if __name__ == '__main__':
    keepAlive = True
    # mode is either 'master' or 'slave'
    mode = sys.argv[1]

    # if mode is master, in this implementation there are 2 sockets on é diff. ports
    if len(sys.argv) < 4:
        port = sys.argv[2]
    else:
        port1 = sys.argv[2]
        port2 = sys.argv[3]

    # if the peer is the master
    if mode == 'master':
        # for p2p messaging launch a node on machine with port1 and port 2 using 2 diff. sockets
        sock1 = py2p.MeshSocket('0.0.0.0', int(port1), prot=py2p.Protocol('node', 'Plaintext'))
        sock2 = py2p.MeshSocket('0.0.0.0', int(port2), prot=py2p.Protocol('master', 'Plaintext'))
        # to listen all the coming messages from both sockets
        sock1.register_handler(msgHandler)
        sock2.register_handler(msgHandler)
        # getting the address of the connected peer
        addr1 = sock1.out_addr[0] + ':' + str(sock1.out_addr[1])
        addr2 = sock2.out_addr[0] + ':' + str(sock2.out_addr[1])

        print("Master is online on ports " + port1 + " and " + port2)

    # if the peer is slave
    elif mode == 'slave':
        # connects itself to the master on one of the ports of the master,
        # so that, we can isolate networks from eachother by keeping one single chain on master
        sock = py2p.MeshSocket('0.0.0.0', int(port), prot=py2p.Protocol('node', 'SSL'))
        sock.register_handler(msgHandler)
        addr = sock.out_addr[0] + ':' + str(sock.out_addr[1])
        # connects itself to the master
        try:
            res = sock.connect('**ip_address**', 20000)
            print("Successfully connected to the master.")
        except:
            print("Master not found.")
            sock.close()
            keepAlive = False
    else:
        print("You are not providing the correct mode.")

    ht = UpdatePeersListThread(mode)
    # mt = MiningThread(mode)

    if mode == 'master':
        sock = sock1

    try:
        # run main forever
        while keepAlive:
            command = input("command: ")

            # CHAIN
            if command == "get chain":
                print(blockchain.chain)

            elif command == "PK":
                try:
                    f=open("PublicKeyServer.txt","rb")
                    importPBK=f.read()
                    print(importPBK)
                    print(blockchain.peers)
                    for peer in blockchain.peers:
                        senderAddr = peer
                        sock1.send("PK", [senderAddr, importPBK])
                except:
                    RSAmain()
                    f=open("PublicKeyServer.txt","rb")
                    importPBK=f.read()
                    print(blockchain.peers)
                    for peer in blockchain.peers:
                        senderAddr = peer
                        sock1.send("PK", [senderAddr, importPBK])


            elif command == "diffuse chain":
                if mode == 'master':
                    # !!! CONSENSUS AMONG NETWORKS !!! 
                    sock1.send('chain', blockchain.chain)
                    sock2.send('chain', blockchain.chain)
                else:
                    sock.send('chain', blockchain.chain)

            # TXS
            elif command == "get txs":
                print(blockchain.unvalidated_transactions)

            elif command == "diffuse txs":
                if mode == 'master':
                    # !!! CONSENSUS AMONG NETWORKS !!!
                    sock1.send('txs', blockchain.unvalidated_transactions)
                    sock2.send('txs', blockchain.unvalidated_transactions)
                else:
                    sock.send('txs', blockchain.unvalidated_transactions)

            # PEERS
            elif command == "get peers":
                print(blockchain.peers)

            # NETWORK
            elif command == "get network":
                blockchain.network = blockchain.peers.copy()
                if mode == 'master':
                    blockchain.network.append(addr1)
                    blockchain.network.append(addr2)
                else: 
                    blockchain.network.append(addr)

                print(blockchain.network)
            #New Transaction
            elif command == "create txs":
                tx = {
                    "PatientID": input("Please Enter PatientID: "),
                        "Patient Name": input("Please Enter Patient Name: "),
                        "Patient DOB": input("Please Enter Patient DOB: "),
                        "Author": input("Please Enter Author: "),
                        "File Name": input("Please Enter File Name: "),
                        "File Path": input("Please Enter File Path: ")
                    } 
                blockchain.add_new_unvalidated_transaction(tx)

            elif command == "send document":
                for filename in os.listdir('upload'):
                    filewdir = "upload/" + filename
                    statinfo = os.stat(filewdir)
                    if statinfo.st_size <=300000: #filesize check
                        f=open(filewdir, "rb")
                        fileplain=f.read()
                        f.close()
                        encoded = base64.b85encode(fileplain)
                        print(filename)
                        time.sleep(1)
                        sock1.send('file', [filename, encoded])
                        print("sent", filename)
                    else:
                        print(filename + " exceeds the file limit and will be skipped")

                    


            
            #Process Chained together
            elif command == "create txs-auto":
                sock1.send('fetch chain', blockchain.chain)
                tx = {
                    "PatientID": input("Please Enter PatientID: "),
                        "Patient Name": input("Please Enter Patient Name: "),
                        "Patient DOB": input("Please Enter Patient DOB: "),
                        "Author": input("Please Enter Author: "),
                        "File Name": input("Please Enter File Name: "),
                        "File Path": input("Please Enter File Path: ")
                    } 
                blockchain.add_new_unvalidated_transaction(tx)
                #diffuse
                if mode == 'master':
                    # !!! CONSENSUS AMONG NETWORKS !!!
                    #for peer in blockchain.peers:
                        #address = peer.split(":", 1)[0] #Remove port number leaving just the IP
                        #f=open(address + ".txt", "r")
                        #cipher=PKCS1_OAEP.new(f.read())
                        #transactions=blockchain.unvalidated_transactions
                        #encoded = cipher.encrypt(transactions)
                        #print(encoded)
                        #sock1.send('txs', encoded)
                    sock1.send('txs', blockchain.unvalidated_transactions)
                    #sock2.send('txs', blockchain.unvalidated_transactions)
                else:
                    sock.send('txs', blockchain.unvalidated_transactions)
                #Mine for sock 1
                sock1.send('mine')
                #Mine for sock 2
                sock2.send('mine')
                #Mine for master
                last_block = blockchain.last_block
                proof = blockchain.proof_of_work(last_block)
                # Forging the new Block by adding it to the Chain
                previous_hash = blockchain.hash(last_block)
                block = blockchain.new_block(proof=proof, previous_hash=previous_hash)
                # calling consensus
                sock.send('consensus', blockchain.chain)
                loadChain("save")

            # MINE
            elif command == "mine":
                # Running the proof of work algorithm to get the next proof
                last_block = blockchain.last_block
                proof = blockchain.proof_of_work(last_block)

                # Forging the new Block by adding it to the Chain
                previous_hash = blockchain.hash(last_block)
                block = blockchain.new_block(proof= proof, previous_hash=previous_hash)

                # calling consensus
                # ? !!! CONSENSUS AMONG NETWORKS !!! ?
                if mode == 'master':
                    sock1.send('consensus', blockchain.chain)
                    sock2.send('consensus', blockchain.chain)
                else:
                    sock.send('consensus', blockchain.chain)

            # HEY
            elif command == "ping":
                if mode == 'master':
                    sock1.send('ping', addr1)
                    sock2.send('ping', addr2)
                else:
                    sock.send('ping', addr)

            #force consensus
            elif command == "force consensus":
                sock1.send('hello consensus', addr1)
                sock2.send('hello consensus', addr2)
            
            elif command == "fetch chain":
                sock1.send('fetch chain', blockchain.chain)
                sock2.send('fetch chain', blockchain.chain)

            #?automate start for test
            elif command == "auto start":
                testLoop = True
                counter = 0
                while testLoop == True:
                    import random
                    names = ["Ossie Mccusker"]
                    fileName = ["xray.png", "document.doc","results.docx","notes.pdf"]
                    filePaths = ["W:/patientdata","/Users/Doctor/Documents"]
                    d = str(random.randint(1,31))
                    m = str(random.randint(1,12))
                    y = str(random.randint(1930,2020))
                    if random.randint(0,100) < 36:
                        tx = {
                            "PatientID": random.randint(0,99999),
                            "Patient Name": random.choice(names),
                            "Patient DOB": "%s/%s/%s"%(d,m,y),
                            "Author": (random.choice(names)),
                            "File Name": random.choice(fileName),
                            "File Path": (random.choice(filePaths))
                            } 
                        blockchain.add_new_unvalidated_transaction(tx)
                        #diffuse
                        sock.send('txs', blockchain.unvalidated_transactions)
                        #Mine for sock
                        sock.send('mine')
                        #Mine for master
                        last_block = blockchain.last_block
                        proof = blockchain.proof_of_work(last_block)
                        # Forging the new Block by adding it to the Chain
                        previous_hash = blockchain.hash(last_block)
                        block = blockchain.new_block(proof=proof, previous_hash=previous_hash)
                        #?calling consensus
                        sock.send('consensus', blockchain.chain)
                        loadChain("save")
                        with open("results.txt", "a") as f:
                            import datetime
                            f.write(str(datetime.datetime.now())+ ": " + str(counter)+"\n")
                            f.close
                            counter +=1
                        print(str(datetime.datetime.now())+ ": " + str(counter))
                        time.sleep(20)

            #?automate stop for test
            elif command == "auto stop":
                testLoop = False

            #?automate stop for test
            elif command == "auto stop":
                testLoop = False

            # Clear
            elif command == "clear":
                import os
                os.system('cls' if os.name == 'nt' else 'clear')
                pass

            # DISCONNECT
            elif command == "exit":
                keepAlive = False
                if mode == 'master':
                    sock1.send('disconnected', addr1)
                    sock1.close()
                    sock2.send('disconnected', addr2)
                    sock2.close()
                else:
                    sock.send('disconnected', addr)
                    sock.close()
                continue

            else:
                print("Invalid Command\n")
                pass
    except KeyboardInterrupt:
        keepAlive = False
        if mode == 'master':
            sock1.send('disconnected', addr1)
            sock1.close()
            sock2.send('disconnected', addr2)
            sock2.close()
        else:
            sock.send('disconnected', addr)
            sock.close()
