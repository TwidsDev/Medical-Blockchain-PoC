# -*- coding: utf-8 -*-

from blockchain import Blockchain
# from wallet import Wallet
# from transaction import Transaction
from uuid import uuid4
import py2p
import threading
import time
import sys

#PARAMETERS 
import os
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

#?Instantiate the Blockchain
blockchain = Blockchain()

#?Instantiate P2P variables
peersList = []
sock = None
addr = None
host = "10.131.54.167"
port = 3000
#?THREADS

class UpdatePeersListThread(object):
    def __init__(self):
        thread = threading.Thread(target=self.run, args=())
        thread.daemon = True
        thread.start()

    def run(self):
        start = True
        loadChain("load")
        GenerateKeys()

        #?run forever
        while  True:
            time.sleep(1)
            # reinitializing the peersList
            peersList = []
            #?populating the peersList
            for socket in sock.routing_table.values():
                peerAddr = socket.addr[0] + ":" + str(socket.addr[1])
                if not peerAddr in peersList:    
                    peersList.append(peerAddr)
            #?assigning peersList array to node's peers
            blockchain.peers = peersList

            #?in the start, getting the chains from the network and adopting the longest chain
            if start and addr != host + str(port):
                sock.send('hello consensus', addr)
                start = False
            #Checks if theres any changes to the block, if so save to file
            chainComp = ""
            if (len(blockchain.chain)) >= chainComp:
                chainComp = (len(blockchain.chain))
                loadChain("save")

class MiningThread(object):
    def __init__(self):
        thread = threading.Thread(target=self.run, args=())
        thread.daemon = True
        thread.start()

    def run(self):
        #?run forever
       # loadChain("load")
        while  True:
            time.sleep(10)

            #?Receiving a reward for finding the proof
            # The sender is "0" to signify that this Node has mined a new coin

            # Running the proof of work algorithm to get the next proof
            last_block = blockchain.last_block
            proof = blockchain.proof_of_work(last_block)

            # Forge the new Block by adding it to the Chain
            previous_hash = blockchain.hash(last_block)
            block = blockchain.new_block(proof= proof, previous_hash=previous_hash)

            #?calling consensus
            sock.send('consensus', blockchain.chain)
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

class ConsensusThread(object):
    def __init__(self):
        thread = threading.Thread(target=self.run, args=())
        thread.daemon = True
        thread.start()

    def run(self):
        #?run forever
        while True:
            time.sleep(5)

            # ?printing the wholeChain
            for block in blockchain.wholeChain:
                print(block['index'], block['previous_hash'])

            # #?CONSENSUS: Regular check (in hello messages)
            # # if the number if the recived chains are equal to the number of the peers in the network
            # #?call the resolve algorithm because it means that all the chains were received by the node
            if len(blockchain.peer_chains) == len(blockchain.peers):
                if blockchain.resolve_conflicts():
                    print("chain replaced with the longer received chain")
                #?clearing the chains array
                blockchain.peer_chains = []
                #storing the chain (adding it to wholeChain)
                blockchain.storeChain()
                #?telling other nodes to store their chains too
                #?sock.send("store chain")

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


#?FUNCTIONS

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
            #sock.sendall(importPBK)
            f.close()
        except:
            RSAmain()
# Message handler method for P2P messaging
def msgHandler(msg, handler):
    '''
    msg.packets[0] = type
    msg.packets[1] = flag
    msg.packets[2] = msg
    msg.packets[3] = hash code of the sender
    '''
    packets = msg.packets

    if packets[1] == "hello consensus":
        senderAddr = packets[2]
        print(senderAddr + " has just been connected.")
        #sock.send("whole chain", [senderAddr, blockchain.wholeChain, blockchain.chain])

    elif packets[1] == "PK":
        address = packets[2][0] #Get IP and port from packet
        address = address.split(":", 1)[0] #Remove port number leaving just the IP
        sent_publickey = packets[2][1] #Get PublicKey
        print("\nPublic Key Received from " + address + "\n")
        print(str(sent_publickey) + "\n")
        f=open(address + ".txt", "w")
        f.write(sent_publickey.decode("UTF-8"))
        f.close
        print("PublicKey has been written to " +address+".txt\n")
        print("Sending Public key to ")
        try:
            f=open("PublicKeyServer.txt","rb")
            importPBK=f.read()
            print(importPBK)
            print(blockchain.peers)
            for peer in blockchain.peers:
                senderAddr = peer
                sock.send("PK", [senderAddr, importPBK])
        except:
            RSAmain()
            f=open("PublicKeyServer.txt","rb")
            importPBK=f.read()
            print(blockchain.peers)
            for peer in blockchain.peers:
                senderAddr = peer
                sock.send("PK", [senderAddr, importPBK])


    # must be called in the node initialization and after the mining 
    elif packets[1] == "consensus":
        blockchain.peer_chains.append(packets[2])
        sock.send('chain', blockchain.chain)

    elif packets[1] == "whole chain":
        senderAddr = packets[2][0]
        if senderAddr == addr:
            blockchain.wholeChain = packets[2][1]
            blockchain.chain = packets[2][2]

    elif packets[1] == "store chain":
        blockchain.storeChain()

    # if the chain request has received
    elif packets[1] == "chain":
        # received peer chains are added to the chain array to be used for the consensus
        blockchain.peer_chains.append(packets[2])

    elif packets[1] == "txs":
        #f=open("PrivateKeyServer.txt","r")
        #private= f.read()
        #cipher = PKCS1_OAEP.new(private)
        #encoded = packets[2]
        #blockchain.add_new_unvalidated_transaction(cipher.decrypt(encoded))
        #print("TX Added: ", packets[2])
        blockchain.add_new_unvalidated_transaction(packets[2])
        print("TX Added: ", packets[2])

    elif packets[1] == "peers":
        print(packets[2])
    elif packets[1] == "fetch chain":
        blockchain.chain = packets[2]
        print("replaced chain from master")

    elif packets[1] == "file":
        print("received file")
        encoded = packets[2][1]
        #print(encoded)
        filename = str(packets[2][0])
        print(filename)
        plainfile = base64.b85decode(encoded)
        print(plainfile)
        f=open(str(filename), "wb")
        f.write(plainfile)
        f.close


    elif packets[1] == "mine":
                #?Receiving a reward for finding the proof
                # The sender is "0" to signify that this Node has mined a new coin
                # Running the proof of work algorithm to get the next proof
                last_block = blockchain.last_block
                proof = blockchain.proof_of_work(last_block)
                # Forging the new Block by adding it to the Chain
                previous_hash = blockchain.hash(last_block)
                block = blockchain.new_block(proof=proof, previous_hash=previous_hash)
                #?calling consensus
                sock.send('consensus', blockchain.chain)

    elif packets[1] == "ping":
        print(packets[2] + " has sent a ping!")
        pass

    #?If we receive a disconnect message we delete this peer from the list
    elif packets[1] == "disconnected":
        #?remove the peer from the list after the disconnect msg has received
        print(packets[2] + " disconnected.")

    else:
        pass

#?MAIN
if __name__ == '__main__':
    keepAlive = True
    # create socket for node
    sock = py2p.MeshSocket('0.0.0.0', port, prot=py2p.Protocol('node', 'Plaintext'))
    # to listen all the coming messages
    sock.register_handler(msgHandler)

    #?getting the address of the connected peer
    addr = sock.out_addr[0]+ ':' + str(sock.out_addr[1])

    # if the peer is not the master
    if addr != host + str(port):
        # connects itself to the master
        try:
            res = sock.connect(host, port)
            print("Successfully connected to the master.")
            sock.send('fetch chain', blockchain.chain)
            print("Found Master Chain")
        except:
            print("Master not found.")
            sock.close()
            keepAlive = False

    ut = UpdatePeersListThread()
    #?mt = MiningThread()
    #?ct = ConsensusThread()

    try:
        # run main forever
        while keepAlive:
            command = input("command: ")

            #?HEY
            if command == "ping":
                sock.send('ping', addr)
            
            elif command == "PK":
                try:
                    f=open("PublicKeyServer.txt","rb")
                    importPBK=f.read()
                    print(importPBK)
                    print(blockchain.peers)
                    for peer in blockchain.peers:
                        senderAddr = peer
                        sock.send("PK", [senderAddr, importPBK])
                except:
                    RSAmain()
                    f=open("PublicKeyServer.txt","rb")
                    importPBK=f.read()
                    print(blockchain.peers)
                    for peer in blockchain.peers:
                        senderAddr = peer
                        sock.send("PK", [senderAddr, importPBK])

            #?CHAIN
            elif command == "get chain":
                print(blockchain.chain)

            elif command == "diffuse chain":
                sock.send('chain', blockchain.chain)
            #New Transaction
            elif command == "create txs":
                tx = {
                    "Name": input("Please Enter Name: "),
                        "DOB": input("Please Enter DOB: ")
                    } 
                blockchain.add_new_unvalidated_transaction(tx)
            #?TXS
            elif command == "get txs":
                print(blockchain.unvalidated_transactions)

            elif command == "diffuse txs":
                sock.send('txs', blockchain.unvalidated_transactions)

            # PEERS
            elif command == "get peers":
                print(blockchain.peers)

            elif command == "diffuse peers":
                sock.send('peers', blockchain.peers)

            #?NETWORK
            elif command == "get network":
                blockchain.network = blockchain.peers.copy()
                blockchain.network.append(addr)
                print(blockchain.network)

            #Process Chained together
            elif command == "create txs-auto":
                #sock.send('fetch chain', blockchain.chain) No need for this anymore!
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

            #?MINE
            elif command == "mine":
                #?Receiving a reward for finding the proof
                # The sender is "0" to signify that this Node has mined a new coin

                # Running the proof of work algorithm to get the next proof
                last_block = blockchain.last_block
                proof = blockchain.proof_of_work(last_block)

                # Forging the new Block by adding it to the Chain
                previous_hash = blockchain.hash(last_block)
                block = blockchain.new_block(proof=proof, previous_hash=previous_hash)

                #?calling consensus
                sock.send('consensus', blockchain.chain)

            #?CONSENSUS
            elif command == "consensus":
                sock.send('consensus', blockchain.chain)
                print("Sent request for consensus")
            
            #?automate start for test
            elif command == "auto start":
                testLoop = True
                counter = 0
                while testLoop == True:
                    import random
                    names = ["Conception Carreras"]
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

            # Clear
            elif command == "clear":
                import os
                os.system('cls' if os.name == 'nt' else 'clear')
                pass
            #?DISCONNECT
            elif command == "exit":
                keepAlive = False
                sock.send('disconnected', addr)
                sock.close()
                continue
            else:
                print("Invalid Command\n")
                pass
    except KeyboardInterrupt:
        keepAlive = False
        sock.send('disconnected', addr)
        sock.close()
