import socket 
import threading
import random 
from enum import Enum
import bcrypt
import json
from Crypto.Cipher import AES
from bitstring import BitArray
import pickle

# Management of message types
class MessageType(Enum):
    CHALLENGE = 'CHALL'
    SRES = 'SRES'
    MESSAGE = 'MSGE'
    DISCONNECT = 'QUIT'
    AES = 'AES1'

# Repeat the timer when triggered
class RepeatTimer(threading.Timer):
    def run(self):
        while not self.finished.wait(self.interval):
            self.function(*self.args, **self.kwargs)

HEADER_PART = 8                 # size of one part of the header
HEADER_SIZE = HEADER_PART*2     # size of the header
PACKET_SIZE = 250               # size of the sended packet

PORT = 2022         # port used
SERVER = socket.gethostbyname(socket.gethostname())     # server identification
ADDRESS = (SERVER, PORT)        # server complete address
UN = 'utf-8'        # encoding
KEY_AVAILABILITY = 20.0*60.0    # time to wait before new key derivation (20min)

MESSAGES = {
    'AES': 'AES encryption'
}

KEY_SIZE = 128 # Ki key size

KI = '11101110000101010000001000101110111000010010110010011100101000000011111100110011110101010111010001100110010010010101111010111010'
CHALLENGE = bin(random.getrandbits(KEY_SIZE))[2:].zfill(KEY_SIZE)


# save credentials to file
def save_credentials(credentials):
    with open('server-credentials.json', 'w') as file:
        json.dump(credentials, file)


# load credentials
def load_credentials():
    with open('server-credentials.json', 'r') as file:
        credentials = json.load(file)
    return credentials


# modify credentials
def update_credentials(key, value):
    credentials = load_credentials()
    credentials[key] = value
    save_credentials(credentials)


# rand challenge computation
def resolve_challenge(key, challenge):
    key_left, key_right = key[:int(KEY_SIZE/2)], key[int(KEY_SIZE/2):]
    challenge_left, challenge_right = challenge[:int(KEY_SIZE/2)], challenge[int(KEY_SIZE/2):]

    as01 = int(key_left, 2)^int(challenge_right, 2)
    as02 = int(key_right, 2)^int(challenge_left, 2)

    as0 = bin(as01^as02)[2:].zfill(int(KEY_SIZE/2))

    as0_left, as0_right = as0[:int(KEY_SIZE/4)], as0[int(KEY_SIZE/4):]
    as1 = int(as0_left, 2)^int(as0_right, 2)

    return bin(as1)[2:].zfill(int(KEY_SIZE/4))


# aes decryption
def aes_management_decrypt(msg):
    data = pickle.loads(msg)
    kc = load_credentials()['Kc']

    cipher = AES.new(key=BitArray(bin=kc).bytes, mode=AES.MODE_EAX, nonce=data['nonce'])
    return cipher.decrypt(data['text']).decode()


# aes encryption
def aes_management_encrypt(msg):
    kc = load_credentials()['Kc']
    cipher = AES.new(key=BitArray(bin=kc).bytes, mode=AES.MODE_EAX)
    ciphertext, tag = cipher.encrypt_and_digest(msg.encode())
    data = {
        'text': ciphertext,
        'tag': tag,
        'nonce': cipher.nonce
    }
    return pickle.dumps(data)


# server initialisation
def init():
    credentials = {
        'Ki': KI,
        'Rand': CHALLENGE
        }

    save_credentials(credentials)

    server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server.bind(ADDRESS)
    server.settimeout(2)
    return server


# prepare message to send
def message_forming(msg_content, msg_type):
    msg_header = f'{msg_type}'.zfill(HEADER_PART)+f'{len(msg_content)}'.zfill(HEADER_PART)
    data = {
        'header': msg_header,
        'content': msg_content
    }
    p_data = pickle.dumps(data)
    p_data += b'0'*(PACKET_SIZE - len(p_data))
    return p_data


# extract data out of a received message
def message_peeling(msg):
    print(f'[EXTRACT] Extracting data out of the packet of size {len(msg)}')
    data = pickle.loads(msg)
    msg_header = data['header']
    msg_content = data['content']
    msg_length = int(msg_header[HEADER_PART:])
    msg_type = msg_header[:HEADER_PART].lstrip('0')
    return (msg_type, msg_length, msg_content)


# check if the rand challenge is validated
def compare_sres(sres, challenge):
    return sres==resolve_challenge(KI, challenge)


# process to authentidication
def authenticate(connection):
    authentified = False
    challenge = load_credentials()['Rand']
    while not authentified:
        message = message_forming(challenge, MessageType.CHALLENGE.value)
        connection.send(message)
        msg_client = connection.recv(PACKET_SIZE)
        if(msg_client):
            msg_type, _, msg_content = message_peeling(msg_client)
            if msg_type == MessageType.SRES.value:
                authentified = compare_sres(msg_content, challenge)
            else: 
                connection.close()
                break
        print(f'Authentification: {authentified}')
        

# check if message is sent by the server
def check_for_new_message(connection):
    while True:
        msg_client = connection.recv(PACKET_SIZE)
        msg_type, msg_length, msg_content = message_peeling(msg_client)
        if msg_type == MessageType.DISCONNECT.value:
            print(f'[MSG] Message of length {msg_length} received: {msg_content}')
            print('[RELEASING] Closing connection...')
            connection.close()
            break
        if msg_type == MessageType.AES.value:
            msg_decrypted = aes_management_decrypt(msg_content)
            print(f'[MSG] Message of length {msg_length} received: {msg_decrypted}')
            print('[AES] Sending AES encrypted message...')
            connection.send(message_forming(aes_management_encrypt(MESSAGES['AES']), MessageType.AES.value))
    print('[SHUTDOWN] Server shutdown...')


# key derivation
def derivate_key():
    print('[KEY] Key derivation...')
    kc = bcrypt.kdf(password=KI.encode(),salt=load_credentials()['Rand'].encode(),desired_key_bytes=int(KEY_SIZE/8),rounds=128)
    update_credentials('Kc', bin(int(kc.hex(), 16))[2:].zfill(KEY_SIZE))


# manage key derivation and time of availability
def key_management():
    derivate_key()
    return RepeatTimer(KEY_AVAILABILITY, derivate_key)


# manage client connection
def client_handler(connection, address):
    print(f'[CONNECTION] Client {address} connected...')
    authenticate(connection)
    key_thread = key_management()
    key_thread.start()
    check_for_new_message(connection)
    key_thread.cancel()

    
# start server
def start(server):
    server.listen()
    print(f'[LISTENING] Server is listening on {SERVER}...')

    try:
        # while True:   #to use for multiple client connections
        connection, address = server.accept()
        thread = threading.Thread(target=client_handler, args=(connection, address))
        thread.start()
    except KeyboardInterrupt:
        print('[SHUTDOWN] Server shutdown...')


# initialise and start server
def main():
    print('[INIT] Server initialisation...')
    server = init()
    print('[START] Server starting...')
    start(server)


if __name__ == '__main__':
    main()