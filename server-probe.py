import socket
from enum import Enum
import bcrypt
import json
import threading
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


# save credentials to file
def save_credentials(credentials):
    with open('client-credentials.json', 'w') as file:
        json.dump(credentials, file)


# load credentials
def load_credentials():
    with open('client-credentials.json', 'r') as file:
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
    print('\n[INFO] Message received!')
    print(f'[EXTRACT] Extracting data out of the packet of size {len(msg)}')
    data = pickle.loads(msg)
    msg_header = data['header']
    msg_content = data['content']
    msg_length = int(msg_header[HEADER_PART:])
    msg_type = msg_header[:HEADER_PART].lstrip('0')
    return (msg_type, msg_length, msg_content)


# send message to server
def send_message(client, msg_content, msg_type):
    client.send(message_forming(msg_content, msg_type))


# key derivation
def derivate_key():
    print('\n[KEY] Key derivation...')
    kc = bcrypt.kdf(password=KI.encode(),salt=load_credentials()['Rand'].encode(),desired_key_bytes=int(KEY_SIZE/8),rounds=128)
    update_credentials('Kc', bin(int(kc.hex(), 16))[2:].zfill(KEY_SIZE))


# manage key derivation and time of availability
def key_management():
    derivate_key()
    return RepeatTimer(KEY_AVAILABILITY, derivate_key)


# aes decryption
def aes_management_decrypt(msg):
    data = pickle.loads(msg)
    kc = load_credentials()['Kc']

    cipher = AES.new(key=BitArray(bin=kc).bytes, mode=AES.MODE_EAX, nonce=data['nonce'])
    encrypted_message = data['text']
    decrypted_message = cipher.decrypt(encrypted_message).decode()
    print(f'\n[MSG] Encrypted message : {encrypted_message}')

    return decrypted_message


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


# client initialisation
def init():
    credentials = {
        'Ki': KI,
        }

    save_credentials(credentials)

    client = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    client.connect(ADDRESS)
    client.settimeout(10)
    return client


# connect to server and process to authentification and send some messages
def main():
    print('[INIT] Client initialisation...')
    client = init()
    print('[CONNECTION] Client connected to server...')

    msg_type, _, msg_content = message_peeling(client.recv(PACKET_SIZE))
    if msg_type==MessageType.CHALLENGE.value:
        print('\n[AUTHENTICATION] Challenge received')
        challenge = msg_content
        update_credentials('Rand', challenge)
        print('[AUTHENTICATION] Sending SRES')
        send_message(client, resolve_challenge(KI, challenge), MessageType.SRES.value)
        key_thread = key_management()

    print('\n[AES] Sending AES encrypted message...')
    send_message(client, aes_management_encrypt(MESSAGES['AES']), MessageType.AES.value)
    msg_server = client.recv(PACKET_SIZE)
    msg_type, msg_length, msg_content = message_peeling(msg_server)
    print(f'[MSG] Message of length {msg_length} received: {aes_management_decrypt(msg_content)}')

    send_message(client, 'See you!', MessageType.DISCONNECT.value)
    print('\n[QUIT] Client quitting...')
    key_thread.cancel()


if __name__ == '__main__':
    main()

