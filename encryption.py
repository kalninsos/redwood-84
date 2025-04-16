import lookup_tables
from lookup_tables import *
import shared_funcs
from shared_funcs import *
import random
import string

padding_amt = 16

def sub_bytes(corpus):
    for i in range(len(corpus)):
        corpus[i] = sbox[corpus[i]]
    return corpus

def shift_rows(corpus):
    temp = [0 for _ in range(len(corpus))]

    temp[0] = corpus[0]
    temp[1] = corpus[5]
    temp[2] = corpus[10]
    temp[3] = corpus[15]

    temp[4] = corpus[4]
    temp[5] = corpus[9]
    temp[6] = corpus[14]
    temp[7] = corpus[3]

    temp[8] = corpus[8]
    temp[9] = corpus[13]
    temp[10] = corpus[2]
    temp[11] = corpus[7]

    temp[12] = corpus[12]
    temp[13] = corpus[1]
    temp[14] = corpus[6]
    temp[15] = corpus[11]

    for i in range(len(corpus)):
        corpus[i] = temp[i]

def mix_columns(corpus):
    temp = [0 for _ in range(len(corpus))]

    temp[0] = (multiply_bafo2[corpus[0]] ^ multiply_bafo3[corpus[1]] ^ corpus[2] ^ corpus[3])
    temp[1] = (corpus[0] ^ multiply_bafo2[corpus[1]] ^ multiply_bafo3[corpus[2]] ^ corpus[3])
    temp[2] = (corpus[0] ^ corpus[1] ^ multiply_bafo2[corpus[2]] ^ multiply_bafo3[corpus[3]])
    temp[3] = (multiply_bafo3[corpus[0]] ^ corpus[1] ^ corpus[2] ^ multiply_bafo2[corpus[3]])
    
    temp[4] = (multiply_bafo2[corpus[4]] ^ multiply_bafo3[corpus[5]] ^ corpus[6] ^ corpus[7])
    temp[5] = (corpus[4] ^ multiply_bafo2[corpus[5]] ^ multiply_bafo3[corpus[6]] ^ corpus[7])
    temp[6] = (corpus[4] ^ corpus[5] ^ multiply_bafo2[corpus[6]] ^ multiply_bafo3[corpus[7]])
    temp[7] = (multiply_bafo3[corpus[4]] ^ corpus[5] ^ corpus[6] ^ multiply_bafo2[corpus[7]])
    
    temp[8] = (multiply_bafo2[corpus[8]] ^ multiply_bafo3[corpus[9]] ^ corpus[10] ^ corpus[11])
    temp[9] = (corpus[8] ^ multiply_bafo2[corpus[9]] ^ multiply_bafo3[corpus[10]] ^ corpus[11])
    temp[10] = (corpus[8] ^ corpus[9] ^ multiply_bafo2[corpus[10]] ^ multiply_bafo3[corpus[11]])
    temp[11] = (multiply_bafo3[corpus[8]] ^ corpus[9] ^ corpus[10] ^ multiply_bafo2[corpus[11]])
    
    temp[12] = (multiply_bafo2[corpus[12]] ^ multiply_bafo3[corpus[13]] ^ corpus[14] ^ corpus[15])
    temp[13] = (corpus[12] ^ multiply_bafo2[corpus[13]] ^ multiply_bafo3[corpus[14]] ^ corpus[15])
    temp[14] = (corpus[12] ^ corpus[13] ^ multiply_bafo2[corpus[14]] ^ multiply_bafo3[corpus[15]])
    temp[15] = (multiply_bafo3[corpus[12]] ^ corpus[13] ^ corpus[14] ^ multiply_bafo2[corpus[15]])

    for i in range(len(corpus)):
        corpus[i] = temp[i]

def split_to_1_byte(m_list):
    partitioned_list = [[0 for _ in range(0,16)] for _ in range(len(m_list))]
    for k in range(len(m_list)):
        i, j = 0, 2
        for l in range(0,16):
            partitioned_list[k][l] = (int(m_list[k][i:j], 16))
            i = j
            j = j + 2
        m_list[k] = partitioned_list[k]
    return m_list

def split_to_16_bytes(plaintext):
    message_list = []

    remaining_length = len(plaintext)
    i, j = 0, 16
    
    while remaining_length >= 16:
        message_list.append(plaintext[i:j])
        i = j
        j += 16
        remaining_length -= 16

    if remaining_length < 16 and remaining_length > 0:
        global padding_amt
        padding_amt = remaining_length
        padded_message = plaintext[i:len(plaintext)]
        while remaining_length != 16 and remaining_length > 0:
            padded_message = padded_message + random.choice(string.ascii_letters)
            remaining_length += 1
        message_list.append(padded_message)
    
    for i in range(len(message_list)):
         message_list[i] = message_list[i].encode('utf-8').hex()

    message_list = split_to_1_byte(message_list)

    return message_list

def chunk_to_str(chunk):
    temp = ""
    for i in range(0, 16):
        temp += format(chunk[i], '02x') # 0: pad with zeros, 2: pad to 2 digits, x: convert to hex
        
    return temp

def AES_Encrypt(plaintext, key):
    key = text_to_list(key)

    encrypted_string = ""
    message_list = split_to_16_bytes(plaintext)

    expanded_key = [0 for _ in range(0,16)]
    expanded_key = key_expansion(key, expanded_key)

    for chunk in message_list:
        #initial round
        add_round_key(chunk, key)
        #normally expand key here, but it has already been expanded

        #main rounds
        for i in range(0,9): #hardcoded 10 (9) rounds for AES_128, alter for > AES128
            sub_bytes(chunk)
            shift_rows(chunk)
            mix_columns(chunk)

            index = (16 * (i+1))
            add_round_key(chunk, expanded_key[index:index + 16])
            #print(f'chunk at round: {i} {chunk}')
        
        #final round
        sub_bytes(chunk)
        shift_rows(chunk)
        add_round_key(chunk, expanded_key[160:176])

        encrypted_string = encrypted_string + chunk_to_str(chunk)
    
    global padding_amt
    encrypted_string = encrypted_string + (trim_bafo[16 - padding_amt])
    return encrypted_string

#for testing
# key = '2b7e151628aed2a6abf7158809cf4f3c'
# plaintext = "this is a message for testing purposes"
# encrypted_text = AES_Encrypt(plaintext, key)

# print(f"Your encrypted message is: {encrypted_text}")
