import lookup_tables
from lookup_tables import *

def add_round_key(corpus, round_key):
    for i in range(len(corpus)):
        corpus[i] ^= round_key[i]

def text_to_list(m_list):
    new_message_list = []
    i, j = 0, 2
    for _ in range(0,16):
        new_message_list.append(int(m_list[i:j], 16))
        i = j
        j = j + 2
    return new_message_list

def key_expansion_core(four_byte, rcon_index):
    #rotation
    temp = four_byte[0]
    four_byte[0] = four_byte[1]
    four_byte[1] = four_byte[2]
    four_byte[2] = four_byte[3]
    four_byte[3] = temp

    #bit substitution
    for i in range(len(four_byte)):
        four_byte[i] = sbox[four_byte[i]]

    #rcon
    four_byte[0] ^= rcon[rcon_index]

def key_expansion(key, expanded_key):
    expanded_key = [0 for _ in range(176)]
    for i in range(0,16):
        expanded_key[i] = key[i]
    
    #variable storage
    bytes_generated = 16
    rcon_iteration = 0
    temp = [0 for _ in range(4)]

    while bytes_generated < 176:
        for i in range(0,4):
            temp[i] = expanded_key[i + bytes_generated - 4]
        
        if bytes_generated % 16 == 0:
            key_expansion_core(temp, rcon_iteration + 1)
            rcon_iteration +=1
        
        for i in range(0,4):
            expanded_key[bytes_generated] = expanded_key[bytes_generated - 16] ^ temp[i]
            bytes_generated += 1
            
    return expanded_key