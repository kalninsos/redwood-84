import lookup_tables
from lookup_tables import *
import shared_funcs
from shared_funcs import *

def splitter(text):
    m_list = []
    i, j = 0, 32
    for _ in range(0,len(text)//32):
        chunk = text[i:j]
        c_list = []
        k, l = 0, 2
        for _ in range(0,16):
            c_list.append(int(chunk[k:l], 16))
            k = l 
            l += 2
        m_list.append(c_list)
        i = j 
        j += 32
    
    return m_list

def inverse_shift_rows(corpus):
    temp = [0 for _ in range(len(corpus))]

    temp[0] = corpus[0]
    temp[1] = corpus[13]
    temp[2] = corpus[10]
    temp[3] = corpus[7]

    temp[4] = corpus[4]
    temp[5] = corpus[1]
    temp[6] = corpus[14]
    temp[7] = corpus[11]

    temp[8] = corpus[8]
    temp[9] = corpus[5]
    temp[10] = corpus[2]
    temp[11] = corpus[15]

    temp[12] = corpus[12]
    temp[13] = corpus[9]
    temp[14] = corpus[6]
    temp[15] = corpus[3]

    for i in range(len(corpus)):
        corpus[i] = temp[i]

def inverse_sub_bytes(corpus):
    for i in range(len(corpus)):
        corpus[i] = inv_s_box[corpus[i]]

def inverse_mix_columns(corpus):
  temp = [0 for _ in range(len(corpus))]

  temp[0] = (multiply_bafo_14[corpus[0]] ^ multiply_bafo_11[corpus[1]] ^ multiply_bafo_13[corpus[2]] ^ multiply_bafo_9[corpus[3]])
  temp[1] = (multiply_bafo_9[corpus[0]] ^ multiply_bafo_14[corpus[1]] ^ multiply_bafo_11[corpus[2]] ^ multiply_bafo_13[corpus[3]])
  temp[2] = (multiply_bafo_13[corpus[0]] ^ multiply_bafo_9[corpus[1]] ^ multiply_bafo_14[corpus[2]] ^ multiply_bafo_11[corpus[3]])
  temp[3] = (multiply_bafo_11[corpus[0]] ^ multiply_bafo_13[corpus[1]] ^ multiply_bafo_9[corpus[2]] ^ multiply_bafo_14[corpus[3]])

  temp[4] = (multiply_bafo_14[corpus[4]] ^ multiply_bafo_11[corpus[5]] ^ multiply_bafo_13[corpus[6]] ^ multiply_bafo_9[corpus[7]])
  temp[5] = (multiply_bafo_9[corpus[4]] ^ multiply_bafo_14[corpus[5]] ^ multiply_bafo_11[corpus[6]] ^ multiply_bafo_13[corpus[7]])
  temp[6] = (multiply_bafo_13[corpus[4]] ^ multiply_bafo_9[corpus[5]] ^ multiply_bafo_14[corpus[6]] ^ multiply_bafo_11[corpus[7]])
  temp[7] = (multiply_bafo_11[corpus[4]] ^ multiply_bafo_13[corpus[5]] ^ multiply_bafo_9[corpus[6]] ^ multiply_bafo_14[corpus[7]])

  temp[8] = (multiply_bafo_14[corpus[8]] ^ multiply_bafo_11[corpus[9]] ^ multiply_bafo_13[corpus[10]] ^ multiply_bafo_9[corpus[11]])
  temp[9] = (multiply_bafo_9[corpus[8]] ^ multiply_bafo_14[corpus[9]] ^ multiply_bafo_11[corpus[10]] ^ multiply_bafo_13[corpus[11]])
  temp[10] = (multiply_bafo_13[corpus[8]] ^ multiply_bafo_9[corpus[9]] ^ multiply_bafo_14[corpus[10]] ^ multiply_bafo_11[corpus[11]])
  temp[11] = (multiply_bafo_11[corpus[8]] ^ multiply_bafo_13[corpus[9]] ^ multiply_bafo_9[corpus[10]] ^ multiply_bafo_14[corpus[11]])

  temp[12] = (multiply_bafo_14[corpus[12]] ^ multiply_bafo_11[corpus[13]] ^ multiply_bafo_13[corpus[14]] ^ multiply_bafo_9[corpus[15]])
  temp[13] = (multiply_bafo_9[corpus[12]] ^ multiply_bafo_14[corpus[13]] ^ multiply_bafo_11[corpus[14]] ^ multiply_bafo_13[corpus[15]])
  temp[14] = (multiply_bafo_13[corpus[12]] ^ multiply_bafo_9[corpus[13]] ^ multiply_bafo_14[corpus[14]] ^ multiply_bafo_11[corpus[15]])
  temp[15] = (multiply_bafo_11[corpus[12]] ^ multiply_bafo_13[corpus[13]] ^ multiply_bafo_9[corpus[14]] ^ multiply_bafo_14[corpus[15]])

  for i in range(len(corpus)):
      corpus[i] = temp[i]

def DEC_chunk_to_str(chunk):
    temp = ''
    for i in range(0, 16):
        temp += bytes.fromhex(format(chunk[i], '02x')).decode('utf-8')
    return temp

def AES_Decrypt(encrypted_text, key):
    key = text_to_list(key)

    decrypted_string = ""
    message_list = splitter(encrypted_text)

    expanded_key = [0 for _ in range(0,16)]
    expanded_key = key_expansion(key, expanded_key)

    for chunk in message_list:
        add_round_key(chunk, expanded_key[160:176]) #only want last 16 bytes of key

        for i in range(9,0,-1):
            inverse_shift_rows(chunk)
            inverse_sub_bytes(chunk)

            index = (16 * i)
            add_round_key(chunk, expanded_key[index:index + 16])
            inverse_mix_columns(chunk)
        
        inverse_shift_rows(chunk)
        inverse_sub_bytes(chunk)
        add_round_key(chunk, key) #I THINK that its correct to use key here, other example uses expanded key so idk

        decrypted_string = decrypted_string + DEC_chunk_to_str(chunk)

    return decrypted_string

#for testing
# key = '2b7e151628aed2a6abf7158809cf4f3c'
# #t = "2b20528fcbea8672cb8b5687aa7e0eb5"
# t = "2b20528fcbea8672cb8b5687aa7e0eb5448929e0b4055dfbc269935ae3aad6bb0cffed4d0b15a568729b34d09b59dc99"
# decrypted = AES_Decrypt(t, key)
# print('this is decrypted: ', decrypted)