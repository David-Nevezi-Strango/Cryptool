from collections import Counter
from math import inf,sqrt, gcd
from string import ascii_lowercase, ascii_uppercase, digits
from copy import deepcopy
from random import choice, choices, getrandbits
from bitarray import bitarray
from bitarray.util import ba2hex, hex2ba, ba2int

#Cesaer
ALPHABET = ascii_lowercase
ALPHABET_SIZE = 26

#Cesaer
def cesaer_diff(message: str) -> float:
    #reference: https://en.wikipedia.org/wiki/Letter_frequency
    FREQUENCY_DICT = {
        "a" : 8.2, "b" : 1.5, "c" : 2.8, "d" : 4.3, "e" : 13, "f" : 2.2, "g" : 2, "h" : 6.1, "i" : 7, "j" : 0.15, "k" : 0.77,
        "l" : 4, "m" : 2.4, "n" : 6.7, "o" : 7.5, "p" : 1.9, "q" : 0.095, "r" : 6, "s" : 6.3, "t" : 9.1, "u" : 2.8, "v" : 0.98,
        "w" : 2.4, "x" : 0.15, "y" : 2, "z" : 0.074 
    }

    counter = Counter(message)
    return sum([abs(counter.get(letter, 0) * 100 / len(message) - FREQUENCY_DICT[letter]) for letter in ALPHABET]) / ALPHABET_SIZE

#reference: https://medium.com/@momohakarish/caesar-cipher-and-frequency-analysis-with-python-635b04e0186f
def cesaer_encrypt(message: str, key: int) -> str:
    result = ""
    for character in message:
        if not character.isalpha():
            result += character
            continue
        index = ALPHABET.index(character.lower())
        decrypted_char = ALPHABET[(index + key) % ALPHABET_SIZE]

        result += decrypted_char.upper() if character.isupper() else decrypted_char
    return result

def cesaer_decrypt(message: str, key: int) -> str:
    return cesaer_encrypt(message, (-key))

def cesaer_analysis(message: str) -> str:
    min_diff = inf
    possible_key = 0

    for key in range(1, ALPHABET_SIZE):
        current_message = cesaer_decrypt(message, key)
        current_diff = cesaer_diff(current_message)

        if current_diff < min_diff:
            min_diff = current_diff
            possible_key = key
    return cesaer_decrypt(message, possible_key)

#util for bifid & polybius
def polybius_make_table(key=""):
    alphabet = "ABCDEFGHIKLMNOPQRSTUVWXYZ"
    intermediate = ""
    table = []
    
    for char in key + alphabet:
        if char not in intermediate:
            intermediate += char
            
    for index in range(0, 25, 5):
        row = intermediate[index:(index + 5)]
        table.append(row)
        
    return table

def polybius_search(char, table):
    for row_index in range(len(table)):
        for col_index in range(len(table[0])):
            if char == table[row_index][col_index]:
                return row_index, col_index
            
    return None, None

#Bifid
#reference: https://en.wikipedia.org/wiki/Bifid_cipher
def bifid_encrypt(message: str, key: str) -> str:
    row_result = ""
    col_result = ""
    table = polybius_make_table(key.upper())
    message = message.upper().replace('J', 'I')
    
    for character in message:
        if character == " ":
            continue
        else:
            i,j = polybius_search(character, table)
            row_result += str(i + 1) if i is not None else ""
            col_result += str(j + 1) if j is not None else ""

    return polybius_decrypt(row_result + col_result, table)

def bifid_decrypt(message: str, key: str) -> str:
    table = polybius_make_table(key.upper())
    message = polybius_encrypt(message, table)
    result = ""
    
    for index in range(len(message)//2):
        if message[index] == " ":
            result += " "
            index += 1
        else:
            result += table[int(message[index]) - 1][int(message[(len(message) // 2) + index]) - 1]
            index += 2
    return result

#Polybius
def polybius_encrypt(message: str, table = None) -> str:
    if not table:
        table = polybius_make_table()
    result = ""
    message = message.upper().replace('J', 'I')
    
    for character in message:
        if character == " ":
            result += " "
        else:
            i,j = polybius_search(character, table)
            result += str(i + 1) + str(j + 1) if i is not None and j is not None else ""

    return result

def polybius_decrypt(message: str, table = None) -> str:
    if not table:
        table = polybius_make_table()
    result = ""
    index = 0
    
    while index < len(message):
        if message[index] == " ":
            result += " "
            index += 1
        else:
            result += table[int(message[index]) - 1][int(message[index + 1]) - 1]
            index += 2
    return result

#SHA-256
#function definitions by the NIST standard
#reference: https://nvlpubs.nist.gov/nistpubs/FIPS/NIST.FIPS.180-4.pdf 
def SHA256_ROTR(x: int, n: int, w: int = 32):
    #rotate right
    return (x >> n) | (x << w - n)
def SHA256_SHR(x:int, n: int):
    return (x >> n)
def SHA256_Ch(x: int, y: int, z: int):
    #if x then y else z
    return (x & y) ^ (~x & z)
def SHA256_Maj(x: int, y: int, z: int):
    #majority of values
    return (x & y) ^ (x & z) ^ (y & z) 

def SHA256_padding(message: bytearray) -> bytearray:
    length = len(message) * 8 # convert from bytes to bits
    message.append(0x80) # add 1 bit
    while (len(message) * 8 + 64) % 512 != 0: #pad until 448 bits (last 64 is reserved for len)
        message.append(0x00)
    message += length.to_bytes(8, 'big') # pad to 8 bytes or 64 bits
    if ((len(message) * 8) % 512 == 0):
        return message
    else:
        print("\n\nError: Padding did not respect the 512 block constraint!\n\n")
        exit(0)

def SHA256_parse(message: bytearray) -> list:
    chunks = list()
    for i in range(0, len(message) , 64):
        chunks.append(message[i:i+64])
    return chunks

def SHA256_sigma1(chunk: bytearray):
    value = int.from_bytes(chunk, 'big')
    return SHA256_ROTR(value, 7) ^ SHA256_ROTR(value, 18) ^ SHA256_SHR(value, 3)

def SHA256_sigma0(chunk: bytearray):
    value = int.from_bytes(chunk, 'big')
    return SHA256_ROTR(value, 17) ^ SHA256_ROTR(value, 19) ^ SHA256_SHR(value, 10)

def SHA256_sum0(value: int):
    return SHA256_ROTR(value, 2) ^ SHA256_ROTR(value, 13) ^ SHA256_ROTR(value, 22)

def SHA256_sum1(value: int):
    return SHA256_ROTR(value, 6) ^ SHA256_ROTR(value, 11) ^ SHA256_ROTR(value, 25)


def sha_256(message: bytearray) -> int:
    #reference: https://nvlpubs.nist.gov/nistpubs/FIPS/NIST.FIPS.180-4.pdf 
    H_INITIAL = [0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a, 0x510e527f, 0x9b05688c, 0x1f83d9ab, 0x5be0cd19]

    K = [0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5,
        0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3, 0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174,
        0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc, 0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
        0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7, 0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967,
        0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13, 0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85,
        0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3, 0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
        0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
        0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208, 0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2]

    #check if input is correct
    if isinstance(message, str):
        message = bytearray(message, 'ascii')
    elif isinstance(message, bytes):
        message = bytearray(message)
    elif not isinstance(message, bytearray):
        print("\n\nError: argument does not have the type of str, bytes or bytearray!\n\n")
        exit(0)
    #preprocess
    padded_message = SHA256_padding(message)
    parsed_message = SHA256_parse(padded_message)
    
    #init
    hash = deepcopy(H_INITIAL)

    #computation
    for chunk in parsed_message:
        schedule = list()
        for t in range(0,64):
            if (t <= 15):
                #as defined in the standard, first, add 32 bits, t = 8 bits (each index represents 8 bits)
                schedule.append(bytes(chunk[t*4:(t*4) + 4]))
            else:
                s1 = SHA256_sigma1(schedule[t - 2])
                w1 = int.from_bytes(schedule[t - 7], 'big')
                s0 = SHA256_sigma0(schedule[t - 15])
                w2 = int.from_bytes(schedule[t - 16], 'big')
                #truncate result for 4 bytes
                result = ((s1 + w1 + s0 + w2) % 2**32).to_bytes(4, 'big')
                schedule.append(result)

        if (len(schedule) != 64):
            print("\n\nError on Schedule, there are a different number of schedules than 64!\n\n")
            exit(0)

        a = hash[0]
        b = hash[1]
        c = hash[2]
        d = hash[3]
        e = hash[4]
        f = hash[5]
        g = hash[6]
        h = hash[7]

        for t in range(0,64):
            t1 = (h + SHA256_sum1(e) + SHA256_Ch(e,f,g) + K[t] + int.from_bytes(schedule[t], 'big')) % 2**32
            t2 = (SHA256_sum0(a) + SHA256_Maj(a,b,c)) % 2**32
            h = g
            g = f
            f = e
            e = (d + t1) % 2**32
            d = c
            c = b
            b = a
            a = (t1 + t2) % 2**32

        #compute intermediate
        hash[0] = (hash[0] + a) % 2**32
        hash[1] = (hash[1] + b) % 2**32
        hash[2] = (hash[2] + c) % 2**32
        hash[3] = (hash[3] + d) % 2**32
        hash[4] = (hash[4] + e) % 2**32
        hash[5] = (hash[5] + f) % 2**32
        hash[6] = (hash[6] + g) % 2**32
        hash[7] = (hash[7] + h) % 2**32

    final = (hash[0].to_bytes(4,'big') + hash[1].to_bytes(4,'big') + hash[2].to_bytes(4,'big') +
             hash[3].to_bytes(4,'big') + hash[4].to_bytes(4,'big') + hash[5].to_bytes(4,'big') +
             hash[6].to_bytes(4,'big') + hash[7].to_bytes(4,'big'))
    
    return final.hex()

#RSA
def rsa_de_encrypt(message: str, keys: list):
    encrypted_str = ""
    for letter in message:
        encrypted_str += chr((ord(letter) ** keys[0]) % keys[1])
    return encrypted_str

def check_prime(n: int) -> bool:
    if(n % 2 == 0):
        return False
    for i in range(3, int(sqrt(n)), 2):
        if (n % i == 0):
            return False
    return True

def rsa_generate():
    keys = dict()
    primes = [i for i in range(512,1024) if check_prime(i)]
    p = 0
    q = 0
    different = True
    while(different):
        p = choice(primes)
        q = choice(primes)
        if (p != q):
            different = False

    n = p*q
    keys["n"] = n
    phi = (p-1)*(q-1)

    #search for e
    e = 2
    while(e < phi):
        if(gcd(e,phi) == 1):
            break
        else:
            e += 1
    keys["e"] = e
    #search for d
    k = 2
    while(k < phi):
        if(((k*phi)+1)/e).is_integer():
            break
        else:
            k += 1

    d = int(((k*phi)+1)/e)
    keys["d"] = d
    return keys

#DES functions
def des_permute(input: bitarray, perm_table: list, n: int) -> bitarray:
    permutation = bitarray()
    for i in range(n):
        permutation.append(input[perm_table[i] - 1])
    return permutation
 
# Shifting the bits towards left by nth shifts
def des_shift_left(key_part: bitarray, nth_round: int) -> bitarray:
    # Number of bit shifts
    shift_table = [1, 1, 2, 2,
                   2, 2, 2, 2,
                   1, 2, 2, 2,
                   2, 2, 2, 1]
    
    result = bitarray()
    result = key_part[:]
    result <<= shift_table[nth_round]

    return result

def des_generate_subkeys(key: bitarray) -> list:
    
    # Parity bit drop table
    key_perm_table = [57, 49, 41, 33, 25, 17, 9,
                      1,  58, 50, 42, 34, 26, 18,
                      10, 2,  59, 51, 43, 35, 27,
                      19, 11, 3,  60, 52, 44, 36,
                      63, 55, 47, 39, 31, 23, 15,
                      7,  62, 54, 46, 38, 30, 22,
                      14, 6,  61, 53, 45, 37, 29,
                      21, 13, 5,  28, 20, 12, 4]

    # Key- Compression Table : Compression of key from 56 bits to 48 bits
    key_comp_table = [14, 17, 11, 24, 1,  5,
                      3,  28, 15, 6,  21, 10,
                      23, 19, 12, 4,  26, 8,
                      16, 7,  27, 20, 13, 2,
                      41, 52, 31, 37, 47, 55,
                      30, 40, 51, 45, 33, 48,
                      44, 49, 39, 56, 34, 53,
                      46, 42, 50, 36, 29, 32]
    
    # Getting 56 bit key from 64 bit using the parity bits
    intermediate_key = des_permute(key, key_perm_table, 56)

    # Splitting
    left = bitarray()
    right = bitarray()
    left = intermediate_key[:28]
    right = intermediate_key[28:]

    round_keys = list()
    for round in range(16):
        # Shifting the bits by nth shifts by checking from shift table
        left = des_shift_left(left, round)
        right = des_shift_left(right, round)
    
        # Combination of left and right string
        combined = left + right
    
        # Compression of key from 56 to 48 bits
        round_key = bitarray()
        round_key = des_permute(combined, key_comp_table, 48)

        # Add round key to the list
        round_keys.append(round_key)
    return round_keys

def base_des_encrypt(input_message, round_keys):
    # Initial Permutation Table
    initial_perm_table = [58, 50, 42, 34, 26, 18, 10, 2,
                          60, 52, 44, 36, 28, 20, 12, 4,
                          62, 54, 46, 38, 30, 22, 14, 6,
                          64, 56, 48, 40, 32, 24, 16, 8,
                          57, 49, 41, 33, 25, 17, 9,  1,
                          59, 51, 43, 35, 27, 19, 11, 3,
                          61, 53, 45, 37, 29, 21, 13, 5,
                          63, 55, 47, 39, 31, 23, 15, 7]
    
    # Expansion D-box Table
    exp_dbox = [32, 1,  2,  3,  4,  5,  4,  5,
                 6,  7,  8,  9,  8,  9,  10, 11,
                 12, 13, 12, 13, 14, 15, 16, 17,
                 16, 17, 18, 19, 20, 21, 20, 21,
                 22, 23, 24, 25, 24, 25, 26, 27,
                 28, 29, 28, 29, 30, 31, 32, 1]
    
    # Straight Permutation Table
    perm_table = [16,  7, 20, 21,
                  29, 12, 28, 17,
                  1,  15, 23, 26,
                  5,  18, 31, 10,
                  2,  8,  24, 14,
                  32, 27,  3,  9,
                  19, 13, 30,  6,
                  22, 11,  4, 25]
    
    # S-box Table
    sbox = [[[14, 4, 13, 1, 2, 15, 11, 8, 3, 10, 6, 12, 5, 9, 0, 7], #1
             [0, 15, 7, 4, 14, 2, 13, 1, 10, 6, 12, 11, 9, 5, 3, 8],
             [4, 1, 14, 8, 13, 6, 2, 11, 15, 12, 9, 7, 3, 10, 5, 0],
             [15, 12, 8, 2, 4, 9, 1, 7, 5, 11, 3, 14, 10, 0, 6, 13]],
    
             [[15, 1, 8, 14, 6, 11, 3, 4, 9, 7, 2, 13, 12, 0, 5, 10], #2
              [3, 13, 4, 7, 15, 2, 8, 14, 12, 0, 1, 10, 6, 9, 11, 5],
              [0, 14, 7, 11, 10, 4, 13, 1, 5, 8, 12, 6, 9, 3, 2, 15],
              [13, 8, 10, 1, 3, 15, 4, 2, 11, 6, 7, 12, 0, 5, 14, 9]],
    
             [[10, 0, 9, 14, 6, 3, 15, 5, 1, 13, 12, 7, 11, 4, 2, 8], #3
              [13, 7, 0, 9, 3, 4, 6, 10, 2, 8, 5, 14, 12, 11, 15, 1],
              [13, 6, 4, 9, 8, 15, 3, 0, 11, 1, 2, 12, 5, 10, 14, 7],
              [1, 10, 13, 0, 6, 9, 8, 7, 4, 15, 14, 3, 11, 5, 2, 12]],
    
             [[7, 13, 14, 3, 0, 6, 9, 10, 1, 2, 8, 5, 11, 12, 4, 15], #4
              [13, 8, 11, 5, 6, 15, 0, 3, 4, 7, 2, 12, 1, 10, 14, 9],
              [10, 6, 9, 0, 12, 11, 7, 13, 15, 1, 3, 14, 5, 2, 8, 4],
              [3, 15, 0, 6, 10, 1, 13, 8, 9, 4, 5, 11, 12, 7, 2, 14]],
    
             [[2, 12, 4, 1, 7, 10, 11, 6, 8, 5, 3, 15, 13, 0, 14, 9], #5
              [14, 11, 2, 12, 4, 7, 13, 1, 5, 0, 15, 10, 3, 9, 8, 6],
              [4, 2, 1, 11, 10, 13, 7, 8, 15, 9, 12, 5, 6, 3, 0, 14],
              [11, 8, 12, 7, 1, 14, 2, 13, 6, 15, 0, 9, 10, 4, 5, 3]],
    
             [[12, 1, 10, 15, 9, 2, 6, 8, 0, 13, 3, 4, 14, 7, 5, 11], #6
              [10, 15, 4, 2, 7, 12, 9, 5, 6, 1, 13, 14, 0, 11, 3, 8],
              [9, 14, 15, 5, 2, 8, 12, 3, 7, 0, 4, 10, 1, 13, 11, 6],
              [4, 3, 2, 12, 9, 5, 15, 10, 11, 14, 1, 7, 6, 0, 8, 13]],
      
             [[4, 11, 2, 14, 15, 0, 8, 13, 3, 12, 9, 7, 5, 10, 6, 1], #7
              [13, 0, 11, 7, 4, 9, 1, 10, 14, 3, 5, 12, 2, 15, 8, 6],
              [1, 4, 11, 13, 12, 3, 7, 14, 10, 15, 6, 8, 0, 5, 9, 2],
              [6, 11, 13, 8, 1, 4, 10, 7, 9, 5, 0, 15, 14, 2, 3, 12]],
     
             [[13, 2, 8, 4, 6, 15, 11, 1, 10, 9, 3, 14, 5, 0, 12, 7], #8
              [1, 15, 13, 8, 10, 3, 7, 4, 12, 5, 6, 11, 0, 14, 9, 2],
              [7, 11, 4, 1, 9, 12, 14, 2, 0, 6, 10, 13, 15, 3, 5, 8],
              [2, 1, 14, 7, 4, 10, 8, 13, 15, 12, 9, 0, 3, 5, 6, 11]]]
    
    # Final Permutation Table
    final_perm_table = [40, 8, 48, 16, 56, 24, 64, 32,
                        39, 7, 47, 15, 55, 23, 63, 31,
                        38, 6, 46, 14, 54, 22, 62, 30,
                        37, 5, 45, 13, 53, 21, 61, 29,
                        36, 4, 44, 12, 52, 20, 60, 28,
                        35, 3, 43, 11, 51, 19, 59, 27,
                        34, 2, 42, 10, 50, 18, 58, 26,
                        33, 1, 41,  9, 49, 17, 57, 25]

    final_result = bitarray()
    
    # Pad message if necessary
    if (len(input_message) % 64 != 0):
        pad = [0] * (64 - (len(input_message) % 64))
        input_message.extend(pad)
    
    # Divide message into blocks
    message_blocks = list()
    for blocksize in range(0, len(input_message), 64):
        message_blocks.append(input_message[blocksize:(blocksize + 64)])
    
    for message in message_blocks:
        # Initial Permutation
        message = des_permute(message, initial_perm_table, 64)
    
        # Splitting
        left = message[0:32]
        right = message[32:64]
        for round in range(16):
            #  Expansion D-box: Expanding the 32 bits data into 48 bits
            right_expanded = des_permute(right, exp_dbox, 48)
    
            # XOR RoundKey[round] and right_expanded
            xor_x = right_expanded ^ round_keys[round]
    
            # S-boxex: substituting the value from s-box table by calculating row and column
            sbox_bitarray = bitarray()
            for index in range(8):
                row = (xor_x[index * 6] * 2 + xor_x[index * 6 + 5] * 2) - 1
                col = ba2int(xor_x[(index * 6 + 1):(index * 6 + 5)]) - 1
                val = bitarray()
                val.frombytes(int.to_bytes(sbox[index][row][col], 4, "big")) 
                sbox_bitarray = sbox_bitarray + val
    
            # Straight D-box: After substituting rearranging the bits
            sbox_bitarray = des_permute(sbox_bitarray, perm_table, 32)
    
            # XOR left and sbox_bitarray
            xor_result = left ^ sbox_bitarray
            left = xor_result
    
            # Swapper
            if(round != 15):
                left, right = right, left
    
        # Combination
        combine = left + right
    
        # Final permutation: final rearranging of bits to get cipher text
        block_result = des_permute(combine, final_perm_table, 64)
        final_result += block_result

    return final_result
 
 
def convert_to_bitarray(input: str) -> bitarray:
# Check if input is correct
    result = bitarray()
    if isinstance(input, bitarray):
        return input
    elif isinstance(input, str):
        result.frombytes(input.encode("utf-8"))
    elif isinstance(input, bytes):
        result.frombytes(input)
    elif isinstance(input, bytearray):
        result.frombytes(bytes(input))
    elif not isinstance(input, bitarray):
        print("\n\nError: cannot convert to bitarray!\n\n")
        exit(0)
    return result

def des_encrypt(message: str, key: str) -> str:

    key = convert_to_bitarray(key)
    message = convert_to_bitarray(message)

    round_keys = des_generate_subkeys(key)
 
    result = base_des_encrypt(message, round_keys)

    return ba2hex(result)#.tobytes().hex()

def des_decrypt(message: str, key: str) -> str:
    
    key = convert_to_bitarray(key)
    message = hex2ba(message)
    #message = convert_to_bitarray(message)

    round_keys = des_generate_subkeys(key)
    
    result = base_des_encrypt(message, round_keys[::-1])

    return result.tobytes().decode()

def des_generate():
    return "{:016x}".format(getrandbits(64))

#TDES-EDE
def tdes_ede_encrypt(message: str, key: str) -> str:
    
    key = convert_to_bitarray(key)
    message = convert_to_bitarray(message)

    # Divide message into blocks
    key_blocks = list()
    for blocksize in range(0, len(key), 64):
        key_blocks.append(key[blocksize:(blocksize + 64)])

    
    # Getting 56 bit key from 64 bit using the parity bits
    result = message
    for index in range(len(key_blocks)):

        round_keys = des_generate_subkeys(key_blocks[index])

        if (index % 2 != 0):
            round_keys = round_keys[::-1]
            
        result = base_des_encrypt(result, round_keys)

    return result.tobytes().hex()

def tdes_ede_decrypt(message: str, key: str) -> str:

    key = convert_to_bitarray(key)
    #message = convert_to_bitarray(message)
    message = hex2ba(message)

    # Divide message into blocks
    key_blocks = list()
    for blocksize in range(0, len(key), 64):
        key_blocks.append(key[blocksize:(blocksize + 64)])

    result = message
    for index in range(len(key_blocks)-1, -1, -1):

        round_keys = des_generate_subkeys(key_blocks[index])

        if (index % 2 == 0):
            round_keys = round_keys[::-1]

        result = base_des_encrypt(result, round_keys)

    return result.tobytes().decode()

def tdes_generate():
    return "".join(des_generate() for i in range(3))

#RC4
#reference: https://www.youtube.com/watch?v=1UP56WM4ook
def rc4_key_process(key: str) -> list:
    result = list()
    res_index = 0
    while (res_index != 256):
        count = 0
        for char in key:
            result.append(ord(char))
            count += 1
            if (len(result) == 256):
                break
        res_index += count
    return result

def rc4_pseudo_random_gen(S: list) -> int:
    #this function will be a generator
    j = 0
    i = 0
    while True:
        i = (i + 1) % 256
        j = (S[i] + j) % 256
        #swap
        S[i] , S[j] = S[j] , S[i]
        #yield index for keystream
        yield S[(S[i] + S[j]) % 256]
    

def rc4_key_sched(K: list) -> list:
    S = [i for i in range(256)]
    j = 0
    
    for i in range(256):
        j = (j + S[i] + K[i]) % 256
        #swap
        S[i] , S[j] = S[j] , S[i]

    return S

def rc4_encrypt(message: str, key: str) -> str:
    processed_msg = [ord(char) for char in message]
    processed_key = rc4_key_process(key)
    key_stream = rc4_pseudo_random_gen(rc4_key_sched(processed_key))
    result = ""
    for char in processed_msg:
        #convert XOR result to hex without 0x prefix and pad left side if needed
        #special case where intermediate is 1/2 byte, not 1 byte (ASCII is 1 btye representation)
        result += str(hex(char ^ next(key_stream)))[2:].rjust(2, "0")
    return result

def rc4_decrypt(message: str, key: str):
    processed_key = rc4_key_process(key)
    #convert from hex to list of corresponding ASCII code
    processed_msg = [int(("0x" + message[index:index+2]), 16) for index in range(0, len(message), 2)]
    key_stream = rc4_pseudo_random_gen(rc4_key_sched(processed_key))
    result = ""
    for char in processed_msg:
        result += str(chr(char ^ next(key_stream)))
    return result

def rc4_generate():
    return ''.join(choices(ascii_uppercase + digits, k = 256))

bifid_dict = {
    "encrypt" : bifid_encrypt,
    "decrypt" : bifid_decrypt
}

polybius_dict = {
    "encrypt" : polybius_encrypt,
    "decrypt" : polybius_decrypt
}

cesaer_dict = {
    "encrypt" : cesaer_encrypt,
    "decrypt" : cesaer_decrypt,
    "cryptanalysis" : cesaer_analysis
}

rsa_dict = {
    "encrypt" : rsa_de_encrypt,
    "decrypt" : rsa_de_encrypt,
    "generate" : rsa_generate
}

des_dict = {
    "encrypt" : des_encrypt,
    "decrypt" : des_decrypt,
    "generate" : des_generate
}

tdes_dict = {
    "encrypt" : tdes_ede_encrypt,
    "decrypt" : tdes_ede_decrypt,
    "generate" : tdes_generate
}

rc4_dict = {
    "encrypt" : rc4_encrypt,
    "decrypt" : rc4_decrypt,
    "generate" : rc4_generate
}

cipher_dict = {
    "bifid" :bifid_dict,
    "polybius" : polybius_dict,
    "cesaer" : cesaer_dict,
    "sha256" : sha_256,
    "rsa" : rsa_dict,
    "des" : des_dict,
    "tdes" : tdes_dict,
    "rc4" : rc4_dict
}


def process(mode_flag, cipher_flag, message, key):


    if (mode_flag == "hashing" and cipher_flag != "sha256"):
        print("\n\nError: Hashing is supported only for SHA-256\n\n")
        exit(0)

    if (mode_flag == "generate" and cipher_flag not in ["rsa", "rc4", "des", "tdes"]):
        print("\n\nError: Generating public/private keys is supported only for RSA, RC4, DES, T-DES\n\n")
        exit(0)

    if (mode_flag == "cryptanalysis" and cipher_flag != "cesaer"):
        print("\n\nError: cryptanalysis is supported only for Cesaer's cipher\n\n")
        exit(0)    
        
    if (mode_flag in ["encrypt", "decrypt"]) and not key and (cipher_flag not in ["polybius", "sha256"]):
        print("\n\nError: Encryption/Decryption selected but no key was given\n\n")
        exit(0)
        
    if (mode_flag != "cryptanalysis" and cipher_flag == "cesaer" and (type(key) is not int)):
        print("\n\nError: Cesaer's cipher needs a number as key\n\n")
        exit(0)
    
    if (cipher_flag == "des" and mode_flag != "generate" and (len(key) != 16) ):
        print("\n\nError: key has different length than 64 bits (encoding is UTF-8)!\n\n")
        exit(0)

    if (cipher_flag == "tdes" and mode_flag != "generate" and (len(key) != 48)):
        print("\n\nError: key has different length than 192 bits (encoding is UTF-8)!\n\n")
        exit(0)

    if (cipher_flag == "sha256"):
        return cipher_dict[cipher_flag](message)
    elif (cipher_flag in ["rsa", "rc4", "des", "tdes"] and mode_flag == "generate"):
        return cipher_dict[cipher_flag][mode_flag]()
    
    return cipher_dict[cipher_flag][mode_flag](message, key) if mode_flag != "cryptanalysis" and cipher_flag != "polybius" else cipher_dict[cipher_flag][mode_flag](message) 