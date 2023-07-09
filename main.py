import argparse
import os
from cipher import process

def write_file(path, output):
    output_path = path
    
    #if file does not exist, create it
    # if not os.path.exists(path):
    #     print("\n\nError: Invalid output path has been given\n\n")
    #     exit(0)

    if os.path.isdir(path):
        output_path = os.path.join(path, "output.txt")
        
    f = open(output_path, "w")
    if(type(output) == dict):
        for key in output:
            f.write(str(key) + " = " + str(output[key]) + "\n")
    else:
        f.write(output)
    f.close()

def read_file(path, key_pair_flag=False):
    input = open(path, "r").read().replace("\n", " ")
    if key_pair_flag:
        return input.split(" ")
    return input

if __name__ == "__main__":
    parser = argparse.ArgumentParser(formatter_class=argparse.RawDescriptionHelpFormatter)

    mode_group = parser.add_mutually_exclusive_group(required=True)
    mode_group.add_argument("-e", "--encrypt", help="Flag argument for encryption of supported chipers/algorithms", action="store_true")
    mode_group.add_argument("-d", "--decrypt", help="Flag argument for decryption of supported chipers/algorithms", action="store_true")
    mode_group.add_argument("-g", "--generate", help="Flag argument for generating keys for supported algorithms", action="store_true")
    mode_group.add_argument("-ha", "--hashing", help="Flag argument for supported hashing algorithms", action="store_true")
    mode_group.add_argument("-a", "--cryptanalysis",  help="Flag argument for cryptanalysis of supported chipers/algorithms", action="store_true")

    cipher_group = parser.add_mutually_exclusive_group(required=True)
    cipher_group.add_argument("--rsa", help="Flag argument for RSA", action="store_true")
    cipher_group.add_argument("--rc4", help="Flag argument for RC4", action="store_true")
    cipher_group.add_argument("-b", "--bifid", help="Flag argument for Bifid chiper", action="store_true")
    cipher_group.add_argument("-p", "--polybius", help="Flag argument for Polybius chiper", action="store_true")
    cipher_group.add_argument("-c", "--cesaer",  help="Flag argument for Cesaer chiper", action="store_true")
    cipher_group.add_argument("--sha256",  help="Flag argument for SHA-256", action="store_true")
    cipher_group.add_argument("--des",  help="Flag argument for DES (ECB)", action="store_true")
    cipher_group.add_argument("--tdes",  help="Flag argument for TDES-EDE (ECB)", action="store_true")

    #required_arg = parser.add_argument_group('Required arguments')
    
    #optional arguments
    parser.add_argument("-m", "--message", metavar='MESSAGE|<MESSAGE_PATH>', help="message or path to message input file")
    parser.add_argument("-k", "--key", metavar='KEY|<KEY_PATH>', help="key or path to key input file (For RSA, have the two values separated by space or newline, last value has to be n)", default = None)
    parser.add_argument("-o", "--output_path", metavar='<OUTPUT_PATH>', help="path to output file", default = None)
    parser.add_argument('-v', '--version', action='version', version='cryptool version 1.6')

    args = parser.parse_args()
    arg_dict = vars(args)
    

    mode_flag = "" #default value
    
    if arg_dict['cryptanalysis']: 
        mode_flag = "cryptanalysis"
    elif arg_dict['encrypt']:
        mode_flag = "encrypt"
    elif arg_dict['decrypt']:
        mode_flag = "decrypt"
    elif arg_dict['generate']:
        mode_flag = "generate"
    elif arg_dict['hashing']:
        mode_flag = "hashing"

    cipher_flag = "" #default value

    if arg_dict['polybius']:
        cipher_flag = "polybius"
    elif arg_dict['bifid']: 
        cipher_flag = "bifid"
    elif arg_dict['cesaer']:
        cipher_flag = "cesaer"
    elif arg_dict['rsa']:
        cipher_flag = "rsa"
    elif arg_dict['rc4']:
        cipher_flag = "rc4"
    elif arg_dict['sha256']:
        cipher_flag = "sha256"
    elif arg_dict['des']:
        cipher_flag = "des"
    elif arg_dict['tdes']:
        cipher_flag = "tdes"

    message = arg_dict['message']
    if message and os.path.isfile(arg_dict['message']):
        message = read_file(arg_dict['message'])

    key = arg_dict['key']
    if key and os.path.isfile(arg_dict['key']):
        key_pair_flag = False
        if cipher_flag == "rsa" and mode_flag != "generate":
            key_pair_flag = True
        key = read_file(arg_dict['key'], key_pair_flag)
        if key_pair_flag:
            key = [int(i) for i in key]
    if key and cipher_flag == "cesaer":
        key = int(key)

    result = process(mode_flag, cipher_flag, message, key)
    
    if arg_dict['output_path']:
        write_file(arg_dict['output_path'], result)
    else:
        print("\n\n", result, "\n\n")