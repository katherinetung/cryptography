import random
import math
import sympy

BIG_NUM=99999
# Caesar Cipher
# Arguments: string, integer
# Returns: string
def encrypt_caesar(plaintext, offset):
    working_string=''
    for i in plaintext:
        num_i=ord(i)
        if ord('A') <= num_i <= ord('Z'):
            new=offset%26+num_i
            if new > ord('Z'):
                new-=26
            working_string+=chr(new)
        else:
            working_string+=i
    return working_string

# Arguments: string, integer
# Returns: string
def decrypt_caesar(ciphertext, offset):
    return encrypt_caesar(ciphertext,-1*offset)

# Vigenere Cipher
# Arguments: string, string
# Returns: string
def encrypt_vigenere(plaintext, keyword):
    encrypt_str=''
    counter=0
    while counter < len(plaintext):
        encrypt_str+=keyword[counter%len(keyword)]
        counter+=1
    working_string=''
    for i in range(len(plaintext)):
        offset=ord(encrypt_str[i])-ord('A')
        working_string+=encrypt_caesar(plaintext[i],offset)
    return working_string

# Arguments: string, string
# Returns: string
def decrypt_vigenere(ciphertext, keyword):
    # Find an "opposite word." A's opposite is a special char,
    # Opposite of B is Z, opposite of C is Y, etc.
    opp_word=''
    for ch in keyword:
        off_from_a=ord(ch)-ord('A')
        off_from_z=ord('Z')-off_from_a+1
        opp_word+=chr(off_from_z)
    print(opp_word)
    return encrypt_vigenere(ciphertext, opp_word)

# Merkle-Hellman Knapsack Cryptosystem
# Arguments: integer
# Returns: tuple (W, Q, R) - W a length-n tuple of integers, Q and R both integers
def generate_private_key(n=8):
    #Part 1: Generating W
    si_sequence=[2]
    for counter in range(n-1):
        s_sum=sum(si_sequence)
        new_el=random.randint(s_sum+1,2*s_sum)
        si_sequence.append(new_el)
    w=tuple(si_sequence)
    #Part 2: Choosing Q
    q=random.randint(sum(si_sequence),BIG_NUM)
    #Part 3: Finding R
    r=random.randint(2,q-1)
    while not math.gcd(r,q) == 1:
        r=random.randint(2,q-1)
    return (w,q,r)


# Arguments: tuple (W, Q, R) - W a length-n tuple of integers, Q and R both integers
# Returns: tuple B - a length-n tuple of integers
def create_public_key(private_key):
    b=[]
    (w,q,r)=private_key
    for i in range(len(w)):
        b.append(r*w[i] % q)
    return tuple(b)

# Argument: tuple of integers
# Returns: an integer equal to the tuple as a base 2 integer
def bits_to_byte(n_tuple):
    n=len(n_tuple)
    sum=0
    for i in range(n):
        sum+=n_tuple[i]*2**(n-i-1)
    return sum

# Argument: an integer between 0 and 255 inclusive
# Returns: a tuple equal to the integer in base 2
def byte_to_bits(byte, n=8):
    base_2=bin(byte)[2:]
    n_tuple=[0 for i in range(n-len(base_2))]
    for i in base_2:
        n_tuple.append(int(i))
    return tuple(n_tuple)

# Arguments: string, tuple B - a length-n tuple of integers
# Returns: list of integers
def encrypt_mhkc(plaintext, public_key):
    c=[]
    for i in plaintext:
        small_c=0
        num_i=ord(i)
        i_tuple=byte_to_bits(num_i)
        for j in range(len(i_tuple)):
            small_c+=public_key[j]*i_tuple[j]
        c.append(small_c)
    return c

# Arguments: list of integers, tuple (W,Q,R)
# Returns: bytearray or str of plaintext
def decrypt_mhkc(ciphertext, private_key):
    (w,q,r)=private_key
    decrypt_msg=''
    for i in ciphertext:
        #Mod inverse
        r_inverse=sympy.numbers.igcdex(r,q)[0]%q
        new_i=i*r_inverse%q
        #Greedy algorithm
        working_i=new_i
        bits=[0 for i in range(len(w))]
        for j in range(len(w)-1,-1,-1):
            cand=working_i-w[j]
            if cand >= 0:
                working_i=cand
                bits[j]=1
        byte=bits_to_byte(tuple(bits))
        decrypt_msg+=chr(byte)
    return decrypt_msg



if __name__ == "__main__":
