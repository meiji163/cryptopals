#!/usr/bin/python3
from collections import Counter
import re
import base64

#English character frequencies
rel_freq = {'e':12.7, 't': 9.0, 'a': 8.1, 'o': 7.5, 'i': 7.0, 'n': 6.7, 's': 6.4, 'h': 6.1, 'r':6.0, 'd': 4.3, 'l': 4.0, 'c': 2.8, 'u': 2.6, 'm': 2.4, 'w': 2.4, 'f': 2.2, 'g': 2.0, 'y': 2.0, 'p': 1.9, 'b': 1.5, 'v': 1.0, 'k': 0.8, 'j': 0.2, 'x': 0.2, 'q': 0.1, 'z': 0.1}

def hex_to_b64( n: str):
    '''converts hex string to base 64 string'''
    e = n.encode('ascii')
    msg = base64.b16decode(e)
    return base64.b64encode(msg).decode('ascii')

def b64_to_hex( n: str ):
    '''converts base 64 string to hex string'''
    e = n.encode('ascii')
    msg = base64.b64decode(e)
    return base64.b16encode(msg).decode('ascii')

def XOR( n: str , m: str):
    '''Takes two hex strings n and m and returns XOR'''
    return format(int(n, 16)^int(m, 16), 'x')

def freq_score( w: str ):
    '''absolute difference between average English character frequency and character frequency of w'''
    score = 0
    for i in range(len(w)):
        if not (w[i].isalpha() or w[i] == " "):
            score += 50 
    a = re.sub('[^a-zA-Z]+', '', w)
    counts = Counter(a.lower())
    score += sum([abs(counts[k]//len(w) - rel_freq[k]) for k in counts ])
    return score

def decode_1char_XOR( n : str ):
    '''Decodes hex string that has been XORd with one-character key.
    Returns None if no decoding is found'''
    L = {}
    for m in range(0, 127):
        key = format(m, 'x')
        key = key*(len(n)//len(key))
        try:
            L[chr(m)] = bytearray.fromhex(XOR(n, key)).decode()
        except:
            continue
    if L == {}:
        return
    minkey = min(L, key = lambda k: freq_score(L[k]))
    return L[minkey] 

def encode_XOR( w: str, key : str ):
    '''Encodes w with repeating XOR key and returns a hex string'''
    e = w.encode('ascii').hex()
    key *= len(w)//len(key) +1
    k = key[:len(w)].encode('ascii').hex()
    return XOR(e, k)

def hamming_dist(n: str, m: str):
    a = bin(int.from_bytes(n.encode(), 'big'))
    b = bin(int.from_bytes(m.encode(), 'big'))
    d = format(int(a, 2)^int(b, 2), 'b')
    return sum([int(i) for i in d])

def decode_XOR(w: str):
    k = sorted(range(2,42), key = lambda keysize: (hamming_dist(w[:keysize],w[keysize:2*keysize]))/keysize) 
    keysize = k[0]
    L=[]
    for j in range(keysize,2):
        block = ""
        for a,b in zip(w[j::keysize], w[j+1::keysize]):
            block += a + b
        L.append(decode_1char_XOR(block))
    print(L)
    print(f"keysize = {keysize}")

if __name__ == '__main__':
    #Challenge 3
    #s = '1b37373331363f78151b7f2b783431333d78397828372d363c78373e783a393b3736'
    #print(decode_1char_XOR(s))
    
    #Challenge 4
    #with open('4.txt','r') as f:
    #    for msg in f.readlines():
    #        if decode_1char_XOR(msg) != None:
    #            print(decode_1char_XOR(msg))

    #Challenge 5
    #msg = "Burning 'em, if you ain't quick and nimble\nI go crazy when I hear a cymbal"
    #print(encode_XOR(msg,'ICE'))

    with open('6.txt') as f:
        l = f.read()
        l = re.sub('\n','',l)
    w = b64_to_hex(l) 
    decode_XOR(w)
