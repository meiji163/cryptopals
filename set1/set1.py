#!/usr/bin/python
from collections import Counter
import re
from base64 import b64decode

#English character frequencies
rel_freq = {'e':12.7, 't': 9.0, 'a': 8.1, 'o': 7.5, 'i': 7.0, 'n': 6.7, 's': 6.4, 'h': 6.1, 'r':6.0, 'd': 4.3, 'l': 4.0, 'c': 2.8, 'u': 2.6, 'm': 2.4, 'w': 2.4, 'f': 2.2, 'g': 2.0, 'y': 2.0, 'p': 1.9, 'b': 1.5, 'v': 1.0, 'k': 0.8, 'j': 0.2, 'x': 0.2, 'q': 0.1, 'z': 0.1}


def XOR(b1, b2):
    '''XOR two bytes objects''' 
    assert len(b1) == len(b2)
    bts = [bytes.fromhex(format(a^b, '02x')) for a,b in zip(b1, b2)]
    return b''.join(bts)

def freq_score( w):
    '''absolute difference between average English character frequency and character frequency of w'''
    score = 0
    for i in range(len(w)):
        if not (w[i].isalpha() or w[i] == " "):
            score += 50 
    a = re.sub('[^a-zA-Z]+', '', w)
    counts = Counter(a.lower())
    score += sum([abs(counts[k]//len(w) - rel_freq[k]) for k in counts ])
    return score

def decode_1chr_XOR(b):
    '''Decodes hex string that has been XORd with one-character key.'''
    L = {}
    for m in range(127):
        key = bytes.fromhex(format(m, '02x'))
        key *= len(b) 
        try:
            L[chr(m)] = XOR(b, key).decode('utf-8')
        except:
            continue
    if L:
        minkey = min(L, key = lambda k: freq_score(L[k]))
        return L[minkey] 

def encode_XOR(b, key):
    '''Encodes w with repeating XOR key '''
    k = key*(len(b)//len(key) +1)
    return XOR(b, k[:len(b)])

def hamming_dist(b1, b2):
    ans = 0
    for a, b in zip(b1, b2):
        c = a^b
        n_ones = 0
        while c > 0:
            n_ones += c & 1
            c = c>>1
        ans += n_ones
    return ans

def decode_XOR(b):
    '''Decode repeating key XOR with top three keysizes'''
    k = sorted(range(1,42), key = lambda keysize: (hamming_dist(b[2*keysize:3*keysize],b[3*keysize:4*keysize]))/keysize) 
    msgs = []  
    for keysize in k[:3]:
        L= [decode_1chr_XOR(b[j::keysize]) for j in range(keysize)]
        msg = ""
        for l in zip(*L):
            msg += ''.join(l)
        msgs.append(msg)
    return msgs

if __name__ == '__main__':
    #Challenge 3
    #s = bytes.fromhex('1b37373331363f78151b7f2b783431333d78397828372d363c78373e783a393b3736')
    #print(decode_1chr_XOR(s))
    
    #Challenge 4
    #with open('4.txt','r') as f:
    #    for e in f.readlines():
    #        msg = decode_1chr_XOR(bytes.fromhex(e))
    #        if msg:
    #            print(msg)

    #Challenge 5
    #msg = b"Burning 'em, if you ain't quick and nimble\nI go crazy when I hear a cymbal"
    #print(encode_XOR(msg,b'ICE').hex())

    #Challenge 6
    #with open('6.txt') as f:
    #    l = f.read().replace('\n','')
    #e = b64decode(l) 
    #print(decode_XOR(e))



