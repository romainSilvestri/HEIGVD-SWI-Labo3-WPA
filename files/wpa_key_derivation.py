#!/usr/bin/env python
# -*- coding: utf-8 -*-

"""
Derive WPA keys from Passphrase and 4-way handshake info

Calcule un MIC d'authentification (le MIC pour la transmission de données
utilise l'algorithme Michael. Dans ce cas-ci, l'authentification, on utilise
sha-1 pour WPA2 ou MD5 pour WPA)
"""

__author__      = "Abraham Rubinstein"
__copyright__   = "Copyright 2017, HEIG-VD"
__license__ 	= "GPL"
__version__ 	= "1.0"
__email__ 		= "abraham.rubinstein@heig-vd.ch"
__status__ 		= "Prototype"

from scapy.all import *
from binascii import a2b_hex, b2a_hex
from pbkdf2_math import pbkdf2_hex
from numpy import array_split
from numpy import array

# Read capture file -- it contains beacon, authentication, association, handshake and data
wpa=rdpcap("wpa_handshake.cap") 

# Important parameters for key derivation - most of them can be obtained from the pcap file

passPhrase  = "actuelle"
A           = "Pairwise key expansion" #this string is used in the pseudo-random function

# Get the ssid from the 1st packet.
ssid        = wpa[0].info

# Get the mac address of the AP from the 1st packet sent. Format the result to be a string
APmac       = str(wpa[0].addr2).replace(':', '')

# Get the mac address of the client from the 4th packet sent. Format the result to be a string
Clientmac   = str(wpa[3].addr2).replace(':', '')

# The ANonce can be found in the 6th packet sent. The result must be formatted and a substring must be created so that only the ANonce is retrieved.
ANonce      = a2b_hex(str(wpa[5][Raw])[13:][:32].encode('hex'))

# The SNonce can be found in the 7th packet sent. The result must be formatted and a substring must be created so that only the SNonce is retrieved.
SNonce      = a2b_hex(str(wpa[6][Raw])[13:][:32].encode('hex'))

# The mic_to_test can be found in the 9th packet sent. The result must be formatted and a substring must be created so that only the mic_to_test is retrieved.
mic_to_test = a2b_hex(str(wpa[8][Raw])[77:][:-2].encode('hex'))

B           = min(APmac,Clientmac)+max(APmac,Clientmac)+min(ANonce,SNonce)+max(ANonce,SNonce) #used in pseudo-random function

# The 36 zeros at the end correspond to the original MIC that we "erased" from the payload. Replacing it by zeros.
data        = str(wpa[8].payload)[34:][:-18].encode('hex') + '0' * 36
#cf "Quelques détails importants" dans la donnée

print "\n\nValues used to derivate keys"
print "============================"
print "Passphrase: ",passPhrase,"\n"
print "SSID: ",ssid,"\n"
print "AP Mac: ",b2a_hex(APmac),"\n"
print "CLient Mac: ",b2a_hex(Clientmac),"\n"
print "AP Nonce: ",b2a_hex(ANonce),"\n"
print "Client Nonce: ",b2a_hex(SNonce),"\n"


def customPRF512(key,A,B):
    """
    This function calculates the key expansion from the 256 bit PMK to the 512 bit PTK
    """
    blen = 64
    i    = 0
    R    = ''
    while i<=((blen*8+159)/160):
        hmacsha1 = hmac.new(key,A+chr(0x00)+B+chr(i),hashlib.sha1)
        i+=1
        R = R+hmacsha1.digest()
    return R[:blen]

#calculate 4096 rounds to obtain the 256 bit (32 oct) PMK
pmk = pbkdf2_hex(passPhrase, ssid, 4096, 32)

#expand pmk to obtain PTK
ptk = customPRF512(a2b_hex(pmk),A,B)

#calculate MIC over EAPOL payload (Michael)- The ptk is, in fact, KCK|KEK|TK|MICK
mic = hmac.new(ptk[0:16],data,hashlib.sha1)

print "\nResults of the key expansion"
print "============================="
print "PMK:\t\t",pmk,"\n"
print "PTK:\t\t",b2a_hex(ptk),"\n"
print "KCK:\t\t",b2a_hex(ptk[0:16]),"\n"
print "KEK:\t\t",b2a_hex(ptk[16:32]),"\	n"
print "TK:\t\t",b2a_hex(ptk[32:48]),"\n"
print "MICK:\t\t",b2a_hex(ptk[48:64]),"\n"
print "MIC:\t\t",mic.hexdigest(),"\n"
