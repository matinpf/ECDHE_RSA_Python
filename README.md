# Overview

The security protocols course was exiting in master. I did two programming homework for it course. One of them is the implementation of Ephemeral Elliptic-curve Diffie–Hellman with RSA Signature with python in the form of a class. ECDHE is a key agreement protocol that provides forward secrecy. In this project, I used P-192 curve, which is NIST Standard. In the following was explained function one by one.

"xgcd": calculate modular inverse using the extended euclidean algorithm.

"DoubleandAdd": for a multiple of a point that takes advantage of doubling and addition algorithm.

"gen_ECkeypair": in this function generate private and public key pair key, which the variable "d" is the private key, and "dpub" is the public key. as you know no one can extract "d" from "dpub". in fact, obtain "d" from "dpub" is a hard problem.


# Curve P-192
Implementing Elliptic-curve Based on Curve P-19,NIST FIPS 186-4 Standard


        p=6277101735386680763835789423207666416083908700390324961279
        b=2455155546008943817740293915197451784769108058161191238065
        gx=602046282375688656758213480587526111916698976636884684818
        gy=174050332293622031404857552280219410364023488927386650641
        ng=6277101735386680763835789423176059013767194773182842284081

# Notice
Implementing is RSA basic and not secure Against any attack.(not RSA-PSS)

SHA-1 is no longer considered as secure cryptographic hash function. Researchers now believe that finding a hash collision.
https://shattered.io/

# I use

For generation prime:

https://github.com/Inndy/python-rsa/blob/master/prime.py
