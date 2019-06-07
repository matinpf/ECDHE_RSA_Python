# -*- coding: utf-8 -*-
"""
Created on Wed May  8 12:39:28 2019

@author: Matin Fallahi
"""
#safe randome
import secrets
import prime
import hashlib
#import sys
#import numpy
#import time
#Curve P-19,NIST FIPS 186-4 Standard
class ECDHE_RSA:
    def __init__(self, name):
        self.name = name
        #y^2=x^3-3x+b
        self.p=6277101735386680763835789423207666416083908700390324961279
        self.b=2455155546008943817740293915197451784769108058161191238065
        self.gx=602046282375688656758213480587526111916698976636884684818
        self.gy=174050332293622031404857552280219410364023488927386650641
        self.ng=6277101735386680763835789423176059013767194773182842284081

     #Euler invers
#    def invers(self,x):
#        if x % self.p == 0:
#            raise ZeroDivisionError("Impossible inverse")
#        return pow(x, self.p-2, self.p)
    
    #standard
#    def xgcd2(self,a, b):
#        x0, x1, y0, y1 = 0, 1, 1, 0
#        while a != 0:
#            q, b, a = b // a, a, b % a
#            y0, y1 = y1, y0 - q * y1
#            x0, x1 = x1, x0 - q * x1
#        return b, x0, y0
    
    #test wiht https://www.dcode.fr/modular-inverse
    def xgcd(self,a, b):
        b0 , b1=0 , 1
        if a<b:
            a , b= b, a
        while b != 0:
            q , a , b = a // b , b , a%b
            b0 ,b1=b1 ,b0-(q*b1)
        return(a,2,b0)

    #TO DO : check is point O?
    def double(self,x1,y1):
        inv=self.xgcd((2*y1)%self.p,self.p)[2]
        if inv<0 :
            inv=inv+self.p
        s=((3 * (x1**2))-3) * inv
        x3=((s**2)-(2*x1))%self.p
        y3=(s*(x1-x3)-y1)%self.p
        return(x3,y3)
        
    def addition(self,x1,y1,x2,y2):
        inv=self.xgcd((x2 - x1)%self.p,self.p)[2]
        if inv<0 :
            inv=inv+self.p
        s = (y2 - y1) * inv
        x3 = (s**2 - x1 - x2) % self.p
        y3 = (s * (x1 - x3) - y1) % self.p
        #print(x3,y3)
        return(x3,y3)
    

    # test with http://www.christelbach.com/ECCalculator.aspx
    def DoubleandAdd(self,d,gx1,gy1):
        d=bin(d)
        bx1=gx1
        by2=gy1
        le=len(d)-2
        for i in range(1,le):
            (bx1,by2)=self.double(bx1,by2)
            
            if d[i+2]=='1' :
                (bx1,by2)=self.addition(bx1,by2,gx1,gy1)  
        return(bx1,by2)
        

    def gen_ECkeypair(self):
        d=0
        while d==0:
            d=secrets.randbelow(self.ng)
        
        dpub=self.DoubleandAdd(d,self.gx,self.gy)
        return d,dpub 
    
    def gen_ECkeyAg(self,bpub,d):
        key=self.DoubleandAdd(d,bpub[0],bpub[1])
        return key
        
        
        
    def gen_pq(self,bits):
        """
        generate keypair (pr, qr)
        """
        assert bits >= 512, 'key length must be at least 512 bits'
        l = bits >> 1
        while True:
            pr = prime.randprime_bits(l)
            if prime.is_probable_prime(pr, None, l // 8):
                break
        while True:
            qr = prime.randprime_bits(bits - l)
            if pr != qr and prime.is_probable_prime(qr, None, l // 8):
                break
        return qr,pr

    
    def power_mod(self,m,r,n):
        M=0
        l=[m]
        flagodd=0
        if(r%2==1):
            r=r-1
            flagodd=1
        M=m
        i=1
        while((r//2)>=i):
            i=i+i
            M=(M*M)%n
            l.append(M)
        j=len(l)-1
        while(1):
            if i==r :
                break
            if(r>=i+2**(j)):
                i=(i)+2**(j)
                M=(M*(l[j]))%n
            j=j-1    
        if(flagodd==1):
            M=(M*m)%n 
        return M    
    #test rsa powr_mod https://www.dcode.fr/modular-exponentiation#q2
    #TO DO 
    def rsakeygenarate(self):
        #test with https://www.dcode.fr/primality-test
        #qr , pr =gen_pq(1024)
        #!!!!!!!!! slow speed for prime 2048 - use defult prime or other algorithms
        qr , pr =self.gen_pq(1024)
        n=qr*pr
        phy=(qr-1)*(pr-1)
        while True:
            er=secrets.randbelow(phy)
            xgcdr=self.xgcd(phy,er)
            if(er!=1 and er!=0 and xgcdr[0]==1):
                break
        dr=xgcdr[2]
        if dr<0 :
            dr=dr+phy
        return (dr,er,n)
    
      
    
    def ras_sign(self,m,dr,n):
        M=self.power_mod(m,dr,n)
        return M
        
    def rsa_verification(self,m,er,n,h):
        M=self.power_mod(m,er,n)
        if(M==h):
            return True
        else :
            return False
        
    def hash_info(self,m1,m2):
        m = hashlib.sha1()
        m.update(str.encode(m1))
        m.update(str.encode(m2))
        M=int(m.hexdigest(),16)
        return M
    
    #check point in curve ?
    #dont use windows calculator !! test with https://defuse.ca/big-number-calculator.htm
    def in_Curve(self,gx1,gy1):
        x=((gx1**3)-(3*gx1)+self.b)%self.p
        y=(gy1**2)%self.p
        #print(x,y)
        #print(gx1,gy1)
        if x==y :
            return True
        else :
            return False
