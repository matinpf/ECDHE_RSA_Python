# -*- coding: utf-8 -*-
"""
Created on Wed May  8 12:39:28 2019

@author: Matin fallahi
"""
#safe randome
import secrets
import prime
import hashlib
import sys
import numpy
import time
class ECDHE_RSA:
    def __init__(self, name):
        self.name = name
        self.p=6277101735386680763835789423207666416083908700390324961279
        self.b=2455155546008943817740293915197451784769108058161191238065
        self.gx=602046282375688656758213480587526111916698976636884684818
        self.gy=174050332293622031404857552280219410364023488927386650641
        self.ng=6277101735386680763835789423176059013767194773182842284081


  
    #x=(gx**3-(3*gx)+b)%p
    #y=(gy**2)%p
    #print(x,y)
    
#    def invers(self,x):
#        if x % self.p == 0:
#            raise ZeroDivisionError("Impossible inverse")
#        return pow(x, self.p-2, self.p)
    
    #test wiht https://www.dcode.fr/modular-inverse
    def xgcd(self,a, b):
        x0, x1, y0, y1 = 0, 1, 1, 0
        while a != 0:
            q, b, a = b // a, a, b % a
            y0, y1 = y1, y0 - q * y1
            x0, x1 = x1, x0 - q * x1
        return b, x0, y0
    
    #print(invers(150))
    #print(xgcd(16,3))
    
    def double(self,x1,y1):
        inv=self.xgcd(self.p,2*y1)[2]
        if inv<0 :
            inv=inv+self.p
        s=((3 * (x1**2))-3) * inv
        x3=((s**2)-(2*x1))%self.p
        y3=(s*(x1-x3)-y1)%self.p
        #print(x3,y3)
        return(x3,y3)
        
    def addition(self,x1,y1,x2,y2):
        inv=self.xgcd(self.p,x2 - x1)[2]
        if inv<0 :
            inv=inv+self.p
        s = (y2 - y1) * inv
        x3 = (s**2 - x1 - x2) % self.p
        y3 = (s * (x1 - x3) - y1) % self.p
        #print(x3,y3)
        return(x3,y3)
    
    #d=double(gx,gy)  
    #print("1")  
    #addition(gx,gy,d[0],d[1])
    
    # test with http://www.christelbach.com/ECCalculator.aspx
    def baby(self,d,gx1,gy1):
        #print(d,gx1,gy1)
        d=bin(d)
        bx1=gx1
        by2=gy1
        le=len(d)-2
        #print(d,le)
        for i in range(1,le):
            (bx1,by2)=self.double(bx1,by2)
            #print(d[i+2],le,i)
            #print(bx1,by2)
            if d[i+2]=='1' :
                #print("ok")
                (bx1,by2)=self.addition(bx1,by2,gx1,gy1)  
        return(bx1,by2)
        
    #print("2")
    #to do : check d not 0
    #d=secrets.randbelow(n-1)
    #b=baby(23,self.gx,self.gy)
    #print(b)
    #end of dp
    def gen_ECkeypair(self):
        d=secrets.randbelow(self.ng-1)
        dpub=self.baby(d,self.gx,self.gy)
        return d,dpub 
    
    def gen_ECkeyAg(self,bpub,d):
        key=self.baby(d,bpub[0],bpub[1])
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
    
    
    #def power_mod2(m,r):
    #    #p=13
    #    #start = time.time()
    #    M=0
    #    l=[m]
    #    flagodd=0
    #    if(r%2==1):
    #        r=r-1
    #        flagodd=1
    #    M=m
    #    i=1
    #    while((r//2)>=i):
    #        i=i+i
    #        M=(M*M)%p
    #        l.append(M)
    #        
    #    j=len(l)-1
    #    maxl=len(l)-1
    #    print("step1",j)
    #    #end = time.time()
    #    #print(end - start)
    #    while(1):
    #        if i==r :
    #            break
    #        if(r>=i+2**(j)):
    #            i=(i)+2**(j)
    #            M=M*(l[j])
    #            maxl=j
    #        j=j-1    
    #        if j==0 :
    #            j=maxl-1
    #    if(flagodd==1):
    #        M=(M*m)%p
    #    #end = time.time()
    #    #print(end - start)   
    #    return M
    #
    #def power_mod3(m,r):
    #    #p=13
    #    #start = time.time()
    #    M=0
    #    l=[m]
    #    flagodd=0
    #    if(r%2==1):
    #        r=r-1
    #        flagodd=1
    #    M=m
    #    i=1
    #    while((r//2)>=i):
    #        i=i+i
    #        M=(M*M)%p
    #        l.append(M)
    #        
    #    j=len(l)-1
    #    maxl=len(l)-1
    #    print("step1",j)
    #    #end = time.time()
    #    #print(end - start)
    #    while(1):
    #        if i==r :
    #            break
    #        
    #        if i+2**((31*j)//32)>=r :
    #            print(j);
    #            j=(31*j)//32     
    #            if i+2**((15*j)//16)>=r :
    #                #print(j);
    #                j=(15*j)//16         
    #                if i+2**((7*j)//8)>=r :
    #                    #print(j);
    #                    j=(7*j)//8       
    #                    if i+2**((3*j)//4)>=r :
    #                        #print(j);
    #                        j=(3*j)//4
    #                        if i+2**(j//2)>=r :
    #                            j=j//2
    #                            if i+2**(j//4)>=r :
    #                                j=j//4   
    #        if(r>=i+2**(j)):
    #            i=(i)+2**(j)
    #            M=M*(l[j])
    #            maxl=j
    #        j=j-1    
    #        if j==0 :
    #            j=maxl-1
    #    if(flagodd==1):
    #        M=(M*m)%p
    #    #end = time.time()
    #    #print(end - start)   
    #    return M
    
    def power_mod(self,m,r,n):
        #p=13
        #start = time.time()
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
        maxl=len(l)-1
        #print("step1",j)
        #end = time.time()
        #print(end - start)
        while(1):
            if i==r :
                break
      
            if(r>=i+2**(j)):
                i=(i)+2**(j)
                M=(M*(l[j]))%n
                maxl=j
            j=j-1    
            if j==0 :
                #print("again")
                j=maxl-1
        if(flagodd==1):
            M=(M*m)%n
        #end = time.time()
        #print(end - start)   
        return M    
    #test rsa powr_mod https://www.dcode.fr/modular-exponentiation#q2
    #g=gen_pq(3072)
    #print(g[0])    
    #print(power_mod(5466,g[0]))    
    #print(power_mod(1027514271589238825201585096476230672035639689874,202310137587330266277784474674228073870890145090451765124773492194783417199320119815669958352439856885379190193921407776522590845235409773707773532763425961617199665946368265869456315381808669025898011820619906788308608456900269986029938085731187157441856883205214062742099539358253517108932711056331300251621))
    
    def rsakeygenarate(self):
        #test with https://www.dcode.fr/primality-test
        #qr , pr =gen_pq(1024)
        #!!!!!!!!! slow speed for prime 2048 - use defult prime or other algorithms
        qr , pr =self.gen_pq(1024)
        n=qr*pr
        phy=(qr-1)*(pr-1)
        while True:
            er=secrets.randbelow(phy-1)
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
    
    #print(hash_info(bytes("matin", 'utf-8')))
    #m= public hsdh(prametr EC)   
    #def rsaA(m):
    #    #test with https://www.dcode.fr/primality-test
    #    #qr , pr =gen_pq(1024)
    #    #!!!!!!!!! slow speed
    #    qr , pr =gen_pq(1024)
    #    n=qr*pr
    #    phy=(qr-1)*(pr-1)
    #    while True:
    #        er=secrets.randbelow(phy-1)
    #        xgcdr=xgcd(phy,er)
    #        if(er!=1 and er!=0 and xgcdr[0]==1):
    #            brea
    #    dr=xgcdr[2]
    #    if dr<0 :
    #        dr=dr+phy
    #    #print(er,phy,xgcdr)
    #    print(m,dr,er)
    #    M=power_mod(m,dr,n)
    #    M=power_mod(M,er,n)
    #    #print(xgcdr)
    #    return M
        
    #print(rsaA(1027514271589238825201585096476230672035639689875))
        
    
