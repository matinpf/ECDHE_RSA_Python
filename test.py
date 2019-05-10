# -*- coding: utf-8 -*-
"""
Created on Thu May  9 15:03:13 2019

@author: ahora
"""
from ECDHE_RSA import ECDHE_RSA
#import abade2


matin = ECDHE_RSA("matin")
print(matin.baby(23,matin.gx,matin.gy))
mohamad = ECDHE_RSA("mohamad")

#matin key genaration
ma_rsa_private,ma_rsa_public,ma_rsa_n=matin.rsakeygenarate()
ma_d,ma_dpub=matin.gen_ECkeypair()

#mohamad key genaration
mo_rsa_private,mo_rsa_public,mo_rsa_n=mohamad.rsakeygenarate()
mo_d,mo_dpub=mohamad.gen_ECkeypair()

#matin sign public EC parametr
ma_dpub_hash=matin.hash_info(str(ma_dpub[0]),str(ma_dpub[1]))
ma_sing_dpub=matin.ras_sign(ma_dpub_hash,ma_rsa_private,ma_rsa_n)

#mohamad sign public EC parametr
mo_dpub_hash=mohamad.hash_info(str(mo_dpub[0]),str(mo_dpub[1]))
mo_sing_dpub=mohamad.ras_sign(mo_dpub_hash,mo_rsa_private,mo_rsa_n)

#matin send ma_rsa_public,ma_rsa_n(CA sign),ma_dpub,ma_sing_dpub to mohahmad
#mohahmad send mo_rsa_public,mo_rsa_n(CA sign),mo_dpub,mo_sing_dpub to matin

#matin verify rsa_sign
mo_dpub_hash_recive=matin.hash_info(str(mo_dpub[0]),str(mo_dpub[1]))
sign_result_matin=matin.rsa_verification(mo_sing_dpub,mo_rsa_public,mo_rsa_n,mo_dpub_hash_recive)
print("matin verify rsa_sign:")
print(sign_result_matin)
#matin Generation sharekey
matin_sharekey=matin.gen_ECkeyAg(mo_dpub,ma_d)


#mohamad verify rsa_sign
ma_dpub_hash_recive=matin.hash_info(str(ma_dpub[0]),str(ma_dpub[1]))
#for test ma_sing_dpub+1
sign_result_mohahmad=matin.rsa_verification(ma_sing_dpub,ma_rsa_public,ma_rsa_n,ma_dpub_hash_recive)
print("mohamad verify rsa_sign:")
print(sign_result_mohahmad)
#mohamad Generation sharekey
#for test mo_d+1
mohamad_sharekey=mohamad.gen_ECkeyAg(ma_dpub,mo_d)


print("matin share key:")
print(matin_sharekey)
print("mohahmad share key:")
print(mohamad_sharekey)
