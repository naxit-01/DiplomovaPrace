from kyber import Kyber512
pk, sk = Kyber512.keygen() #generuje privatni s shared klice
c, key = Kyber512.enc(pk) 
_key = Kyber512.dec(c,sk)

print(key,"\n",_key)
assert key == _key

print("end")