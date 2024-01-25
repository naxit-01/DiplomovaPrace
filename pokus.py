from modules import jwt, DILITHIUM

alg= DILITHIUM()

pk, sk = alg.generate_keypair()

payload = {"data":"data"}
jwtm= jwt.encode(payload, sk, "DILITHIUM")
print(jwt.decode(jwtm, pk))