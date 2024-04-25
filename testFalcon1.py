from modules.signAlgLib import Falcon_official
signAlg=Falcon_official()
#signAlg.test()
pk, sk = signAlg.generate_keypair()
signature = signAlg.sign(sk,"Hello")
if signAlg.verify(pk,"Hello", signature):
    print("TRUE")