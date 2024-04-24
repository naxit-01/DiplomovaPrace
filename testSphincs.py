message = "the message"

import modules.signatures as signatures

signalg = signatures.SPHINCS_Tottifi()

pk, sk = signalg.generate_keypair()
signature = signalg.sign(sk,message)
if signalg.verify(pk,message,signature):
    print("true")