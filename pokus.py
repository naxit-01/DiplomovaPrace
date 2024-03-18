from modules.signatures import SPHINCSPlus

prom = "pyspx.shake_128s"
sign_alg = SPHINCSPlus
sk, pk = sign_alg.generate_keypair()
print("wnd")
