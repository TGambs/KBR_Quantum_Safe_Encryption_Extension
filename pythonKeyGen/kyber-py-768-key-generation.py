# must 'pip install kyber_py' before use
from kyber_py.ml_kem import ML_KEM_768
import base64

pk, sk = ML_KEM_768.keygen()

#print("Public:", pk)
#print("Private:", sk)

print("Public:", base64.b64encode(pk).decode())
print("")
print("Private:", base64.b64encode(sk).decode())
