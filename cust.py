import phe as paillier
import json

def storeKeys():
    public_key, private_key = paillier.generate_paillier_keypair()
    keys = {
        'public_key': {'n': public_key.n},
        'private_key': {'p': private_key.p, 'q': private_key.q}
    }
    with open('custkeys.json', 'w') as file:
        json.dump(keys, file)
#storeKeys()
def getKeys():
    with open('custkeys.json', 'r') as file:
        keys = json.load(file)
        pub_key = paillier.PaillierPublicKey(n=int(keys['public_key']['n']))
        priv_key = paillier.PaillierPrivateKey(pub_key, int(keys['private_key']['p']), int(keys['private_key']['q']))
        return pub_key, priv_key

def serializeData(public_key, data):
    encrypted_data_list = [public_key.encrypt(x) for x in data]
    encrypted_data = {
        'public_key': {'n': public_key.n},
        'values': [(str(x.ciphertext()), x.exponent) for x in encrypted_data_list]
    }
    serialized = json.dumps(encrypted_data)
    return serialized

def loadAnswer():
    with open('answer.json', 'r') as file:
        ans = json.load(file)
    answer = json.loads(ans)
    return answer

try:
    pub_key, priv_key = getKeys()
except:
    storeKeys()
    pub_key, priv_key = getKeys()

data = [47,5,2,1]
print("Original Data:", data)

datafile = serializeData(pub_key, data)
with open('data.json', 'w') as file:
    json.dump(datafile, file)
print("Encrypted Data:", datafile)

answer_file = loadAnswer()
answer_key = paillier.PaillierPublicKey(n=int(answer_file['pubkey']['n']))
answer = paillier.EncryptedNumber(answer_key, int(answer_file['values'][0]), int(answer_file['values'][1]))
print("Public Key:", pub_key.n)
print("Private Key (p):", priv_key.p)
print("Private Key (q):", priv_key.q)

if answer_key == pub_key:
    decrypted_answer = priv_key.decrypt(answer)
    print("Decrypted Answer:", decrypted_answer)

