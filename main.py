import requests
import hmac
import hashlib
import time
import base64

def generate_totp(secret_key):
    interval = int(time.time()) // 30  # TOTP Time Step X is 30 seconds
    counter = interval.to_bytes(8, byteorder='big')
    hmac_sha512 = hmac.new(secret_key, counter, hashlib.sha512).digest()
    offset = hmac_sha512[-1] & 0x0F
    truncated_hash = hmac_sha512[offset:offset + 4]
    otp = int.from_bytes(truncated_hash, byteorder='big') & 0x7FFFFFFF
    return str(otp).zfill(10)

userid = "mdarshad1000@gmail.com"
shared_secret = (userid + "HENNGECHALLENGE003").encode('utf-8')
totp_password = generate_totp(shared_secret)

auth_string = f"{userid}:{totp_password}"
base64_auth_string = base64.b64encode(auth_string.encode('utf-8')).decode('utf-8')

url = "https://api.challenge.hennge.com/challenges/003"
headers = {
    "Content-Type": "application/json",
    "Authorization": f"Basic {base64_auth_string}"
}

payload = {
    "github_url": "https://gist.github.com/mdarshad1000/c9786286b951fae9e2c46a5590d4b02c",
    "contact_email": "mdarshad1000@gmail.com",
    "solution_language": "python"
}

response = requests.post(url, headers=headers, json=payload)
print(response.text)
