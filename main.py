import requests
import hmac
import hashlib
import time

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

url = "https://api.challenge.hennge.com/challenges/003"
headers = {
    "Content-Type": "application/json",
    "Authorization": f"Basic {userid}:{totp_password}"
}

print(headers["Authorization"])

payload = {
    "github_url": "https://gist.github.com/mdarshad1000/c9786286b951fae9e2c46a5590d4b02c",
    "contact_email": "mdarshad1000@gmail.com",
    "solution_language": "python"
}

response = requests.post(url, headers=headers, json=payload)
print(response.status_code)
