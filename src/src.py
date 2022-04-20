import os, uuid, string, time, random, signal, threading, subprocess, json
clear = lambda: subprocess.call('cls||clear', shell=True)
os.system("python.exe -m pip install pysocks")
try:
    import requests
except ImportError:
    os.system("pip install requests")
    import requests
try:
    import colorama
except ImportError:
    os.system("pip install colorama")
    import colorama
try:
    import autopy
except ImportError:
    os.system("pip install autopy")
    import autopy
colorama.init()
class THRIDING():
    def __init__(self, target, target2):
        self.threads_list = []
        self.target = target
        self.target2 = target2
    def gen(self, threads):
        if self.target2!="":
            t = threading.Thread(target=self.target2)
            t.setDaemon(True)
            self.threads_list.append(t)
        for i in range(threads):
            t = threading.Thread(target=self.target)
            t.setDaemon(True)
            self.threads_list.append(t)

    def start(self):
        for thread_start in self.threads_list:
            thread_start.start()

    def join(self):
        for thread_join in self.threads_list:
            thread_join.join()
class DESIGN():
    WHITE = '\x1b[1;37;40m'
    YELLOW = '\x1b[1;33;40m'
    RED = '\x1b[1;31;40m'
    BLUE = '\x1b[36m\x1b[40m'
    GREEN = '\x1b[32m\x1b[40m'
    greenplus = f"{WHITE}( {GREEN}+ {WHITE})"
    blueplus = f"{WHITE}( {BLUE}+ {WHITE})"
    redminus = f"{WHITE}( {RED}- {WHITE})"
    blueproxies = f"{WHITE}( {BLUE}PROXIES {WHITE})"
    redproxies = f"{WHITE}( {RED}PROXIES {WHITE})"
    blueaccounts = f"{WHITE}( {BLUE}ACCOUNTS {WHITE})"
    redaccounts = f"{WHITE}( {RED}ACCOUNTS {WHITE})"
    bluezero = f"{WHITE}( {BLUE}0 {WHITE})"
    blueone = f"{WHITE}( {BLUE}1 {WHITE})"
    bluetwo = f"{WHITE}( {BLUE}2 {WHITE})"
    bluethree = f"{WHITE}( {BLUE}3 {WHITE})"
    xrblue = f"\n{blueplus} 14D Bypass {BLUE}/ {WHITE}Instagram{BLUE}: {WHITE}@xnce {BLUE}/ {WHITE}@ro1c"
    xrblue2 = f"\n{blueplus} Auto Claimer {BLUE}/ {WHITE}Instagram{BLUE}: {WHITE}@xnce {BLUE}/ {WHITE}@ro1c"
class SETTINGS():
    def __init__(self):
        print(f"\n{DESIGN.bluezero} New Settings {DESIGN.blueone} Load Settings: ", end="")
        self.settingsmode = input()
        if self.settingsmode=="1":
            self.open_settings()
        else:
            if not any(x==self.settingsmode for x in ["0", "1"]):
                print(f'\n{DESIGN.redminus} ["0", "1"]')
                print(f"\n{DESIGN.redminus} Enter To Exit: ", end="")
                input()
                exit()
    def open_settings(self):
        try:
            settings = json.loads(open("settings.txt", "r").read())
            try:
                self.tmode = settings["settings"]["tool_mode"]
                self.proxymode = settings["settings"]["proxy_mode"]
                self.loginmode = settings["settings"]["login_mode"]
                self.login_api = settings["settings"]["login_api"]
            except Exception as err:
                print(f"{DESIGN.redminus} Something Is Worng On Your Settings ({err})")
                self.settingsmode = "0"
        except Exception as err:
            print(err)
            print(f"\n{DESIGN.redminus} {DESIGN.RED}settings.txt {DESIGN.WHITE}is missing")
            self.settingsmode = "0"
accounts = []
proxies = []
class FILES():
    def __init__(self, filename, my_list):
        self.open_file(filename, my_list)
    def open_file(self, filename, my_list):
        try:
            for x in open(f"{filename}.txt", "r").read().split("\n"):
                if x!="":
                    my_list.append(x)
            print(f"\n{DESIGN.blueplus} Successfully Load {DESIGN.BLUE}{filename}.txt")
            time.sleep(2)
        except Exception as err:
            print(err)
            print(f"\n{DESIGN.redminus} {DESIGN.RED}{filename}.txt {DESIGN.WHITE}is missing ", end="")
            input()
            exit()
class XNCE():
    def __init__(self, mode):
        self.done, self.error, self.set, self.next_check, self.run, self.username_changed = 0, 0, 0, 10, True, False
        self.sessions = []
        self.users = []
        self.loginuuid = str(uuid.uuid4())
        self.reqs = requests.Session()
        if mode=="0":
            if s.settingsmode == "0":
                print(f"\n{DESIGN.blueone} Grab Proxies {DESIGN.bluetwo} Load Proxies: ", end="")
                self.promode = input()
            else:
                self.promode = s.proxymode
            if self.promode=="1":
                self.grab_proxies()
            elif self.promode=="2":
                FILES("proxies", proxies)
            else:
                print(f"\n{DESIGN.redminus} ['0', '1']")
                self.inex()
            if s.settingsmode=="0":
                print(f"\n{DESIGN.blueone} Normal Login {DESIGN.bluetwo} Sessionid: ", end="")
                self.logmode = input()
            else:
                self.logmode = s.loginmode
            if self.logmode=="1":
                print(f"\n{DESIGN.blueplus} username: ", end="")
                self.username = input()
                print(f"\n{DESIGN.blueplus} password: ", end="")
                self.password = input()
                if s.settingsmode=="0":
                    print(f"\n{DESIGN.blueone} Api Login {DESIGN.bluetwo} Web Login: ", end="")
                    self.api_mode = input()
                else:
                    self.api_mode = s.login_api
                for x in range(2):
                    if self.api_mode=="1":
                        self.api_login()
                    elif self.api_mode=="2":
                        self.web_login()
                    else:
                        print(f"\n{DESIGN.redminus} ['0', '1']")
                        self.inex()
            elif self.logmode=="2":
                print(f"\n{DESIGN.blueplus} You Need Two {DESIGN.RED}Different Api Sessions {DESIGN.WHITE}For The {DESIGN.RED}Same Account")
                print(f"\n{DESIGN.blueplus} sessionid1: ", end="")
                sessionid1 = input()
                if sessionid1=="":
                    print(f"\n{DESIGN.redminus} This Field Is Required")
                    self.inex()
                print(f"\n{DESIGN.blueplus} sessionid2: ", end="")
                sessionid2 = input()
                if sessionid2=="":
                    print(f"\n{DESIGN.redminus} This Field Is Required")
                    self.inex()
                if sessionid1==sessionid2:
                    print(f"\n{DESIGN.redminus} You Need Two {DESIGN.RED}Different Api Sessions {DESIGN.WHITE}For The {DESIGN.RED}Same Account")
                    self.inex()
                self.sessions = [sessionid1, sessionid2]
                self.check_sessions()
            else:
                print(f"\n{DESIGN.redminus} ['0', '1']")
                self.inex()
            self.current_user()
            self.new_username = "xnce" + "".join(random.choices(string.ascii_lowercase+string.digits, k=10))
            open(f"{self.username}.txt", "a").write(f"\n{self.new_username}\n{self.sessions[0]}\n{self.sessions[1]}")
        elif mode=="2":
            if s.settingsmode=="0":
                print(f"\n{DESIGN.blueone} Grab Proxies {DESIGN.bluetwo} Load Proxies: ", end="")
                self.promode = input()
            else: 
                self.promode = s.proxymode
            if self.promode=="1":
                self.grab_proxies()
            elif self.promode=="2":
                FILES("proxies", proxies)
            else:
                print(f"\n{DESIGN.redminus} ['0', '1']")
                self.inex()
            if s.settingsmode=="0":
                print(f"\n{DESIGN.blueone} Normal Login {DESIGN.bluetwo} Sessionid: ", end="")
                self.logmode = input()
            else:
                self.logmode = s.loginmode
            if self.logmode=="1":
                print(f"\n{DESIGN.blueplus} username: ", end="")
                self.username = input()
                print(f"\n{DESIGN.blueplus} password: ", end="")
                self.password = input()
                if s.settingsmode=="0":
                    print(f"\n{DESIGN.blueone} Api Login {DESIGN.bluetwo} Web Login: ", end="")
                    self.api_mode = input()
                else:
                    self.api_mode = s.login_api
                if self.api_mode=="1":
                    self.api_login()
                elif self.api_mode=="2":
                    self.web_login()
                else:
                    print(f"\n{DESIGN.redminus} ['0', '1']")
                    self.inex()
            elif self.logmode=="2":
                print(f"\n{DESIGN.blueplus} sessionid: ", end="")
                sessionid = input()
                self.sessions.append(sessionid)
                self.check_sessions()
            self.current_user()
            open(f"{self.username}.txt", "a").write(f"\n{self.sessions[0]}")
        if s.settingsmode=="0":
            try:
                if self.logmode=="2":
                    self.api_mode = "1"
                open("settings.txt", "w").write('{"settings": {\n\t"tool_mode": "%s",\n\t"proxy_mode": "%s",\n\t"login_mode": "%s",\n\t"login_api": "%s"\n}}'%(tmode, self.promode, self.logmode, self.api_mode))
            except Exception as err: 
                print(f"{DESIGN.redminus} {err}")
                self.inex()
    def inex(self):
        self.run = False
        print(f"\n{DESIGN.redminus} Enter To Exit: ", end="")
        input()
        os.kill(os.getpid(), signal.SIGTERM)
    def grab_proxies(self):
        req = requests.get("https://api.proxyscrape.com/v2/?request=getproxies&protocol=socks4&timeout=10000&country=all&ssl=all&anonymity=all")
        #print(req.text, req.status_code)
        if req.status_code==200:
            open("proxies.txt", "w").write(f"")
            for x in req.text.split("\r\n"):
                open("proxies.txt", "a").write(f"\n{x}")
            file = open("proxies.txt", "r").read().split("\n")
            for x in file:
                if x!="" and x!="\n":
                    proxies.append(x)
            print(f"\n{DESIGN.blueplus} {DESIGN.BLUE}{len(proxies)} {DESIGN.WHITE}Proxies Grabbed Successfully")
        else:
            print(f"\n{DESIGN.redminus} {req.text}, {req.status_code}")
            print(f"\n{DESIGN.redminus} Error While Grab Proxies")
            self.inex()
    def api_send_choice(self):
        print(f"\n{DESIGN.blueplus} Choice: ", end="")
        choice = str(input())
        if not any(x==choice for x in ["0", "1"]):
            print(f"\n{DESIGN.redminus} ['0', '1']")
            self.inex()
        head = {"user-agent": f"Instagram 150.0.0.0.000 Android"}
        data = {
            "choice": choice,
            "_uuid": uuid.uuid4(),
            "_uud": uuid.uuid4(),
            "_csrftoken": "massing"
        }
        req = requests.post(f"https://i.instagram.com/api/v1{self.path}", headers=head, data=data, cookies=self.coo)
        #print(req.text, req.status_code)
        if req.status_code==200:
            print(f'\n{DESIGN.blueplus} Code Sent To {DESIGN.BLUE}{req.json()["step_data"]["contact_point"]}')
        else:
            print(f"\n{DESIGN.redminus} {req.text}, {req.status_code}")
            self.inex()
    def api_send_code(self):
        print(f"\n{DESIGN.blueplus} Code: ", end="")
        code = str(input())
        head = {"user-agent": f"Instagram 150.0.0.0.000 Android"}
        data = {
            "security_code": code,
            "_uuid": uuid.uuid4(),
            "_uud": uuid.uuid4(),
            "_csrftoken": "massing"
        }
        req = requests.post(f"https://i.instagram.com/api/v1{self.path}", headers=head, data=data, cookies=self.coo)
        #print(req.text, req.status_code)
        if "logged_in_user" in req.text:
            print(f"\n{DESIGN.blueplus} Logged In {DESIGN.BLUE}'{self.username}'")
            self.sessions.append(req.cookies.get("sessionid"))
        else:
            print(f"\n{DESIGN.redminus} {req.text}, {req.status_code}")
            self.inex()
    def api_challenge(self):
        head = {"user-agent": f"Instagram 150.0.0.0.000 Android"}
        req = requests.get(f"https://i.instagram.com/api/v1{self.path}", headers=head, cookies=self.coo)
        #print(req.text, req.status_code)
        if "phone_number" in req.json()["step_data"]:
            try:
                print(f'\n{DESIGN.bluezero} phone_number {DESIGN.BLUE}{req.json()["step_data"]["phone_number"]}')
            except:
                print(f"\n{DESIGN.redminus} {req.text}, {req.status_code}")
                print(f"\n{DESIGN.redminus} Error {DESIGN.RED}phone_number")
                self.inex()
        if "email" in req.json()["step_data"]:
            try:
                print(f'\n{DESIGN.blueone} email {DESIGN.BLUE}{req.json()["step_data"]["email"]}')
            except:
                print(f"\n{DESIGN.redminus} {req.text}, {req.status_code}")
                print(f"\n{DESIGN.redminus} Error {DESIGN.RED}email")
                self.inex()
        if not any(x in req.json()["step_data"] for x in ["phone_number", "email"]):
            print(f"\n{DESIGN.redminus} {req.text}, {req.status_code}")
            print(f"\n{DESIGN.redminus} Unknown Verification Method")
            self.inex()
        self.api_send_choice()
        self.api_send_code()
    def api_login(self):
        head = {"user-agent": f"Instagram 150.0.0.0.000 Android"}
        data = {
            "jazoest": "22452",
            "phone_id": self.loginuuid,
            "enc_password": f"#PWD_INSTAGRAM:0:0:{self.password}",
            "username": self.username,
            "guid": self.loginuuid,
            "device_id": self.loginuuid,
            "google_tokens": "[]",
            "login_attempt_count": "0"}
        req = requests.post("https://i.instagram.com/api/v1/accounts/login/", headers=head, data=data)
        #print(req.text, req.status_code)
        if "logged_in_user" in req.text:
            print(f"\n{DESIGN.blueplus} Logged In {DESIGN.BLUE}'{self.username}'")
            self.sessions.append(req.cookies.get("sessionid"))
        elif "challenge_required" in req.text:
            self.coo = req.cookies
            self.path = req.json()['challenge']['api_path']
            print(f"\n{DESIGN.redminus} challenge_required")
            print(f"\n{DESIGN.blueone} Accept Secure {DESIGN.bluetwo} Continue To Secure System: ", end="")
            secmode = input()
            if secmode=="1":
                print(f"\n{DESIGN.blueplus} Choose {DESIGN.BLUE}This was me")
                print(f"\n{DESIGN.blueplus} Enter If You Accept: ", end="")
                input()
                self.api_login()
            elif secmode=="2":
                self.api_challenge()
            else:
                print(f"\n{DESIGN.redminus} ['0', '1']")
                self.inex()
        else:
            print(f"\n{DESIGN.redminus} {req.text}, {req.status_code}")
            self.inex()
    def web_send_choice(self):
        print(f"\n{DESIGN.blueplus} Choice: ", end="")
        choice = str(input())
        if not any(x==choice for x in ["0", "1"]):
            print(f"\n{DESIGN.redminus} ['0', '1']")
            self.inex()
        data = {"choice": choice}
        req = requests.post(self.url, headers=self.web_head, data=data, cookies=self.coo)
        #print(req.text, req.status_code)
        if "Enter Your Security" in req.text:
            print(f'\n{DESIGN.blueplus} Code Sent To {DESIGN.BLUE}{req.json()["contact_point"]}')
        else:
            print(f"\n{DESIGN.redminus} {req.text}, {req.status_code}")
            self.inex()
    def web_send_code(self):
        print(f"\n{DESIGN.blueplus} Code: ", end="")
        code = str(input())
        data = {"security_code": code}
        req = requests.post(self.url, headers=self.web_head, data=data, cookies=self.coo)
        #print(req.text, req.status_code)
        if "userId" in req.text:
            print(f"\n{DESIGN.blueplus} Logged In {DESIGN.BLUE}'{self.username}'")
            self.sessions.append(req.cookies.get("sessionid"))
        else:
            print(f"\n{DESIGN.redminus} {req.text}, {req.status_code}")
            self.inex()
    def web_challenge(self):
        head = {
            'accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.9', 
            'accept-encoding': 'gzip, deflate, br', 
            'accept-language': 'en-US,en;q=0.9', 
            "cookie": f"ig_did={uuid.uuid4()}; csrftoken=CZ37ZcqSevnDjDL6CInIP2zG1YgaqzmO; mid=Yf17eAAAAAE1aZP3-AsIFCTY-Wdy",
            'sec-fetch-dest': 'document', 
            'sec-fetch-mode': 'navigate', 
            'sec-fetch-site': 'none', 
            'sec-fetch-user': '?1', 
            'upgrade-insecure-requests': '1', 
            'user-agent': 'Mozilla/7.7'
        }
        req = requests.get(self.url, headers=head)
        #print(req.text, req.status_code)
        if "challengeType" in req.text:
            if "phone_number" in req.json()["fields"]:
                try:
                    print(f'\n{DESIGN.bluezero} phone_number {DESIGN.BLUE}{req.json()["fields"]["phone_number"]}')
                except:
                    print(f"\n{DESIGN.redminus} {req.text}, {req.status_code}")
                    print(f"\n{DESIGN.redminus} Error {DESIGN.RED}phone_number")
                    self.inex()
            if "email" in req.json()["fields"]:
                try:
                    print(f'\n{DESIGN.blueone} email {DESIGN.BLUE}{req.json()["fields"]["email"]}')
                except:
                    print(f"\n{DESIGN.redminus} {req.text}, {req.status_code}")
                    print(f"\n{DESIGN.redminus} Error {DESIGN.RED}email")
                    self.inex()
            if not any(x in req.text for x in ["phone_number", "email"]):
                print(f"\n{DESIGN.redminus} {req.text}, {req.status_code}")
                print(f"\n{DESIGN.redminus} Unknown Verification Method")
                self.inex()
        else:
            print(f"\n{DESIGN.redminus} {req.text}, {req.status_code}")
            self.inex()
        self.web_send_choice()
        self.web_send_code()
    def web_login(self):
        self.web_head = {
            "accept": "*/*", 
            "accept-encoding": "gzip, deflate, br", 
            "accept-language": "en-US,en;q=0.9", 
            "content-length": "267", 
            "content-type": "application/x-www-form-urlencoded", 
            "cookie": "ig_did=0897491F-B736-4E7E-A657-37438D0967B8; csrftoken=xvAQoMiz2eaU4RrcmRp2hqinDVMfgkpe; rur=FTW; mid=XxTPfgALAAGHGReE-x_i1ISMG4Xr", 
            "origin": "https://www.instagram.com", 
            "referer": "https://www.instagram.com/", 
            "sec-fetch-dest": "empty", 
            "sec-fetch-mode": "cors", 
            "sec-fetch-site": "same-origin", 
            "user-agent": "Mozilla/91.81 (Linux; Android 6.3; Nexus 5 Build/MRA58N) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/83.0.4103.116 Mobile Safari/537.36", 
            "x-csrftoken": "xvAQoMiz2eaU4RrcmRp2hqinDVMfgkpe", 
            "x-ig-app-id": "1217981644879628", 
            "x-ig-www-claim": "0", 
            "x-instagram-ajax": "180c154d218a", 
            "x-requested-with": "XMLHttpRequest"
        }
        data = {
            "enc_password": f"#PWD_INSTAGRAM_BROWSER:0:0:{self.password}",
            "username": self.username,
            "optIntoOneTap": "false"
        }
        req = requests.post("https://www.instagram.com/accounts/login/ajax/", headers=self.web_head, data=data)
        #print(req.text, req.status_code)
        if "userId" in req.text:
            print(f"\n{DESIGN.blueplus} Logged In {DESIGN.BLUE}'{self.username}'")
            self.sessions.append(req.cookies.get("sessionid"))
        elif "checkpoint_required" in req.text:
            self.coo = req.cookies
            self.url = 'https://www.instagram.com'+ req.json()['checkpoint_url']+'?__a=1'
            print(f"\n{DESIGN.redminus} challenge_required")
            print(f"\n{DESIGN.blueone} Accept Secure {DESIGN.bluetwo} Continue To Secure System: ", end="")
            secmode = input()
            if secmode=="1":
                print(f"\n{DESIGN.blueplus} Choose {DESIGN.BLUE}This was me")
                print(f"\n{DESIGN.blueplus} Enter If You Accept: ", end="")
                input()
                self.web_login()
            elif secmode=="2":
                self.web_challenge()
            else:
                print(f"\n{DESIGN.redminus} ['0', '1']")
                self.inex()
        else:
            print(f"\n{DESIGN.redminus} {req.text}, {req.status_code}")
            self.inex()
    def check_sessions(self):
        for sessionid in self.sessions:
            head = {
                "user-agent": f"Instagram 150.0.0.0.000 Android",
                "cookie": f"sessionid={sessionid}" 
            }
            req = requests.get("https://i.instagram.com/api/v1/accounts/current_user/?edit=true", headers=head)
            #print(req.text, req.status_code)
            if "pk" in req.text and '"status":"ok"' in req.text:
                username = req.json()["user"]["username"]
                print(f"\n{DESIGN.blueplus} {sessionid} {DESIGN.BLUE}@{username}")
                self.users.append(username)
            elif req.status_code==403:
                print(f"\n{DESIGN.redminus} {req.text}, {req.status_code}")
                print(f"\n{DESIGN.redminus} Bad Sessionid {DESIGN.RED}{sessionid}")
                self.inex()
            else:
                print(f"\n{DESIGN.redminus} {req.text}, {req.status_code}")
                self.inex()
        if len(self.sessions) > 1:
            if self.users[0]!=self.users[1]:
                print(f"\n{DESIGN.redminus} You Need Two {DESIGN.RED}Different Api Sessions {DESIGN.WHITE}For The {DESIGN.RED}Same Account")
                self.inex()
    def current_user(self):
        head = {
            "user-agent": f"Instagram 150.0.0.0.000 Android",
            "cookie": f"sessionid={self.sessions[0]}" 
        }
        req = requests.get("https://i.instagram.com/api/v1/accounts/current_user/?edit=true", headers=head)
        #print(req.text, req.status_code)
        if "pk" in req.text and '"status":"ok"' in req.text:
            try:
                self.username = req.json()["user"]["username"]
                self.full_name = req.json()["user"]["full_name"]
                self.biography = req.json()["user"]["biography"]
                self.external_url = req.json()["user"]["external_url"]
                self.email = req.json()["user"]["email"]
                self.phone_number = req.json()["user"]["phone_number"]
                trusted_username = req.json()["user"]["trusted_username"]
                if trusted_username!=self.username:
                    print(f"\n{DESIGN.redminus} Username Is Swappable")
                    print(f"\n{DESIGN.redminus} Are You Sure You Want To Continue? ({DESIGN.GREEN}Y{DESIGN.WHITE}/{DESIGN.RED}n{DESIGN.WHITE}): ", end="")
                    riskmode = input()
                    if riskmode.lower()=="y":
                        pass
                    elif riskmode.lower()=="n":
                        self.inex()
                    else:
                        print(f"\n{DESIGN.redminus} ['Y', 'n']")
                        self.inex()
            except Exception as err:
                print(f"\n{DESIGN.redminus} {err}")
                print(f"\n{DESIGN.redminus} Failed To Check 14D Please Check It Manually")
                print(f"\n{DESIGN.blueplus} Enter If You Check And Sure It's 14D: ", end="")
                input()
        else:
            print(f"\n{DESIGN.redminus} {req.text}, {req.status_code}")
            self.inex()
    def check(self):
        head = {
            "user-agent": f"Instagram 150.0.0.0.000 Android",
            "cookie": f"sessionid={self.sessions[0]}" 
        }
        try:
            req = requests.get("https://i.instagram.com/api/v1/accounts/current_user/?edit=true", headers=head)
            #print(req.text, req.status_code)
            if "trusted_username" in req.text:
                try:
                    trusted_username = req.json()["user"]["trusted_username"]
                    if trusted_username!=self.username:
                        self.bypass = True
                    else:
                        self.bypass = False
                except:
                    print(f"\n{DESIGN.redminus} {req.text}, {req.status_code}")
                    self.bypass = True
            else:
                print(f"\n{DESIGN.redminus} {req.text}, {req.status_code}")
                self.bypass = True
        except:
            pass
    def bypass_check1(self):
        self.check()
        if self.bypass:
            self.run = False
            print(f"\r\n{DESIGN.blueplus} Bypass = {DESIGN.BLUE}True")
            autopy.alert.alert(f"Done @{self.username}", "@xnce")
            os.kill(os.getpid(), signal.SIGTERM)
        elif self.bypass==False and self.username_changed:
            self.run = False
            print(f"\r\n{DESIGN.redminus} Bypass = {DESIGN.RED}False")
            autopy.alert.alert(f"Failed @{self.username}", "@xnce")
            os.kill(os.getpid(), signal.SIGTERM)
        elif self.bypass==False:
            print(f"\n{DESIGN.redminus} Bypass = {DESIGN.RED}False")
    def bypass_check2(self):
        while self.run:
            if self.done >= self.next_check:
                self.check()
                if self.bypass:
                    self.run = False
                    print(f"\n{DESIGN.blueplus} Bypass = {DESIGN.BLUE}True")
                    autopy.alert.alert(f"Done @{self.username}", "@xnce")
                    os.kill(os.getpid(), signal.SIGTERM)
                elif self.bypass==False and self.username_changed:
                    self.run = False
                    print(f"\n{DESIGN.redminus} Bypass = {DESIGN.RED}False")
                    autopy.alert.alert(f"Failed @{self.username}", "@xnce")
                    os.kill(os.getpid(), signal.SIGTERM)
                elif self.bypass==False:
                    print(f"\n{DESIGN.redminus} Bypass = {DESIGN.RED}False")
                    self.next_check += 10
    def bypass_check3(self):
        self.check()
        if self.bypass:
            self.run = False
            print(f"\n{DESIGN.blueplus} Bypass = {DESIGN.BLUE}True")
            autopy.alert.alert(f"Done @{self.username}", "@xnce")
            os.kill(os.getpid(), signal.SIGTERM)
        elif self.bypass==False:
            print(f"\n{DESIGN.redminus} Bypass = {DESIGN.RED}False")
    def edit_profile(self):
        sessionid = self.sessions[1]
        self.sessions.remove(sessionid)
        head = {
            "user-agent": f"Instagram 185.0.0.0.000 Android (29/10; 300dpi; 720x1440; {''.join(random.choices(string.ascii_lowercase+string.digits, k=16))}/{''.join(random.choices(string.ascii_lowercase+string.digits, k=16))}; {''.join(random.choices(string.ascii_lowercase+string.digits, k=16))}; {''.join(random.choices(string.ascii_lowercase+string.digits, k=16))}; {''.join(random.choices(string.ascii_lowercase+string.digits, k=16))}; en_GB;)",
            "cookie": f"sessionid={sessionid}"
        }
        data = {
            "external_url": self.external_url,
            "phone_number": self.phone_number,
            "username": self.new_username,
            "first_name": self.full_name,
            "_uid": sessionid.split("%3A")[0],
            "device_id": uuid.uuid4(),
            "biography": self.biography,
            "_uuid": uuid.uuid4(),
            "email": self.email
        }
        try:
            req = requests.post("https://i.instagram.com/api/v1/accounts/edit_profile/", headers=head, data=data)
            #print(req.text, req.status_code)
            if '"status":"ok"' in req.text and req.status_code==200:
                print(f"\n{DESIGN.blueplus} Username Changed {DESIGN.BLUE}@{self.new_username}")
                self.username_changed = True
            else:
                print(f"\n{DESIGN.redminus} {req.text}, {req.status_code}")
                self.sessions.append(sessionid)
        except:
            self.sessions.append(sessionid)
    def web_edit(self):
        sessionid = self.sessions[1]
        self.sessions.remove(sessionid)
        head = {
            "content-type": "application/x-www-form-urlencoded",
            "origin": "https://www.instagram.com",
            "referer": "https://www.instagram.com/accounts/edit/",
            "user-agent": "Mozilla/5.0 (Windows NT 6.3; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/98.0.4758.102 Safari/537.36",
            "x-asbd-id": "198387",
            "x-csrftoken": "BdlCGSYQb1FD2yCGEkNu7CUlIhD28vL9",
            "x-ig-app-id": "936619743392459",
            "x-ig-www-claim": "0",
            "x-instagram-ajax": "9ec8fd538e0f",
            "x-requested-with": "XMLHttpRequest",
            "cookie": f"sessionid={sessionid}"
        }
        data = {
            "first_name": self.full_name,
            "email": self.email,
            "username": self.new_username,
            "phone_number": self.phone_number,
            "biography": self.biography,
            "external_url": self.external_url,
            "chaining_enabled": "on"}
        try:
            req = requests.post("https://www.instagram.com/accounts/edit/", headers=head, data=data)
            #print(req.text, req.status_code)
            if '"status":"ok"' in req.text and req.status_code==200:
                print(f"\n{DESIGN.blueplus} Username Changed {DESIGN.BLUE}@{self.new_username}")
                self.username_changed = True
            else:
                print(f"\n{DESIGN.redminus} {req.text}, {req.status_code}")
                self.sessions.append(sessionid)
        except:
            self.sessions.append(sessionid)
    def random_proxy(self):
        prox = random.choice(proxies)
        proxy = {"http": f"socks4://{prox}", "https": f"socks4://{prox}"}
        return proxy
    def set_username(self, proxy):
        head = {
            "user-agent": f"Instagram 150.0.0.0.000 Android (29/10; 300dpi; 720x1440; {''.join(random.choices(string.ascii_lowercase+string.digits, k=16))}/{''.join(random.choices(string.ascii_lowercase+string.digits, k=16))}; {''.join(random.choices(string.ascii_lowercase+string.digits, k=16))}; {''.join(random.choices(string.ascii_lowercase+string.digits, k=16))}; {''.join(random.choices(string.ascii_lowercase+string.digits, k=16))}; en_GB;)",
            "cookie": f"sessionid={self.sessions[0]}" 
        }
        data = {"username": self.username}
        req = self.reqs.post("https://i.instagram.com/api/v1/accounts/set_username/", headers=head, data=data, proxies=proxy)
        #print(req.text, req.status_code, "set_username")
        if '"username"' in req.text and req.status_code==200:
            self.done += 1
            if self.username_changed:
                self.set += 1
        elif req.status_code==429:
            self.error += 1
        else:
            #print(f"\n{DESIGN.redminus} {req.text}, {req.status_code}")
            pass
        self.counter()
    def main0(self):
        while self.run:
            try:
                self.set_username(self.random_proxy())
                if self.done >= 10:
                    if not self.username_changed:
                        self.edit_profile()
                        self.set_username("")
                    else:
                        if self.set >= 5:
                            self.bypass_check1()
                self.set_username(self.random_proxy())
            except Exception as err:
                try:
                    self.set_username(self.random_proxy())
                except:
                    pass
    def main1(self):
        while self.run:
            try:
                self.set_username(self.random_proxy())
                if self.done >= 10:
                    if not self.username_changed:
                        self.web_edit()
                        #self.set_username("")
                    else:
                        if self.set >= 7:
                            self.bypass_check1()
                self.set_username(self.random_proxy())
            except Exception as err:
                try:
                    self.set_username(self.random_proxy())
                except:
                    pass
    def main2(self):
        while self.run:
            try:
                self.set_username(self.random_proxy())
            except:
                try:
                    self.set_username(self.random_proxy())
                except:
                    pass
    def main3(self):
        while self.run:
            try:
                self.set_username(self.random_proxy())
                if self.done >= self.next_check:
                    self.next_check += 10
                    self.bypass_check3()
            except:
                try:
                    self.set_username(self.random_proxy())
                except:
                    pass
    def counter(self):
        os.system(f"title Done : {self.done} / Error : {self.error}")
class XNCE2():
    def __init__(self):
        self.done, self.error, self.turn, self.rs, self.run, self.username_claimed = 0, 0, 0, "-", True, False
        self.data = {"username": target}
        self.reqs = requests.Session()
    def inex(self):
        self.run = False
        print(f"\n{DESIGN.redminus} Enter To Exit: ", end="")
        input()
        os.kill(os.getpid(), signal.SIGTERM)
    def current_user(self, sessionid):
        head = {
            "user-agent": f"Instagram 150.0.0.0.000 Android",
            "cookie": f"sessionid={sessionid}" 
        }
        try:
            req = requests.get("https://i.instagram.com/api/v1/accounts/current_user/?edit=true", headers=head)
            #print(req.text, req.status_code)
            try:
                email = req.json()["user"]["email"]
                phone_number = req.json()["user"]["phone_number"]
            except:
                email = "-"
                phone_number = "-"
        except:
            email = "-"
            phone_number = "-"
        open(f"{target}.txt", "a").write(f"email: {email}\nphone_number: {phone_number}\n")
    def claimed(self, sessionid, attempts, rs):
        self.username_claimed = True
        open(f"{target}.txt", "a").write(f"\nusername: {target}\nsessionid: {sessionid}\nattempts: {attempts}\nR/s: {rs}\n")
        print(f"\n{DESIGN.blueplus} Claimed {DESIGN.BLUE}@{target}")
        self.current_user(sessionid)
        self.inex()
    def remove_session(self, sessionid):
        accounts.remove(sessionid)
        if len(accounts) < 1:
            print(f"\n{DESIGN.redminus} run = {DESIGN.RED}False{DESIGN.WHITE}, No Accounts")
            self.inex()
    def allow_cookies(self, sessionid):
        head = {
            "accept": "*/*",
            "accept-encoding": "gzip, deflate, br",
            "accept-language": "en-US,en;q=0.9",
            "content-type": "application/x-www-form-urlencoded",
            "cookie": f"csrftoken=lsTCRaBnoodTq5lxG4vSp32JzMevNPJf; mid=YgZa-AAEAAEnepP4F1342yj-MahQ; ig_did=84ED2434-4FBB-4C74-8B90-94C4611BB587; sessionid={sessionid}",
            "origin": "https://www.instagram.com/",
            "referer": "https://www.instagram.com/",
            "user-agent": "Mozilla/5.0 (Windows NT 6.3; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/98.0.4758.82 Safari/537.36",
            "x-asbd-id": "198387",
            "x-csrftoken": "lsTCRaBnoodTq5lxG4vSp32JzMevNPJf",
            "x-ig-app-id": "936619743392459",
            "x-ig-www-claim": "0",
            "x-instagram-ajax": "44eaba6c585b",
            "x-mid": "YgZa-AAEAAEnepP4F1342yj-MahQ",
            "x-requested-with": "XMLHttpRequest"
        }
        data = {
            "doc_id": "4181090201923535",
            "variables": '{"third_party_tracking_opt_in":true,"cross_site_tracking_opt_in":true,"input":{"client_mutation_id":0}}'
        }
        req = requests.post("https://www.instagram.com/web/wwwgraphql/ig/query/", headers=head, data=data)
        #print(req.text, req.status_code)
        if'"success":true' not in req.text:
            self.remove_session(sessionid)
    def random_proxy(self):
        prox = random.choice(proxies)
        return {"https": f"{my_proxy}{prox}", "http": f"{my_proxy}{prox}"}
    def set_username(self, sessionid):
        head = {
            "user-agent": f"Instagram 150.0.0.0.000 Android",
            "cookie": f"sessionid={sessionid}"
        }
        req = self.reqs.post("https://i.instagram.com/api/v1/accounts/set_username/", headers=head, data=self.data, proxies=self.random_proxy())
        #print(req.text, req.status_code, "set_username")
        if '"status":"ok' in req.text and req.status_code==200:
            if not self.username_claimed:
                self.claimed(sessionid, self.done, self.rs)
        elif any(x in req.text for x in ["already exists", "isn't", "Something is wrong"]):
            self.done += 1
        elif any(x in req.text for x in ["challenge_required", "checkpoint_required"]):
            self.allow_cookies(sessionid)
            #self.remove_session(sessionid)
        elif "login_required" in req.text:
            self.remove_session(sessionid)
        elif any(x in req.text for x in ["Try Again Later", "Oops, an error"]) or req.text=="":
            self.error += 1
        elif req.status_code==429:
            self.error += 1
        else:
            #print(f"\n{DESIGN.redminus} {req.text}, {req.status_code}")
            pass
    def main(self):
        while self.run:
            try:
                sessionid = accounts[self.turn]
            except:
                self.turn = 0
                try:
                    sessionid = accounts[self.turn]
                except:
                    pass
            self.turn += 1
            try:
                self.set_username(sessionid)
            except Exception as err:
                try:
                    self.set_username(sessionid)
                except:
                    pass
    def counter(self):
        while self.run:
            before = self.done
            time.sleep(1)
            after = self.done
            self.rs = after-before
            os.system(f"title Done : {self.done} / Error : {self.error} / Accounts: {len(accounts)} / R/s: {self.rs}")
clear()
print(DESIGN.xrblue)
print(f"\n{DESIGN.blueplus} Last Update: {DESIGN.BLUE}2022/04/20 20:40")
print(f"\n{DESIGN.blueplus} This Tool Is {DESIGN.YELLOW}Free")
s = SETTINGS()
if s.settingsmode=="0": 
    print(f"\n{DESIGN.blueone} 14D Bypass {DESIGN.bluetwo} Auto Claimer: ", end="")
    tmode = input()
else: 
    tmode = s.tmode
if tmode=="1":
    print(f"\n{DESIGN.bluezero} Auto Bypass {DESIGN.blueone} Auto Bypass {DESIGN.BLUE}NEW {DESIGN.bluetwo} Manual Bypass {DESIGN.bluethree} Manual Bypass {DESIGN.BLUE}NEW{DESIGN.WHITE}: ", end="")
    bpmode = input()
    if bpmode=="0":
        x = XNCE("0")
        clear()
        print(DESIGN.xrblue)
        print(f"\n{DESIGN.blueplus} Enter To Start: ", end="")
        input()
        t = THRIDING(x.main0, "")
        t.gen(2000)
        t.start()
        t.join()
    elif bpmode=="1":
        x = XNCE("0")
        clear()
        print(DESIGN.xrblue)
        print(f"\n{DESIGN.blueplus} Enter To Start: ", end="")
        input()
        t = THRIDING(x.main1, "")
        t.gen(2000)
        t.start()
        t.join()
    elif bpmode=="2":
        x = XNCE("2")
        clear()
        print(DESIGN.xrblue)
        print(f"\n{DESIGN.blueplus} Enter To Start: ", end="")
        input()
        t = THRIDING(x.main2, x.bypass_check2)
        t.gen(999)
        t.start()
        t.join()
    elif bpmode=="3":
        x = XNCE("2")
        clear()
        print(DESIGN.xrblue)
        print(f"\n{DESIGN.blueplus} Enter To Start: ", end="")
        input()
        t = THRIDING(x.main3, "")
        t.gen(999)
        t.start()
        t.join()
    else:
        print(f"\n{DESIGN.redminus} ['0', '1'  '2]")
        input()
        exit()
elif tmode=="2":
    FILES("proxies", proxies)
    FILES("accounts", accounts)
    clear()
    print(DESIGN.xrblue2)
    print(f"\n{DESIGN.bluezero} HTTP/S {DESIGN.blueone} SOCKS4 {DESIGN.bluetwo} SOCKS5: ", end="")
    proxies_type = input()
    if proxies_type=="0":
        my_proxy = ""
    elif proxies_type=="1":
        my_proxy = "socks4://"
    elif proxies_type=="2":
        my_proxy = "socks5//"
    else:
        print(f'\n{DESIGN.redminus} ["0", "1", "2"]', end="")
        input()
        exit()
    print(f"\n{DESIGN.blueplus} Target: ", end="")
    target = input()
    if target=="":
        print(f"\n{DESIGN.redminus} wtf is this", end="")
        input()
        exit()
    print(f"\n{DESIGN.blueplus} Threads: ", end="")
    threads = int(input())
    x2 = XNCE2()
    print(f"\n{DESIGN.blueplus} Enter To Start: ", end="")
    input()
    t = THRIDING(x2.main, x2.counter)
    t.gen(threads)
    t.start()
    t.join()
else:
    print(f"\n{DESIGN.redminus} ['1', '2']")
    input()
    exit()
