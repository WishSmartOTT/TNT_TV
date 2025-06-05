#!/usr/bin/python
# -*- coding: utf-8 -*-
import subprocess, os, random, string, sys, shutil, socket, zipfile, urllib2
from itertools import cycle, izip
from zipfile import ZipFile

rDownloadURL = {"main": "https://github.com/emre1393/xtreamui_mirror/releases/latest/download/main.tar.gz", "sub": "https://github.com/emre1393/xtreamui_mirror/releases/latest/download/LB.tar.gz"}
rPackages = ["libcurl3", "libxslt1-dev", "libgeoip-dev", "e2fsprogs", "wget", "mcrypt", "nscd", "htop", "zip", "unzip", "mc", "libjemalloc1", "python-paramiko"]
rInstall = {"MAIN": "main", "LB": "sub"}

rVersions = {
    "16.04": "xenial",
    "18.04": "bionic"
}

class col:
    HEADER = '\033[95m'
    OKBLUE = '\033[94m'
    OKGREEN = '\033[92m'
    WARNING = '\033[93m'
    FAIL = '\033[91m'
    YELLOW = '\033[33m'
    ENDC = '\033[0m'
    BOLD = '\033[1m'
    UNDERLINE = '\033[4m'

def generate(length=32): return ''.join(random.choice(string.ascii_letters + string.digits) for i in range(length))

def getIP():
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    s.connect(("8.8.8.8", 80))
    return s.getsockname()[0]

def getVersion():
    try: return subprocess.check_output("lsb_release -d".split()).split(":")[-1].strip()
    except: return ""

def printc(rText, rColour=col.OKBLUE, rPadding=0):
    print "%s ┌──────────────────────────────────────────┐ %s" % (rColour, col.ENDC)
    for i in range(rPadding): print "%s │                                          │ %s" % (rColour, col.ENDC)
    print "%s │ %s%s%s │ %s" % (rColour, " "*(20-(len(rText)/2)), rText, " "*(40-(20-(len(rText)/2))-len(rText)), col.ENDC)
    for i in range(rPadding): print "%s │                                          │ %s" % (rColour, col.ENDC)
    print "%s └──────────────────────────────────────────┘ %s" % (rColour, col.ENDC)
    print " "

def prepare(rType="MAIN"):
    global rPackages
    if rType <> "MAIN": rPackages = rPackages[:-3]
    printc("Preparing Installation")
    for rFile in ["/var/lib/dpkg/lock-frontend", "/var/cache/apt/archives/lock", "/var/lib/dpkg/lock"]:
        try: os.remove(rFile)
        except: pass
    os.system("apt-get update > /dev/null")
    printc("Removing libcurl4 if installed")
    os.system("apt-get remove --auto-remove libcurl4 -y > /dev/null")
    for rPackage in rPackages:
        printc("Installing %s" % rPackage)
        os.system("apt-get install %s -y > /dev/null" % rPackage)
    printc("Installing libpng")
    os.system("wget -q -O /tmp/libpng12.deb http://mirrors.kernel.org/ubuntu/pool/main/libp/libpng/libpng12-0_1.2.54-1ubuntu1_amd64.deb")
    os.system("dpkg -i /tmp/libpng12.deb > /dev/null")
    os.system("apt-get install -y > /dev/null") # Clean up above
    try: os.remove("/tmp/libpng12.deb")
    except: pass
    try:
        subprocess.check_output("getent passwd xtreamcodes > /dev/null".split())
    except:
        # Create User
        printc("Creating user xtreamcodes")
        os.system("adduser --system --shell /bin/false --group --disabled-login xtreamcodes > /dev/null")
    if not os.path.exists("/home/xtreamcodes"): os.mkdir("/home/xtreamcodes")
    return True

def install(rType="MAIN"):
    global rInstall, rDownloadURL
    printc("Downloading Software")
    try: rURL = rDownloadURL[rInstall[rType]]
    except:
        printc("Invalid download URL!", col.FAIL)
        return False
    os.system('wget -q -O "/tmp/xtreamcodes.tar.gz" "%s"' % rURL)
    if os.path.exists("/tmp/xtreamcodes.tar.gz"):
        printc("Installing Software")
        if os.path.exists("/home/xtreamcodes/iptv_xtream_codes/GeoLite2.mmdb"):
            os.system('chattr -f -i /home/xtreamcodes/iptv_xtream_codes/GeoLite2.mmdb > /dev/null')
        os.system('tar -zxvf "/tmp/xtreamcodes.tar.gz" -C "/home/xtreamcodes/" > /dev/null')
        try: os.remove("/tmp/xtreamcodes.tar.gz")
        except: pass
        return True
    printc("Failed to download installation file!", col.FAIL)
    return False


def installadminpanel():
    rURL = "https://github.com/emre1393/xtreamui_mirror/releases/latest/download/release_22f.zip"
    printc("Downloading Admin Panel")  
    os.system('wget -q -O "/tmp/update.zip" "%s"' % rURL)
    if os.path.exists("/tmp/update.zip"):
        try: is_ok = zipfile.ZipFile("/tmp/update.zip")
        except:
            printc("Invalid link or zip file is corrupted!", col.FAIL)
            os.remove("/tmp/update.zip")
            return False
    printc("Installing Admin Panel")
    os.system('unzip -o /tmp/update.zip -d /tmp/update/ > /dev/null && cp -rf /tmp/update/XtreamUI-master/* /home/xtreamcodes/iptv_xtream_codes/ > /dev/null && rm -rf /tmp/update/XtreamUI-master > /dev/null && rm -rf /tmp/update > /dev/null && chown -R xtreamcodes:xtreamcodes /home/xtreamcodes > /dev/null')
    try: os.remove("/tmp/update.zip")
    except: pass
    rURL2 = "https://github.com/emre1393/xtreamui_mirror/releases/latest/download/newstuff.zip"
    printc("Downloading New Stuff for Admin Panel")  
    os.system('wget -q -O "/tmp/update2.zip" "%s"' % rURL2)
    if os.path.exists("/tmp/update2.zip"):
        try: is_ok = zipfile.ZipFile("/tmp/update2.zip")
        except:
            printc("Invalid link or zip file is corrupted!", col.FAIL)
            os.remove("/tmp/update2.zip")
            return False
        printc("Installing New Stuff for Admin Panel")
        os.system('unzip -o /tmp/update2.zip -d /tmp/update2/ > /dev/null && cp -rf /tmp/update2/* /home/xtreamcodes/iptv_xtream_codes/ > /dev/null && rm -rf /tmp/update2/* > /dev/null && rm -rf /tmp/update2 > /dev/null && chown -R xtreamcodes:xtreamcodes /home/xtreamcodes/ > /dev/null > /dev/null')
        return True
    printc("Failed to download installation file!", col.FAIL)
    return False

def encrypt(rHost="172.20.0.11", rUsername="user_iptvpro", rPassword="", rDatabase="xtream_iptvpro", rServerID=1, rPort=7999):
    printc("Encrypting...")
    try: os.remove("/home/xtreamcodes/iptv_xtream_codes/config")
    except: pass
    rf = open('/home/xtreamcodes/iptv_xtream_codes/config', 'wb')
    rf.write(''.join(chr(ord(c)^ord(k)) for c,k in izip('{\"host\":\"%s\",\"db_user\":\"%s\",\"db_pass\":\"%s\",\"db_name\":\"%s\",\"server_id\":\"%d\", \"db_port\":\"%d\", \"pconnect\":\"0\"}' % (rHost, rUsername, rPassword, rDatabase, rServerID, rPort), cycle('5709650b0d7806074842c6de575025b1'))).encode('base64').replace('\n', ''))
    rf.close()

def configure():
    printc("Configuring System")
    if not "/home/xtreamcodes/iptv_xtream_codes/" in open("/etc/fstab").read():
        rFile = open("/etc/fstab", "a")
        rFile.write("tmpfs /home/xtreamcodes/iptv_xtream_codes/streams tmpfs defaults,noatime,nosuid,nodev,noexec,mode=1777,size=90% 0 0\ntmpfs /home/xtreamcodes/iptv_xtream_codes/tmp tmpfs defaults,noatime,nosuid,nodev,noexec,mode=1777,size=3G 0 0")
        rFile.close()
    if not "xtreamcodes" in open("/etc/sudoers").read():
        os.system('echo "xtreamcodes ALL = (root) NOPASSWD: /sbin/iptables, /usr/bin/chattr" >> /etc/sudoers')
    if not os.path.exists("/etc/init.d/xtreamcodes"):
        rFile = open("/etc/init.d/xtreamcodes", "w")
        rFile.write("#! /bin/bash\n/home/xtreamcodes/iptv_xtream_codes/start_services.sh")
        rFile.close()
        os.system("chmod +x /etc/init.d/xtreamcodes > /dev/null")
    os.system("mount -a")
    try: os.remove("/usr/bin/ffmpeg")
    except: pass
    if not os.path.exists("/home/xtreamcodes/iptv_xtream_codes/tv_archive"): os.mkdir("/home/xtreamcodes/iptv_xtream_codes/tv_archive/")
    os.system("ln -s /home/xtreamcodes/iptv_xtream_codes/bin/ffmpeg /usr/bin/")
    os.system("chown xtreamcodes:xtreamcodes -R /home/xtreamcodes > /dev/null")
    os.system("chmod -R 0777 /home/xtreamcodes > /dev/null")
    if rType == "MAIN": 
        os.system("sudo find /home/xtreamcodes/iptv_xtream_codes/admin/ -type f -exec chmod 644 {} \;")
        os.system("sudo find /home/xtreamcodes/iptv_xtream_codes/admin/ -type d -exec chmod 755 {} \;")
    #adds domain/user/pass/id.ts url support
    with open('/home/xtreamcodes/iptv_xtream_codes/nginx/conf/nginx.conf', 'r') as nginx_file:
        nginx_replace = nginx_file.read()
        nginx_replace = nginx_replace.replace("rewrite ^/(.*)/(.*)/(\\d+)$ /streaming/clients_live.php?username=$1&password=$2&stream=$3&extension=ts break;", "rewrite ^/(.*)/(.*)/(\\d+)\\.(.*)$ /streaming/clients_live.php?username=$1&password=$2&stream=$3&extension=$4 break;\r\n        rewrite ^/(.*)/(.*)/(\\d+)$ /streaming/clients_live.php?username=$1&password=$2&stream=$3&extension=ts break;\r\n")
    with open('/home/xtreamcodes/iptv_xtream_codes/nginx/conf/nginx.conf', 'w') as nginx_file:
        nginx_file.write(nginx_replace)
    os.system("wget -q https://github.com/emre1393/xtreamui_mirror/releases/latest/download/downloads/nginx -O /home/xtreamcodes/iptv_xtream_codes/nginx/sbin/nginx")
    os.system("wget -q https://github.com/emre1393/xtreamui_mirror/releases/latest/download/nginx_rtmp -O /home/xtreamcodes/iptv_xtream_codes/nginx_rtmp/sbin/nginx_rtmp")
    os.system("wget -q https://github.com/emre1393/xtreamui_mirror/releases/latest/download/pid_monitor.php -O /home/xtreamcodes/iptv_xtream_codes/crons/pid_monitor.php")
    os.system("sudo chmod +x /home/xtreamcodes/iptv_xtream_codes/nginx/sbin/nginx")
    os.system("sudo chmod +x /home/xtreamcodes/iptv_xtream_codes/nginx_rtmp/sbin/nginx_rtmp")
    os.system("sudo find /home/xtreamcodes/iptv_xtream_codes/wwwdir/ -type f -exec chmod 644 {} \;")
    os.system("sudo find /home/xtreamcodes/iptv_xtream_codes/wwwdir/ -type d -exec chmod 755 {} \;")
    os.system("chmod 0700 /home/xtreamcodes/iptv_xtream_codes/config > /dev/null")
    os.system("sed -i 's|echo \"Xtream Codes Reborn\";|header(\"Location: https://www.google.com/\");|g' /home/xtreamcodes/iptv_xtream_codes/wwwdir/index.php")
    os.system("wget -q https://github.com/emre1393/xtreamui_mirror/releases/latest/download/GeoLite2.mmdb -O /home/xtreamcodes/iptv_xtream_codes/GeoLite2.mmdb")
    os.system('chattr -f +i /home/xtreamcodes/iptv_xtream_codes/GeoLite2.mmdb > /dev/null')
    os.system("sed -i 's|chown -R xtreamcodes:xtreamcodes /home/xtreamcodes|chown -R xtreamcodes:xtreamcodes /home/xtreamcodes 2>/dev/null|g' /home/xtreamcodes/iptv_xtream_codes/start_services.sh")
    os.system("chmod +x /home/xtreamcodes/iptv_xtream_codes/start_services.sh > /dev/null")

    if not "xtream-codes.com" in open("/etc/hosts").read(): os.system('echo "127.0.0.1    xtream-codes.com" >> /etc/hosts')
    if not "api.xtream-codes.com" in open("/etc/hosts").read(): os.system('echo "127.0.0.1    api.xtream-codes.com" >> /etc/hosts')
    if not "downloads.xtream-codes.com" in open("/etc/hosts").read(): os.system('echo "127.0.0.1    downloads.xtream-codes.com" >> /etc/hosts')
    if not "@reboot root /home/xtreamcodes/iptv_xtream_codes/start_services.sh" in open("/etc/crontab").read(): os.system('echo "@reboot root /home/xtreamcodes/iptv_xtream_codes/start_services.sh" >> /etc/crontab')

def start(first=True):
    if first: printc("Starting Xtream Codes")
    else: printc("Restarting Xtream Codes")
    os.system("/home/xtreamcodes/iptv_xtream_codes/start_services.sh > /dev/null")


if __name__ == "__main__":

    try: rVersion = os.popen('lsb_release -sr').read().strip()
    except: rVersion = None
    if not rVersion in rVersions:
        printc("Unsupported Operating System, Works only on Ubuntu Server 16 and 18")
        sys.exit(1)

    printc("Xtream UI - Installer Mirror", col.OKGREEN, 2)
    print "%s │ Check out the mirror repo: https://bitbucket.org/emre1393/xtreamui_mirror %s" % (col.OKGREEN, col.ENDC)
    print " "
    rType = raw_input("  Installation Type [MAIN, LB]: ")
    print " "
    if rType.upper() in ["MAIN", "LB"]:
        if rType.upper() == "LB":
            rHost = raw_input("  Main Server IP Address: ")
            rPassword = raw_input("  MySQL Password: ")
            try: rServerID = int(raw_input("  Load Balancer Server ID: "))
            except: rServerID = -1
            print " "
        else:
            rHost = "172.20.0.11"
            rPassword = f9ef1qOmOQrghZumyH11pw
            rServerID = 1
            rAccesscode = generate(12)

        rUsername = "user_iptvpro"
        rDatabase = "xtream_iptvpro"
        rPort = 7999
        if len(rHost) > 0 and len(rPassword) > 0 and rServerID > -1:
            printc("Start installation? Y/N", col.WARNING)
            if raw_input("  ").upper() == "Y":
                print " "
                rRet = prepare(rType.upper())
                if not install(rType.upper()): sys.exit(1)
                if rType.upper() == "MAIN":
                    if not mysql(rUsername, rPassword): sys.exit(1)
                encrypt(rHost, rUsername, rPassword, rDatabase, rServerID, rPort)
                if rType.upper() == "MAIN": 
                    installadminpanel()
                    os.system("sed -i 's|randomcodehere|%s|g' /home/xtreamcodes/iptv_xtream_codes/nginx/conf/admin_panel.conf" % rAccesscode)
                configure()
                start()
                printc("Installation completed!", col.OKGREEN, 2)
                if rType.upper() == "MAIN":
                    printc("Please store your MySQL password!")
                    printc(rPassword)
                    printc("Admin UI Login URL is:")
                    printc("http://%s:8080/%s" % (getIP(), rAccesscode))
                    printc("Admin UI default login is admin/admin")
            else: printc("Installation cancelled", col.FAIL)
        else: printc("Invalid entries", col.FAIL)
    else: printc("Invalid installation type", col.FAIL)
