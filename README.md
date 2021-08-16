<p align="center"><img width=600 alt="Invoke-DNSteal" src="https://raw.githubusercontent.com/JoelGMSec/Invoke-DNSteal/main/Design/Invoke-DNSteal.png"></p>

**Invoke-DNSteal** is a Simple & Customizable DNS Data Exfiltrator.

This tool helps you to exfiltrate data through DNS protocol over UDP and TCP, and lets you control the size of queries using random delay. Also, allows you to avoid detections by using random domains in each of your queries and you can use it to transfer information both locally and remotely.


# Requirements
- Powershell 4.0 or higher
- Python 2


# Download
It is recommended to clone the complete repository or download the zip file.
You can do this by running the following command:
```
git clone https://github.com/JoelGMSec/Invoke-DNSteal.git
```


# Usage
```
.\Invoke-DNSteal.ps1 -h

  ___                 _              ____  _   _ ____  _             _
 |_ _|_ __ _   __ __ | | __ __      |  _ \| \ | / ___|| |__ __  __ _| |
  | || '_ \ \ / / _ \| |/ / _ \_____| | | |  \| \___ \| __/ _ \/ _' | |
  | || | | \ V / (_) |   <  __/_____| |_| | |\  |___) | ||  __/ (_| | |
 |___|_| |_|\_/ \___/|_|\_\___|     |____/|_| \_|____/ \__\___|\__,_|_|

  --------------------------- by @JoelGMSec --------------------------

 Info:  This tool helps you to exfiltrate data through DNS protocol
        and lets you control the size of queries using random delay

 Usage: .\Invoke-DNSteal.ps1 -t target -p payload -l length
         -s server -tcponly true/false -min 3000 -max 5000

 Parameters:
       · Target:      Domain target to exfiltrate data
       · Payload:     Payload to send over DNS chunks
       · Length:      Length of payload to control data size
       · Server:      Custom server to resolve DNS queries
       · TcpOnly:     Set TcpOnly to true or false
       · Delay Min:   Min delay time to do a query in ms
       · Delay Max:   Max delay time to do a query in ms
       · Random:      Use random domain name to avoid detection

 Warning: The length (payload size) must be between 4 and 240
          The process time will increase depending on data size
```

### The detailed guide of use can be found at the following link:

https://darkbyte.net/exfiltrando-informacion-por-dns-con-invoke-dnsteal


# License
This project is licensed under the GNU 3.0 license - see the LICENSE file for more details.


# Credits and Acknowledgments
<!-- Twitter URLs -->
[@3v4si0n]: https://twitter.com/3v4si0n

This script has been created and designed from scratch by Joel Gámez Molina // @JoelGMSec

Special thanks to [@3v4si0n] for DNS over TCP implementation, and some general Python code.


# Contact
This software does not offer any kind of guarantee. Its use is exclusive for educational environments and / or security audits with the corresponding consent of the client. I am not responsible for its misuse or for any possible damage caused by it.

For more information, you can contact through info@darkbyte.net


# Support
You can support my work buying me a coffee:

[<img width=250 alt="buymeacoffe" src="https://cdn.buymeacoffee.com/buttons/v2/default-blue.png">](https://www.buymeacoffee.com/joelgmsec)
