# IPCAS - Intrusion Prevention and Counter Attack System

IPCAS is an Intrusion Prevention and Counter Attack System born as a research project for my Computer System Security exam.

As the name says, this tool aims to prevent an attack and try to replicate it to all the other victims you specify. Despite being a research project, it turned out to be really usefull and usable during the CTF Attack-Defense, famous competitions where a lot of cybersecurity teams from all the world can take part.

In fact, the tool can be used to analyze a specific service you have to protect (a particular ip addres accessible from the machine you are going to run the software), looking for incoming attack and replicate them to all the other CTF participants, without even knowing the real attack. 

I created a video tutorial to explain both the architecture and how the system works, making a simple example using a dumb web application which you can find under the [vuln\_app](./vuln_app) folder.

https://drive.google.com/file/d/1g6QS__hsjmrfE1f3QuKdnrGEHPpMY9KD/view?usp=sharing

## Requirements

```python
from mitmproxy import proxy, options
from mitmproxy.tools.dump import DumpMaster
from mitmproxy.script import concurrent
from argparse import ArgumentParser, ArgumentDefaultsHelpFormatter
from random import choice
from string import digits, ascii_letters
from threading import Timer
from re import search
from urllib3 import PoolManager
```

Many of these dependencies are already satisfied, but you will likely have to install at least:

* mitmproxy
* urllib3

## Architecture

IPCAS is a reverse proxy that forwards traffic to and from another address. It is built over the Mitmproxy framework, a very huge and complete tool which has significantly eased IPCAS production.

Since mitmproxy relies on Addons, small pieces of code which can be added/removed from the program, IPCAS introduces an ad-hoc addon built to analyze service responses. This addon is multithreading, meaning that every client connection is independent and managed concurrently.

It contains an additional feature: when it detects an attack, it replicates the malicious request to all the other CTF participants addresses contained in a pre configured pool (usually obtained after a nmap scan). This additional feature will be improved to store the achieved flags in a MongoDB database, in order to let another component (CTFSubmitter) read them and try to score points by delivering them to the master service.

The analysis performed on the request is quite simple: if the response payload matches a specific pattern (the ctf flag), IPCAS will modify it with a fake one, letting our attacker believe that he has successfully obtained the flag, while we are defending ours and not losing points. The fake flag is generated only once, but it could be easily modified to make them regenerate every X minute, like in a real competition.

## Usage

```bash
usage: ipcas.py [-h] [-a ADDRESS] [-p PORT] [-f FLAG] reverse-address

positional arguments:
  reverse-address       reserve service address ("http[s]://host[:port]")

optional arguments:
  -h, --help            show this help message and exit
  -a ADDRESS, --address ADDRESS
                        address to bind proxy to (default: )
  -p PORT, --port PORT  proxy service port (default: 8080)
  -f FLAG, --flag FLAG  pattern for the flag (default: myFlg{(.*)})
```

It is important to generate the fake flag that the pattent contains the square brackets around the content, since it has to be modified with the randomly created one.

The default address, as for mitmproxy, is *, meaning that it will listen for all incoming connections also from the other LAN devices.

## Possible extensions

* store flags in MongoDB and create a Submitter
* store flows in MongoDB and create a Dashboard