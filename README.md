# Lord of Cereal (Work in progress)
Java serialization tool for creating encrypted and HMAC protected payloads.

![Alt Text Cereal](https://gph.is/11s2Dss)

## Overview:
This tool is meant for situations when the encryption and/or HMAC secret from the web.xml file is leaked from the server (through LFI or other means). The secret can be used in this tool so that payloads are encrypted and HMAC protected and then sent to the server for execution.  

### Encryption method:
* DES
* (Coming soon: AES)

### Digest method:
* HMAC-SHA1
* (More to come soon)

### Payload formatting options:
* Powershell
* Bash
* (Python/Perl coming soon!)

### Sample command:
`python Lord_of_Cereal.py -u "http://192.168.1.10:8080/sub.faces" -e DES -s s3cr3tk3y -p commons3 -t javax.faces.ViewState -c "ping 192.168.10.8" -f powershell`

## To do:
* Add support for other encryption methods
* Add support for other HMAC digest methods
* Add separate option for when the encryption secret and HMAC secret differ
* Add switches for Java payload types
* Add Python and Perl support as payload options
