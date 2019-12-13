# ReverseShell_Windows
Reverse shell that runs on windows (tested on win10). Tries to establish connection with C2 server on localhost via port 1337.
It adds itself to startup programs in registry (assuming it ran with admin privileges).

## Commands
The shell supports the following commands:

- whoami
- hostname
- dir - mimics ls/dir commands
- cd - traverse  in victim's pc
- encrypt %file_name% - creates an encrypted version of %file_name% and deletes the original. Prompts the victim to pay money.
- decrypt %file_name% - decrypts the relevant file.
- shutdown - ends connection and removes the tool from registry.

## Encryption
Uses RC4 encryption which is extremely simple and easy to apply. 
See: https://docs.microsoft.com/en-us/windows/win32/seccrypto/example-c-program-encrypting-a-file

## Usage
Run nc -lp 1337 to listen on port 1337. Can use 'rlwrap' for history options.

## Compilation flags
Exe compiled with:
g++ -m32 -std=c++11 ReverseShell.cpp -o trust_me.exe -s -lws2_32 -fno-exceptions -fmerge-all-constants -static-libstdc++ -static-libgcc -w -fpermissive

Ensures the binary is minimal as possible, stripped from compilation meta-data and avoids dynamic links.
Further reading can be found here: 
https://niiconsulting.com/checkmate/2018/03/malware-development-welcome-dark-side-part-2-2/

