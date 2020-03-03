# FilterKit
MacOS kernel security filter

This is a POC for a socket and process filter for MacOS (currently only tested under Mojave/xCode 11)

This was originally conceived to log all network connections and the sha256 hash of their corresponding processes at the kernel level. The idea was to pipe this data directly out to a server. By not utilizing user-space, this "canary" can drop all the data needed for security auditing whilst staying relatively obscured.

Currently the project only dumps output to the os console as shown:



- Thread locking is used to ensure there are no significant overhead issues.
- Hashing is performed by accessing the file system from with-in the kernel (magic? ;p).

Known Issues:
- MacOS forwards all inbound connections via the local firewall, thus inbound user-space traffic will always have the same destination process (com.apple.WebKit).
- You will need to disable kext signing to load, or buy a dev license.
- May not work under Catalina due to api changes (aka EndpointSecurity).
- Unloading of kext is buggy (may crash, just reboot to unload, security feature ? ;p)

Todo:
- Function for RSA on outbound data
- Function to send data to server
- Possibly add file-write events
- Server side implementation
- Fix unloading bug
- Clean up includes
- Optimize / Buffer ?

# Usage
```
sudo chown -R root:wheel FilterKit.kext
sudo sudo chmod -R 755 FilterKit.kext
sudo kextutil FilterKit.kext
```

# Acknowledgements	

Hashing libraries Alain Mosnier - https://github.com/amosnier/sha-2
OS X and iOS Kernel Programming - Ole Henry Halvorsen | Douglas Clarke

# Disclaimer

Please refer to LICENSE file.

NOTE: This is a POC, I'm not a professional kernel developer!
