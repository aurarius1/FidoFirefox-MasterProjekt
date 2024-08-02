# FidoMP_Firefox
This repository contains the modifications needed to make to the Firefox sourcecode to build Firefox with support for the work of my Master's project - namely to make use of a DBUS server to interact with a Fido token when creating a credential / asserting.

# How to
The setup is pretty easy, from the [base repo](https://github.com/aurarius1/FidoDbus-MasterProject) fetch the files in code/client/ and copy them into into dom/webauthn inside the Firefox directory. 

Afterwards proceed with the files in this repository. You first need to replace the MakeCredential and GetAssertion function in dom/webauthn/WebAuthnService.cpp in the Firefox source code with the two functions contained in the WebAuthnService.cpp inside this repository. You could also replace the whole file, but that probably would lead to build errors (as this file already changed during the time of development of my project), so it's best to just copy the functions on their own. Additionally you'd need to add a `include "fido.h"` at the top of the file, as my functions use this dependency. The original thought here was to provide this dependency as a shared library, but due to build errors with Firefox that I couldn't resolve I decided that two more files to copy aren't really an issue. 

Now you only need to tell Firefox that it should really use the fido.cpp file, therefore you need to add this entry `"fido.cpp",` to the `UNIFIED_SOURCES` array (this needs to be in alphabetical order, so it needs to be at the right place, otherwise you'll get an error) in the moz.build file (still inside the dom/webauthn folder).

Nearly there. At the end of the moz.build file you need to add those two lines: 
```
CXXFLAGS += ['-I/usr/include/dbus-1.0', '-I/usr/lib/x86_64-linux-gnu/dbus-1.0/include']
LDFLAGS += ['-ldbus-1']
```
to tell firefox about the dbus dependency.

The last step is to install this dependency, for Ubuntu/Debian based distros run: 
```
sudo apt install libdbus-1-dev
```

Afterwards you can change directory to the base Firefox directory and run `./mach build` and `./mach run`. If you now visit either `https://localhost:3000` (if you are running the webauthn-test-server like described in the base repository) or `https://webauthn.io` you should be able to make use of the DBUS functionality within Firefox. 

## DISCLAIMER
If you are using `https://webauthn.io` Firefox will prompt you with a request to access your tokens upon load, I have not figured out what check they have in place in the baseline implementation (the request still happens in baseline Firefox, it is just seemingly ignored), so you can just close this request / ignore it.