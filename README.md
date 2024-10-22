
# Lemmo One Reverse Engineering
The Lemmo One from lemmofuture.com seems to be based on Tuya SDK.  
The following was tested with MK2 model.  
The goal was mostly being able to unlock the bike even if the servers eventually were to disappear.  
I really wish these were more open, but well...  

## Involved Keys in Cloud communication
These are relevant for communication with the Cloud API, https://a1.tuyaeu.com/api.json .

## appName ("com.lemo.mobile")

### appId (`3wty5tnsvhfakgtffg5y`) THING_SMART_APPKEY
from AndroidManifest.xml

### appSecret (`vg7fcrp7ujgwvumjx5pewas45gt8urma`) THING_SMART_SECRET
from AndroidManifest.xml

### certSignerHash (`D3:D4:7D:AF:2A:5B:EF:9F:5C:6A:69:06:2F:A8:DE:12:A0:E8:E9:18:A5:B4:14:88:D2:CE:7A:36:B3:B8:1A:DA`)
Signer #1 certificate SHA-256 digest of `config.arm64_v8a.apk`:  
`apksigner.bat verify --print-certs` or `keytool -printcert -jarfile config.arm64_v8a.apk`

### bmpKey? (`jejmv339k7q3s7dg3rmw7m3h55vx3vxs`)
TODO: How to get without just dumping memory?
See below Frida Dumping(1).

## ecode? (`99***************`)
TODO: How to get without just dumping memory? No idea what this param even is - likely token or login related?  
Not sure this is even called ecode, just saw it somewhere named like that and reused that.
See below Frida Dumping(1).

## Involved Keys in BLE communication
Some of these might change after logging in/out or reregistering the bike.

### ADDRESS ("**:**:**:**:**:**")
Can be get through the app, top-right info, details, Mac (3d from top).

### UUID (`45**************\0\0\0\0\0\0\0\0`)
Can be get through the app, top-right info, details, UUID (2nd from top).

### (Bike) devId (`bf***************`)
Can be get through the app, top-right info, details, Virtual ID (topmost).  
(The smartpac has its own devId that is longer but also visible through the SmartPac page in the app)

### loginKey (`***********`)
Alphanumeric including special chars. Only first 6 chars used.
This local key is determined from server-side and session-specific.  
Easiest way to get this is through FRIDA through any function accessing it, like getSecretKey5.  
Ssee Frida Dumping (2).


## Frida Dumping(1) until more reversed...
[F] https://github.com/Nightbringer21/fridump  
```
$ py fridump.py -U LEMMO
$ strings * | grep vg7fcrp7ujgwvumjx5pewas45gt8urma
```
From there you get multiple matches, like:
`com.lemo.mobile_D3:D4:7D:AF:2A:5B:EF:9F:5C:6A:69:06:2F:A8:DE:12:A0:E8:E9:18:A5:B4:14:88:D2:CE:7A:36:B3:B8:1A:DA_jejmv339k7q3s7dg3rmw7m3h55vx3vxs_vg7fcrp7ujgwvumjx5pewas45gt8urma`  
This `appId_certSignerHash_bmpKey_appSecret` is the HMAC-SHA256 key that is used for login requests, request signing and what I call "session-less" things.

The output also contains some other (maybe partial lines without suffix) with another `_99**************` suffix part containing the ecode.  
So for "session" things (cloud API things like querying versions, ...) the HMAC-SHA256 key includes that, so  `appId_certSignerHash_bmpKey_appSecret_ecode`. 

## Frida Dumping (2)
Frida can also be used to dump the local login key the app knows.
It will be dumped after `loginKeyComplete` output in the log when using something like the snippet below.
```
Java.perform(function() {
    Java.use("com.thingclips.sdk.bluetooth.ddbpqbb").getSecretKey5.implementation = function() {
        console.log("getSecretKey5 loginKeyComplete", this.getConnectParam().loginKeyComplete.value, "srand", this.getConnectParam().secretKey.value);
        return this.getSecretKey5();
    };
});
```

# Similar work and inspirations
[1] https://github.com/nalajcie/tuya-sign-hacking/tree/master  
[2] https://blog.rgsilva.com/reverse-engineering-positivos-smart-home-app/  
[3] https://gist.github.com/bahorn/9bebbbf37c2167f7057aea0244ff2d92  
[4] https://gist.github.com/Staars/70eb319dc1143d2a1176ad766d14689e  
[5] https://gist.github.com/bahorn/9bebbbf37c2167f7057aea0244ff2d92?permalink_comment_id=3981562 (missing chKey field for signature but if added works)
