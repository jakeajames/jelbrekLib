# jelbrekLib
Give me tfp0, I give you jelbrek

Library with commonly used patches in open-source jailbreaks. Call this a (light?) QiLin open-source alternative.

# Compiling:

    ./make.sh
    
# Setup

- Compile OR head over to https://github.com/jakeajames/jelbrekLib/tree/master/downloads and get everything there. 
- Link with jelbrekLib.a & IOKit.tbd and include jelbrekLib.h
- Call init_jelbrek() with tfp0 as your first thing and term_jelbrek() as your last

# Issues
- AMFID patch won't resist after app enters background. Fix would be using a daemon (like amfidebilitate) or injecting a dylib (iOS 11)

# iOS 12 satus
- trustbin() is broken (will panic immediately after). Probably because of a bad patchfinder. (I get a valid pointer but if I do rk64(ptr) I get 0xXXXXXXXXfeedfacf)
- rootFS remount is broken. There is hardening on snapshot_rename() which *can* and *has* been (privately) bypassed, but it for sure isn't as bad as last year with iOS 11.3.1, where they made **major** changes. The only thing we need is figuring out how they check if the snapshot is the rootfs and not something in /var for example where snapshot_rename works fine.
- task_for_pid() is broken too, which means inject_dylib() and patchAMFID() are as well. Now, task_for_pid() *does* work if you get the right entitlements **but** you won't be able to do anything with the task port it gives you, whether you're platform, you've injected get-task-allow to target or whatever. I am entirely lost on what causes this, the error isn't informative either, "Invalid argument". I've so far tried doing this with launchd, amfid & SpringBoard, all give the same error. I should try it with an App Store app to see if it works, if it does, they're most likely adding some kind of protection to all system daemons. If it doesn't, then I don't know, I'm not doing it correctly perhaps??
- kexecute() is also probably broken on A12. Use bazad's PAC bypass which offers the same thing, so this isn't an issue (fr now)
- getting root, unsandboxing, NVRAM lock/unlock, setHSP4() are all working fine (yeh, but they're useless if you wanna do cool things). The rest that is not on top of my mind should also work fine.

## Codesign bypass
- Patching amfid should be a matter of getting task_for_pid() working. (Note: on A12 you need to take a completely different approach, bazad has proposed an amfid-patch-less-amfid-bypass in here https://github.com/bazad/blanket/tree/master/amfidupe, which will probably work but don't take my word for it). As for the payload dylib, you can just sign it with a legit cert and nobody will complain about the signature. As for unsigned binaries, you'll probably have to sign them with a legit cert as well, due to CoreTrust.

# Credits

- theninjaprawn & xerub for patchfinding
- xerub & Electra team for trustcache injection
- stek29 for nvramunlock & lock and hsp4 patch
- theninjaprawn & Ian Beer for dylib injection
- Luca Todesco for the remount patch technique
- Umang Raghuvanshi for the original remount idea
- pwn20wnd for the implementation of the rename-APFS-snapshot technique
- AMFID dylib-less patch technique by Ian Beer reworked with the patch code from Electra's amfid_payload (stek29 & coolstar)
- rootless-hsp4 idea by Ian Beer. Implemented on his updated async_wake exploit
- Sandbox exceptions by stek29 (https://stek29.rocks/2018/01/26/sandbox.html)
- CSBlob patching with stuff from Jonathan Levin and xerub
- Symbol finding by me ;) (https://github.com/jakeajames/kernelSymbolFinder)
- The rest of patches are fairly simple and shouldn't be considered property of anyone in my opinion. Everyone who has enough knowledge can write them fairly easily

And, don't forget to tell me if I forgot to credit anyone!
