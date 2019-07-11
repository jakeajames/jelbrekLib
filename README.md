# jelbrekLib
Give me tfp0, I give you jelbrek

Library with commonly used patches in open-source jailbreaks. Call this a (light?) QiLin open-source alternative.

# Compiling:

./make.sh

# Setup

- Compile OR head over to https://github.com/jakeajames/jelbrekLib/tree/master/downloads and get everything there.
- Link with jelbrekLib.dylib and include jelbrekLib.h
- Call init_jelbrek() with tfp0, as your first thing and term_jelbrek(), as your last

# Issues
- AMFID patch won't resist after app enters background. Fix would be using a daemon (like amfidebilitate) or injecting a dylib (iOS 11)

# iOS 12 status
- ~~rootFS remount is broken. There is hardening on snapshot_rename() which *can* and *has* been (privately) bypassed, but it for sure isn't as bad as last year with iOS 11.3.1, where they made **major** changes. The only thing we need is figuring out how they check if the snapshot is the rootfs and not something in /var for example where snapshot_rename works fine.~~ Use unc0ver's code if you need the remount, I will probably add it along some bigger update

# Credits

- xerub for the original patchfinding code
- theninjaprawn for some patchfinders
- xerub for the original trustcache injection technique
- stek29 for nvramunlock & lock and hsp4 patch
- theninjaprawn & Ian Beer for dylib injection
- Luca Todesco for the original remount patch technique
- Umang Raghuvanshi for the rename-APFS-snapshot remount idea
- pwn20wnd for the oiriginal implementation of the rename-APFS-snapshot technique
- AMFID dylib-less patch technique by Ian Beer reworked with the patch code from Electra's amfid_payload (stek29 & coolstar)
- rootless-hsp4 idea by Ian Beer. Implemented on his updated async_wake exploit
- Sandbox exceptions by stek29 (https://stek29.rocks/2018/01/26/sandbox.html) (& a few fixes by me for iOS 12+)
- CSBlob patching with stuff from Jonathan Levin and xerub
- Symbol finding (https://github.com/jakeajames/kernelSymbolFinder) & the CoreTrust bypass technique by me ;)
- The rest of patches are fairly simple and shouldn't be considered property of anyone in my opinion. Everyone who has enough knowledge can write them fairly easily

And, don't forget to tell me if I forgot to credit anyone!

