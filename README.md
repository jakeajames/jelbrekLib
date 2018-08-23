# jelbrekLib
Give me tfp0, I give you jelbrek

Library with commonly used patches in open-source jailbreaks. Call this a (light?) QiLin open-source alternative.
h
# Compiling:

    ./make.sh
    
# Setup

- Compile OR ead over to https://github.com/jakeajames/jelbrekLib/tree/master/downloads and get everything there. 
- Link with jelbrekLib.a & IOKit.tbd and include jelbrekLib.h
- Call init_jelbrek() with tfp0 as your first thing and term_jelbrek() as your last

# Issues

- Not everything tested, but stuff should work
- AMFID patch won't resist after app enters background. Fix would be using a daemon (like amfidebilitate; well one is coming soon, open-source ;D) or injecting a dylib

# Credits

- theninjaprawn & xerub for patchfinding
- xerub & Electra team for trustcache injection
- stek29 for nvramunlock & lock and hsp4 patch
- theninjaprawn & Ian Beer for dylib injection
- Luca Todesco for the remount patch technique
- Umang Raghuvanshi for the original remount idea
- pwn20wnd for the implementation of the rename-APFS-snapshot technique
- AMFID dylib-less patch technique by Ian Beer reworked with the patch code from Electra's amfid_payload (stek29 & coolstar)
- Symbol finding by me ;) https://github.com/jakeajames/kernelSymbolFinder
- The rest of patches are fairly simple and shouldn't be considered property of anyone in my opinion. Everyone who has enough knowledge can write them fairly easily

And, don't forget to tell me if I forgot to credit anyone!
