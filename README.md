# jelbrekLib
Give me tfp0, I give you jelbrek

Library with commonly used patches in open-source jailbreaks. Call this a (light?) QiLin open-source alternative.

# Compiling:

    ./make.sh
    
# Normal setup

- Head over to https://github.com/jakeajames/jelbrekLib/tree/master/downloads, get everything there. Link with jelbrekLib.a & IOKit.tbd and include jelbrekLib.h
- Call init_jelbrek() with tfp0 as your first thing and term_jelbrek() as your last

# Issues

- Not everything tested
- This conflicts with almost every possible exploit from Ian Beer or fork of it due to similar naming. If that happens remove every patch except the tfp0 variable (don't name it 'tfp0') or rename the functions in either the project or library
