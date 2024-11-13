 # FortisApplet

## Build From Source
###### The following has been tested on Arch Linux using OpenJDK 11.0.8 and GlobalPlatformPro 0.2.0
```
# Clone FortisApplet
git clone --recursive https://github.com/FortisCard/fortis-java-card-applet.git
cd fortis-java-card-applet

# Build math library
pushd lib/JCMathLib && python3 package.py -c SecP256k1 -p 'com.fortis' -o ../../src/com/fortis/jcmathlib.java && popd

# Build CAP file
ant

# Load onto FortisCard (requires GlobalPlatformPro)
gpp -install build/fortis-1.0.0.cap
```
