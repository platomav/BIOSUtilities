# BIOSUtilities [Refactor - WIP]
**Various BIOS Utilities for Modding/Research**

[BIOS Utilities News Feed](https://twitter.com/platomaniac)

* [**AMI BIOS Guard Extractor**](#ami-bios-guard-extractor)
* [**AMI UCP Update Extractor**](#ami-ucp-update-extractor)
* [**Dell PFS Update Extractor**](#dell-pfs-update-extractor)
* [**Panasonic BIOS Package Extractor**](#panasonic-bios-package-extractor)
* [**Phoenix TDK Packer Extractor**](#phoenix-tdk-packer-extractor)
* [**Portwell EFI Update Extractor**](#portwell-efi-update-extractor)
* [**VAIO Packaging Manager Extractor**](#vaio-packaging-manager-extractor)

## **AMI BIOS Guard Extractor**

![]()

#### **Description**

Parses AMI BIOS Guard (a.k.a. PFAT, Platform Firmware Armoring Technology) images, extracts their SPI/BIOS/UEFI firmware components and decompiles the Intel BIOS Guard Scripts. It supports all AMI PFAT revisions and formats, including those with Index Information tables or nested AMI PFAT structures. The output comprises only final firmware components which are directly usable by end users.

Note that the AMI PFAT structure may not have an explicit component order. AMI's BIOS Guard Firmware Update Tool (AFUBGT) updates components based on the user/OEM provided Parameters and Options or Index Information table, when applicable. That means that merging all the components together does not usually yield a proper SPI/BIOS/UEFI image. The utility does generate such a merged file with the name "00 -- \<filename\>\_ALL.bin" but it is up to the end user to determine its usefulness. Moreover, any custom OEM data after the AMI PFAT structure are additionally stored in the last file with the name "\<n+1\> -- \_OOB.bin" and it is once again up to the end user to determine its usefulness. In cases where the trailing custom OEM data include a nested AMI PFAT structure, the utility will process and extract it automatically as well.

#### **Usage**

You can either Drag & Drop or manually enter AMI BIOS Guard (PFAT) image file(s). Optional arguments:
  
* -h or --help : show help message and exit
* -v or --version : show utility name and version
* -i or --input-dir : extract from given input directory
* -o or --output-dir : extract in given output directory
* -e or --auto-exit : skip press enter to exit prompts

#### **Compatibility**

Should work at all Windows, Linux or macOS operating systems which have Python 3.8 support.

#### **Prerequisites**

Optionally, to decompile the AMI PFAT \> Intel BIOS Guard Scripts, you must have the following 3rd party utility at the "external" project directory:

* [BIOS Guard Script Tool](https://github.com/platomav/BGScriptTool) (i.e. big_script_tool.py)

#### **Build/Freeze/Compile with PyInstaller**

PyInstaller can build/freeze/compile the utility at all three supported platforms, it is simple to run and gets updated often.

1. Make sure Python 3.8.0 or newer is installed:

> python --version

2. Use pip to install PyInstaller:

> pip3 install pyinstaller

3. Place prerequisites at the "external" project directory:

> BIOS Guard Script Tool (optional)

4. Build/Freeze/Compile:

> pyinstaller --add-data="external/*;external/" --noupx --onefile \<path-to-project\>\/AMI_PFAT_Extract.py

You should find the final utility executable at "dist" folder

#### **Anti-Virus False Positives**

Some Anti-Virus software may claim that the built/frozen/compiled executable contains viruses. Any such detections are false positives, usually of PyInstaller. You can switch to a better Anti-Virus software, report the false positive to their support, add the executable to the exclusions, build/freeze/compile yourself or use the Python script directly.

#### **Pictures**

![]()

## **AMI UCP Update Extractor**

![]()

#### **Description**

Parses AMI UCP (Utility Configuration Program) Update executables, extracts their firmware components (e.g. SPI/BIOS/UEFI, EC, ME etc) and shows all relevant info. It supports all AMI UCP revisions and formats, including those with nested AMI PFAT, AMI UCP or Insyde SFX structures. The output comprises only final firmware components and utilities which are directly usable by end users.

#### **Usage**

You can either Drag & Drop or manually enter AMI UCP Update executable file(s). Optional arguments:
  
* -h or --help : show help message and exit
* -v or --version : show utility name and version
* -i or --input-dir : extract from given input directory
* -o or --output-dir : extract in given output directory
* -e or --auto-exit : skip press enter to exit prompts
* -c or --checksum : verify AMI UCP Checksums (slow)

#### **Compatibility**

Should work at all Windows, Linux or macOS operating systems which have Python 3.8 support.

#### **Prerequisites**

To run the utility, you must have the following 3rd party tools at the "external" project directory:

* [TianoCompress](https://github.com/tianocore/edk2/tree/master/BaseTools/Source/C/TianoCompress/) (e.g. [TianoCompress.exe for Windows](https://github.com/tianocore/edk2-BaseTools-win32/) or TianoCompress for Linux)
* [7-Zip Console](https://www.7-zip.org/) (i.e. 7z.exe for Windows or 7zzs for Linux)

Optionally, to decompile the AMI UCP \> AMI PFAT \> Intel BIOS Guard Scripts (when applicable), you must have the following 3rd party utility at the "external" project directory:

* [BIOS Guard Script Tool](https://github.com/platomav/BGScriptTool) (i.e. big_script_tool.py)

#### **Build/Freeze/Compile with PyInstaller**

PyInstaller can build/freeze/compile the utility at all three supported platforms, it is simple to run and gets updated often.

1. Make sure Python 3.8.0 or newer is installed:

> python --version

2. Use pip to install PyInstaller:

> pip3 install pyinstaller

3. Place prerequisites at the "external" project directory:

> TianoCompress\
> 7-Zip Console\
> BIOS Guard Script Tool (optional)

4. Build/Freeze/Compile:

> pyinstaller --add-data="external/*;external/" --noupx --onefile \<path-to-project\>\/AMI_UCP_Extract.py

You should find the final utility executable at "dist" folder

#### **Anti-Virus False Positives**

Some Anti-Virus software may claim that the built/frozen/compiled executable contains viruses. Any such detections are false positives, usually of PyInstaller. You can switch to a better Anti-Virus software, report the false positive to their support, add the executable to the exclusions, build/freeze/compile yourself or use the Python script directly.

#### **Pictures**

![]()

## **Dell PFS Update Extractor**

![]()

#### **Description**

Parses Dell PFS Update images and extracts their Firmware (e.g. SPI, BIOS/UEFI, EC, ME etc) and Utilities (e.g. Flasher etc) component sections. It supports all Dell PFS revisions and formats, including those which are originally LZMA compressed in ThinOS packages, ZLIB compressed or Intel BIOS Guard (PFAT) protected. The output comprises only final firmware components which are directly usable by end users.

#### **Usage**

You can either Drag & Drop or manually enter Dell PFS Update images(s). Optional arguments:
  
* -h or --help : show help message and exit
* -v or --version : show utility name and version
* -i or --input-dir : extract from given input directory
* -o or --output-dir : extract in given output directory
* -e or --auto-exit : skip press enter to exit prompts
* -a or --advanced : extract signatures and metadata
* -s or --structure : show PFS structure information

#### **Compatibility**

Should work at all Windows, Linux or macOS operating systems which have Python 3.8 support.

#### **Prerequisites**

Optionally, to decompile the Intel BIOS Guard (PFAT) Scripts, you must have the following 3rd party utility at the "external" project directory:

* [BIOS Guard Script Tool](https://github.com/platomav/BGScriptTool) (i.e. big_script_tool.py)

#### **Build/Freeze/Compile with PyInstaller**

PyInstaller can build/freeze/compile the utility at all three supported platforms, it is simple to run and gets updated often.

1. Make sure Python 3.8.0 or newer is installed:

> python --version

2. Use pip to install PyInstaller:

> pip3 install pyinstaller

3. Place prerequisites at the "external" project directory:

> BIOS Guard Script Tool (optional)

4. Build/Freeze/Compile:

> pyinstaller --add-data="external/*;external/" --noupx --onefile \<path-to-project\>\/Dell_PFS_Extract.py

You should find the final utility executable at "dist" folder

#### **Anti-Virus False Positives**

Some Anti-Virus software may claim that the built/frozen/compiled executable contains viruses. Any such detections are false positives, usually of PyInstaller. You can switch to a better Anti-Virus software, report the false positive to their support, add the executable to the exclusions, build/freeze/compile yourself or use the Python script directly.

#### **Pictures**

![]()

## **Panasonic BIOS Package Extractor**

![]()

#### **Description**

Parses Panasonic BIOS Package executables and extracts their firmware (e.g. SPI, BIOS/UEFI, EC etc) and utilities (e.g. winprom, configuration etc) components. It supports all Panasonic BIOS Package revisions and formats, including those which contain LZNT1 compressed files. The output comprises only final firmware components which are directly usable by end users.

#### **Usage**

You can either Drag & Drop or manually enter Panasonic BIOS Package executable file(s). Optional arguments:
  
* -h or --help : show help message and exit
* -v or --version : show utility name and version
* -i or --input-dir : extract from given input directory
* -o or --output-dir : extract in given output directory
* -e or --auto-exit : skip press enter to exit prompts

#### **Compatibility**

Should work at all Windows, Linux or macOS operating systems which have Python 3.8 support.

#### **Prerequisites**

To run the utility, you must have the following 3rd party Python modules installed:

* [pefile](https://pypi.org/project/pefile/)
* [lznt1](https://pypi.org/project/lznt1/)

Moreover, you must have the following 3rd party tool at the "external" project directory:

* [7-Zip Console](https://www.7-zip.org/) (i.e. 7z.exe for Windows or 7zzs for Linux)

#### **Build/Freeze/Compile with PyInstaller**

PyInstaller can build/freeze/compile the utility at all three supported platforms, it is simple to run and gets updated often.

1. Make sure Python 3.8.0 or newer is installed:

> python --version

2. Use pip to install PyInstaller:

> pip3 install pyinstaller

3. Use pip to install pefile and lznt1:

> pip3 install pefile lznt1

4. Place prerequisite at the "external" project directory:

> 7-Zip Console

5. Build/Freeze/Compile:

> pyinstaller --add-data="external/*;external/" --noupx --onefile \<path-to-project\>\/Panasonic_BIOS_Extract.py

At dist folder you should find the final utility executable

#### **Anti-Virus False Positives**

Some Anti-Virus software may claim that the built/frozen/compiled executable contains viruses. Any such detections are false positives, usually of PyInstaller. You can switch to a better Anti-Virus software, report the false positive to their support, add the executable to the exclusions, build/freeze/compile yourself or use the Python script directly.

#### **Pictures**

![]()

## **Phoenix TDK Packer Extractor**

![]()

#### **Description**

Parses Phoenix Tools Development Kit (TDK) Packer executables and extracts their firmware (e.g. SPI, BIOS/UEFI, EC etc) and utilities (e.g. WinFlash etc) components. It supports all Phoenix TDK Packer revisions and formats, including those which contain LZMA compressed files. The output comprises only final firmware components which are directly usable by end users.

#### **Usage**

You can either Drag & Drop or manually enter Phoenix Tools Development Kit (TDK) Packer executable file(s). Optional arguments:
  
* -h or --help : show help message and exit
* -v or --version : show utility name and version
* -i or --input-dir : extract from given input directory
* -o or --output-dir : extract in given output directory
* -e or --auto-exit : skip press enter to exit prompts

#### **Compatibility**

Should work at all Windows, Linux or macOS operating systems which have Python 3.8 support.

#### **Prerequisites**

To run the utility, you must have the following 3rd party Python module installed:

* [pefile](https://pypi.org/project/pefile/)

#### **Build/Freeze/Compile with PyInstaller**

PyInstaller can build/freeze/compile the utility at all three supported platforms, it is simple to run and gets updated often.

1. Make sure Python 3.8.0 or newer is installed:

> python --version

2. Use pip to install PyInstaller:

> pip3 install pyinstaller

3. Use pip to install pefile:

> pip3 install pefile

4. Build/Freeze/Compile:

> pyinstaller --noupx --onefile \<path-to-project\>\/Phoenix_TDK_Extract.py

At dist folder you should find the final utility executable

#### **Anti-Virus False Positives**

Some Anti-Virus software may claim that the built/frozen/compiled executable contains viruses. Any such detections are false positives, usually of PyInstaller. You can switch to a better Anti-Virus software, report the false positive to their support, add the executable to the exclusions, build/freeze/compile yourself or use the Python script directly.

#### **Pictures**

![]()

## **Portwell EFI Update Extractor**

![]()

#### **Description**

Parses Portwell UEFI Unpacker EFI executables (usually named "Update.efi") and extracts their firmware (e.g. SPI, BIOS/UEFI, EC etc) and utilities (e.g. Flasher etc) components. It supports all known Portwell UEFI Unpacker revisions (v1.1, v1.2, v2.0) and formats (used, empty, null), including those which contain EFI compressed files. The output comprises only final firmware components and utilities which are directly usable by end users.

#### **Usage**

You can either Drag & Drop or manually enter Portwell UEFI Unpacker EFI executable file(s). Optional arguments:
  
* -h or --help : show help message and exit
* -v or --version : show utility name and version
* -i or --input-dir : extract from given input directory
* -o or --output-dir : extract in given output directory
* -e or --auto-exit : skip press enter to exit prompts

#### **Compatibility**

Should work at all Windows, Linux or macOS operating systems which have Python 3.8 support.

#### **Prerequisites**

To run the utility, you must have the following 3rd party Python module installed:

* [pefile](https://pypi.org/project/pefile/)

> pip3 install pefile

Moreover, you must have the following 3rd party tool at the "external" project directory:

* [TianoCompress](https://github.com/tianocore/edk2/tree/master/BaseTools/Source/C/TianoCompress/) (e.g. [TianoCompress.exe for Windows](https://github.com/tianocore/edk2-BaseTools-win32/) or TianoCompress for Linux)

#### **Build/Freeze/Compile with PyInstaller**

PyInstaller can build/freeze/compile the utility at all three supported platforms, it is simple to run and gets updated often.

1. Make sure Python 3.8.0 or newer is installed:

> python --version

2. Use pip to install PyInstaller:

> pip3 install pyinstaller

3. Use pip to install pefile:

> pip3 install pefile

4. Place prerequisite at the "external" project directory:

> TianoCompress

5. Build/Freeze/Compile:

> pyinstaller --add-data="external/*;external/" --noupx --onefile \<path-to-project\>\/Portwell_EFI_Extract.py

You should find the final utility executable at "dist" folder

#### **Anti-Virus False Positives**

Some Anti-Virus software may claim that the built/frozen/compiled executable contains viruses. Any such detections are false positives, usually of PyInstaller. You can switch to a better Anti-Virus software, report the false positive to their support, add the executable to the exclusions, build/freeze/compile yourself or use the Python script directly.

#### **Pictures**

![]()

## **VAIO Packaging Manager Extractor**

![]()

#### **Description**

Parses VAIO Packaging Manager executables and extracts their firmware (e.g. SPI, BIOS/UEFI, EC, ME etc), utilities (e.g. WBFLASH etc) and driver (audio, video etc) components. If direct extraction fails, it attempts to unlock the executable in order to run at all non-VAIO systems and allow the user to choose the extraction location. It supports all VAIO Packaging Manager revisions and formats, including those which contain obfuscated Microsoft CAB archives or obfuscated unlock values. The output comprises only final firmware components which are directly usable by end users.

#### **Usage**

You can either Drag & Drop or manually enter VAIO Packaging Manager executable file(s). Optional arguments:
  
* -h or --help : show help message and exit
* -v or --version : show utility name and version
* -i or --input-dir : extract from given input directory
* -o or --output-dir : extract in given output directory
* -e or --auto-exit : skip press enter to exit prompts

#### **Compatibility**

Should work at all Windows, Linux or macOS operating systems which have Python 3.8 support.

#### **Prerequisites**

To run the utility, you do not need any prerequisites.

#### **Build/Freeze/Compile with PyInstaller**

PyInstaller can build/freeze/compile the utility at all three supported platforms, it is simple to run and gets updated often.

1. Make sure Python 3.8.0 or newer is installed:

> python --version

2. Use pip to install PyInstaller:

> pip3 install pyinstaller

3. Build/Freeze/Compile:

> pyinstaller --noupx --onefile \<path-to-project\>\/VAIO_Package_Extract.py

At dist folder you should find the final utility executable

#### **Anti-Virus False Positives**

Some Anti-Virus software may claim that the built/frozen/compiled executable contains viruses. Any such detections are false positives, usually of PyInstaller. You can switch to a better Anti-Virus software, report the false positive to their support, add the executable to the exclusions, build/freeze/compile yourself or use the Python script directly.

#### **Pictures**

![]()