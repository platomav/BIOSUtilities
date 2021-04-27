# BIOSUtilities
**Various BIOS Utilities for Modding/Research**

[BIOS Utilities News Feed](https://twitter.com/platomaniac)

<a href="https://www.paypal.com/cgi-bin/webscr?cmd=_s-xclick&hosted_button_id=DJDZD3PRGCSCL"><img border="0" title="BIOS Utilities Donation via Paypal or Debit/Credit Card" alt="BIOS Utilities Donation via Paypal or Debit/Credit Card" src="https://user-images.githubusercontent.com/11527726/109392268-e0f68280-7923-11eb-83d8-0a63f0d20783.png"></a>

## **Dell PFS BIOS Extractor**

![](https://i.imgur.com/Oy1IkcW.png)

#### **Description**

Parses Dell PFS BIOS images and extracts their SPI/BIOS/UEFI firmware components. It supports all Dell PFS revisions and formats, including those which are originally LZMA compressed in ThinOS packages, ZLIB compressed or split in chunks. The output comprises only final firmware components which are directly usable by end users. An optional Advanced user mode is available as well, which additionally extracts firmware Signatures and more Metadata.

#### **Usage**

You can either Drag & Drop or manually enter the full path of a folder containing Dell PFS BIOS images. Optional arguments:
  
* -h or --help : show help message and exit
* -a or --advanced : extract in advanced user mode

#### **Download**

An already built/frozen/compiled binary is provided by me for Windows only. Thus, **you don't need to manually build/freeze/compile it under Windows**. Instead, download the latest version from the [Releases](https://github.com/platomav/BIOSUtilities/releases) tab. To extract the already built/frozen/compiled archive, you need to use programs which support RAR5 compression. Note that you need to manually apply any prerequisites.

#### **Compatibility**

Should work at all Windows, Linux or macOS operating systems which have Python 3.7 support. Windows users who plan to use the already built/frozen/compiled binary must make sure that they have the latest Windows Updates installed which include all required "Universal C Runtime (CRT)" libraries.

#### **Prerequisites**

To run the utility, you do not need any 3rd party tool.

#### **Build/Freeze/Compile with PyInstaller**

PyInstaller can build/freeze/compile the utility at all three supported platforms, it is simple to run and gets updated often.

1. Make sure Python 3.7.0 or newer is installed:

> python --version

2. Use pip to install PyInstaller:

> pip3 install pyinstaller

3. Build/Freeze/Compile:

> pyinstaller --noupx --onefile Dell_PFS_Extract.py

At dist folder you should find the final utility executable

#### **Anti-Virus False Positives**

Some Anti-Virus software may claim that the built/frozen/compiled executable contains viruses. Any such detections are false positives, usually of PyInstaller. You can switch to a better Anti-Virus software, report the false positive to their support, add the executable to the exclusions, build/freeze/compile yourself or use the Python script directly.

#### **Pictures**

![](https://i.imgur.com/LCsUknA.png)

## **AMI BIOS Guard Extractor**

![](https://i.imgur.com/p0rrlqv.png)

#### **Description**

Parses AMI BIOS Guard (a.k.a. PFAT, Platform Firmware Armoring Technology) images, extracts their SPI/BIOS/UEFI firmware components and decompiles the Intel BIOS Guard Scripts. It supports all AMI PFAT revisions and formats, including those with nested AMI PFAT structures. The output comprises only final firmware components which are directly usable by end users.

Note that the AMI PFAT structure does not have an explicit component order. AMI's BIOS Guard Firmware Update Tool (AFUBGT) updates components based on the user/OEM provided Parameters and Options. That means that merging all the components together does not usually yield a proper SPI/BIOS/UEFI image. The utility does generate such a merged file with the name "X_00 -- AMI_PFAT_X_DATA_ALL.bin" but it is up to the end user to determine its usefulness. Moreover, any custom OEM data after the AMI PFAT structure are additionally stored in a file with the name "X_YY -- AMI_PFAT_X_DATA_END.bin" and it is once again up to the end user to determine its usefulness. In cases where the trailing custom OEM data include a nested AMI PFAT structure, the utility will process and extract it automatically as well.

#### **Usage**

You can either Drag & Drop or manually enter the full path of a folder containing AMI BIOS Guard (PFAT) images.

#### **Download**

An already built/frozen/compiled binary is provided by me for Windows only. Thus, **you don't need to manually build/freeze/compile it under Windows**. Instead, download the latest version from the [Releases](https://github.com/platomav/BIOSUtilities/releases) tab. To extract the already built/frozen/compiled archive, you need to use programs which support RAR5 compression. Note that you need to manually apply any prerequisites.

#### **Compatibility**

Should work at all Windows, Linux or macOS operating systems which have Python 3.7 support. Windows users who plan to use the already built/frozen/compiled binary must make sure that they have the latest Windows Updates installed which include all required "Universal C Runtime (CRT)" libraries.

#### **Prerequisites**

To decompile the Intel BIOS Guard Scripts via the Python script, you need to additionally have the following 3rd party Python utility at the same directory:

* [BIOS Guard Script Tool](https://github.com/allowitsme/big-tool/tree/sdk-compat) (i.e. big_script_tool.py)

#### **Build/Freeze/Compile with PyInstaller**

PyInstaller can build/freeze/compile the utility at all three supported platforms, it is simple to run and gets updated often.

1. Make sure Python 3.7.0 or newer is installed:

> python --version

2. Use pip to install PyInstaller:

> pip3 install pyinstaller

3. Copy BIOS Guard Script Tool dependency to build directory:

> AMI_PFAT_Extract.py, big_script_tool.py

4. Build/Freeze/Compile:

> pyinstaller --noupx --onefile AMI_PFAT_Extract.py

At dist folder you should find the final utility executable

#### **Anti-Virus False Positives**

Some Anti-Virus software may claim that the built/frozen/compiled executable contains viruses. Any such detections are false positives, usually of PyInstaller. You can switch to a better Anti-Virus software, report the false positive to their support, add the executable to the exclusions, build/freeze/compile yourself or use the Python script directly.

#### **Pictures**

![](https://i.imgur.com/iZD3GY0.png)

## **Apple EFI Sucatalog Link Grabber**

![](https://i.imgur.com/zTVFs4I.png)

#### **Description**

Parses Apple Software Update CatalogURL .sucatalog files and saves all EFI firmware package links into a text file. It removes any xml formatting, ignores false positives, removes duplicate links and sorts them in alphabetical order for easy comparison afterwards.

#### **Usage**

You can either Drag & Drop or let it automatically parse any .sucatalog files within its working directory.

#### **Download**

An already built/frozen/compiled binary is provided by me for Windows only. Thus, **you don't need to manually build/freeze/compile it under Windows**. Instead, download the latest version from the [Releases](https://github.com/platomav/BIOSUtilities/releases) tab. To extract the already built/frozen/compiled archive, you need to use programs which support RAR5 compression. Note that you need to manually apply any prerequisites.

#### **Compatibility**

Should work at all Windows, Linux or macOS operating systems which have Python 3.7 support. Windows users who plan to use the already built/frozen/compiled binary must make sure that they have the latest Windows Updates installed which include all required "Universal C Runtime (CRT)" libraries.

#### **Prerequisites**

To run the utility, you do not need any 3rd party tool.

#### **Build/Freeze/Compile with PyInstaller**

PyInstaller can build/freeze/compile the utility at all three supported platforms, it is simple to run and gets updated often.

1. Make sure Python 3.7.0 or newer is installed:

> python --version

2. Use pip to install PyInstaller:

> pip3 install pyinstaller

3. Build/Freeze/Compile:

> pyinstaller --noupx --onefile Apple_EFI_Links.py

At dist folder you should find the final utility executable

#### **Anti-Virus False Positives**

Some Anti-Virus software may claim that the built/frozen/compiled executable contains viruses. Any such detections are false positives, usually of PyInstaller. You can switch to a better Anti-Virus software, report the false positive to their support, add the executable to the exclusions, build/freeze/compile yourself or use the Python script directly.

## **Apple EFI File Renamer**

![](https://i.imgur.com/mWGhWja.png)

#### **Description**

Parses Apple EFI files and renames them based on Intel's official $IBIOSI$ tag as follows: Model_Version_Build_Year_Month_Day_Hour_Minute_Checksum. The checksum is calculated and added by the utility in order to differentiate any EFI files with the same $IBIOSI$ tag. In rare cases in which the $IBIOSI$ tag is compressed, the utility automatically first uses [LongSoft's UEFIFind and UEFIExtract](https://github.com/LongSoft/UEFITool) tools.

#### **Usage**

You can either Drag & Drop or manually enter the full path of a folder containing Apple EFI firmware.

#### **Download**

An already built/frozen/compiled binary is provided by me for Windows only. Thus, **you don't need to manually build/freeze/compile it under Windows**. Instead, download the latest version from the [Releases](https://github.com/platomav/BIOSUtilities/releases) tab. To extract the already built/frozen/compiled archive, you need to use programs which support RAR5 compression. Note that you need to manually apply any prerequisites.

#### **Compatibility**

Should work at all Windows, Linux or macOS operating systems which have Python 3.7 support. Windows users who plan to use the already built/frozen/compiled binary must make sure that they have the latest Windows Updates installed which include all required "Universal C Runtime (CRT)" libraries.

#### **Prerequisites**

To run the python script or its built/frozen/compiled binary, you need to have the following 3rd party tools at the same directory:

* [UEFIFind](https://github.com/LongSoft/UEFITool) (i.e. UEFIFind.exe)
* [UEFIExtract](https://github.com/LongSoft/UEFITool) (i.e. UEFIExtract.exe)

#### **Build/Freeze/Compile with PyInstaller**

PyInstaller can build/freeze/compile the utility at all three supported platforms, it is simple to run and gets updated often.

1. Make sure Python 3.7.0 or newer is installed:

> python --version

2. Use pip to install PyInstaller:

> pip3 install pyinstaller

3. Build/Freeze/Compile:

> pyinstaller --noupx --onefile Apple_EFI_Rename.py

At dist folder you should find the final utility executable

#### **Anti-Virus False Positives**

Some Anti-Virus software may claim that the built/frozen/compiled executable contains viruses. Any such detections are false positives, usually of PyInstaller. You can switch to a better Anti-Virus software, report the false positive to their support, add the executable to the exclusions, build/freeze/compile yourself or use the Python script directly.

## **Apple EFI IM4P Splitter**

![](https://i.imgur.com/G5RkXQk.png)

#### **Description**

Parses Apple multiple EFI firmware .im4p files and splits all detected EFI firmware into separate SPI/BIOS images.

#### **Usage**

You can either Drag & Drop or manually enter the full path of a folder containing Apple EFI IM4P firmware.

#### **Download**

An already built/frozen/compiled binary is provided by me for Windows only. Thus, **you don't need to manually build/freeze/compile it under Windows**. Instead, download the latest version from the [Releases](https://github.com/platomav/BIOSUtilities/releases) tab. To extract the already built/frozen/compiled archive, you need to use programs which support RAR5 compression. Note that you need to manually apply any prerequisites.

#### **Compatibility**

Should work at all Windows, Linux or macOS operating systems which have Python 3.7 support. Windows users who plan to use the already built/frozen/compiled binary must make sure that they have the latest Windows Updates installed which include all required "Universal C Runtime (CRT)" libraries.

#### **Prerequisites**

To run the utility, you do not need any 3rd party tool.

#### **Build/Freeze/Compile with PyInstaller**

PyInstaller can build/freeze/compile the utility at all three supported platforms, it is simple to run and gets updated often.

1. Make sure Python 3.7.0 or newer is installed:

> python --version

2. Use pip to install PyInstaller:

> pip3 install pyinstaller

3. Build/Freeze/Compile:

> pyinstaller --noupx --onefile Apple_EFI_Split.py

At dist folder you should find the final utility executable

#### **Anti-Virus False Positives**

Some Anti-Virus software may claim that the built/frozen/compiled executable contains viruses. Any such detections are false positives, usually of PyInstaller. You can switch to a better Anti-Virus software, report the false positive to their support, add the executable to the exclusions, build/freeze/compile yourself or use the Python script directly.

## **Apple EFI Package Extractor**

![](https://i.imgur.com/pufGuZ4.png)

#### **Description**

Parses Apple EFI firmware packages (i.e. FirmwareUpdate.pkg, BridgeOSUpdateCustomer.pkg), extracts their EFI images, splits those in IM4P format and renames the final SPI/BIOS images accordingly. The utility automatically uses the free version of [AnyToISO](https://www.crystalidea.com/anytoiso) to extract the EFI .pkg files. The subsequent IM4P splitting and EFI renaming requires the presence of "Apple EFI IM4P Splitter" and "Apple EFI File Renamer" utilities.

#### **Usage**

You can either Drag & Drop or manually enter the full path of a folder containing Apple EFI firmware package (.pkg) files. Depending on where AnyToISO is installed on your system, you must change the "anytoiso_path" variable accordingly.

#### **Download**

An already built/frozen/compiled binary is **not** provided because the script requires the user to set the AnyToISO executable path variable. Remember that you need to include prerequisites such as AnyToISO, Apple EFI IM4P Splitter and Apple EFI File Renamer for the utility to work.

#### **Compatibility**

Should work at all Windows & macOS operating systems which have Python 3.7 and AnyToISO support.

#### **Prerequisites**

To run the python script, you need to have the following 3rd party tools installed or placed at the same directory:

* [AnyToISO](https://www.crystalidea.com/anytoiso) (i.e. anytoiso.exe)
* [UEFIFind](https://github.com/LongSoft/UEFITool) (i.e. UEFIFind.exe)
* [UEFIExtract](https://github.com/LongSoft/UEFITool) (i.e. UEFIExtract.exe)

#### **Build/Freeze/Compile with PyInstaller**

PyInstaller can build/freeze/compile the utility at all three supported platforms, it is simple to run and gets updated often. Note that, due to this utility's nature, you may need to perform some small script changes for a built/frozen/compiled binary to work.

1. Make sure Python 3.7.0 or newer is installed:

> python --version

2. Use pip to install PyInstaller:

> pip3 install pyinstaller

3. Build/Freeze/Compile:

> pyinstaller --noupx --onefile Apple_EFI_Package.py

At dist folder you should find the final utility executable

#### **Anti-Virus False Positives**

Some Anti-Virus software may claim that the built/frozen/compiled executable contains viruses. Any such detections are false positives, usually of PyInstaller. You can switch to a better Anti-Virus software, report the false positive to their support, add the executable to the exclusions, build/freeze/compile yourself or use the Python script directly.

## **Panasonic BIOS Update Extractor**

![](https://i.imgur.com/uZAoMGR.png)
<sub><sup>*Icon owned by Panasonic*</sup></sub>

#### **Description**

Parses Panasonic BIOS Update executables and extracts their SPI/BIOS image. The utility automatically uses [Rustam Abdullaev's unpack_lznt1](https://github.com/rustyx/unpack_lznt1) tool in order to decompress the initially Microsoft LZNT1 compressed resource data.

#### **Usage**

You can either Drag & Drop or manually enter the full path of a folder containing Panasonic BIOS Update executables.

#### **Download**

An already built/frozen/compiled Windows binary is provided by me. Thus, **you don't need to manually build/freeze/compile it**. Instead, download the latest version from the [Releases](https://github.com/platomav/BIOSUtilities/releases) tab. To extract the already built/frozen/compiled archive, you need to use programs which support RAR5 compression. Note that you need to manually apply any prerequisites.

#### **Compatibility**

Should work at all Windows operating systems which have Python 3.7 support. Windows users who plan to use the already built/frozen/compiled binary must make sure that they have the latest Windows Updates installed which include all required "Universal C Runtime (CRT)" libraries.

#### **Prerequisites**

To run the python script, you need to have the following 3rd party Python modules installed:

* [PEfile](https://pypi.python.org/pypi/pefile/)

> pip3 install pefile

To run the python script or its built/frozen/compiled binary, you need to additionally have the following 3rd party tool at the same directory:

* [unpack_lznt1](https://github.com/rustyx/unpack_lznt1) (i.e. unpack_lznt1.exe)

#### **Build/Freeze/Compile with PyInstaller**

PyInstaller can build/freeze/compile the utility at Windows, it is simple to run and gets updated often.

1. Make sure Python 3.7.0 or newer is installed:

> python --version

2. Use pip to install PyInstaller:

> pip3 install pyinstaller

3. Use pip to install PEfile:

> pip3 install pefile

4. Build/Freeze/Compile:

> pyinstaller --noupx --onefile Panasonic_BIOS_Extract.py

At dist folder you should find the final utility executable

#### **Anti-Virus False Positives**

Some Anti-Virus software may claim that the built/frozen/compiled executable contains viruses. Any such detections are false positives, usually of PyInstaller. You can switch to a better Anti-Virus software, report the false positive to their support, add the executable to the exclusions, build/freeze/compile yourself or use the Python script directly.

## **VAIO Packaging Manager Extractor**

![](https://i.imgur.com/rg4xrxJ.png)
<sub><sup>*Icon owned by VAIO*</sup></sub>

#### **Description**

Parses VAIO Packaging Manager executables and extracts their contents. If direct extraction fails, it unlocks the executable in order to run at all systems and allow the user to choose the extraction location. The utility automatically uses [Igor Pavlov's 7-Zip](https://www.7-zip.org/) tool in order to decompress the initially obfuscated Microsoft CAB compressed contents.

#### **Usage**

You can either Drag & Drop or manually enter the full path of a folder containing VAIO Packaging Manager executables.

#### **Download**

An already built/frozen/compiled binary is provided by me for Windows only. Thus, **you don't need to manually build/freeze/compile it under Windows**. Instead, download the latest version from the [Releases](https://github.com/platomav/BIOSUtilities/releases) tab. To extract the already built/frozen/compiled archive, you need to use programs which support RAR5 compression. Note that you need to manually apply any prerequisites.

#### **Compatibility**

Should work at all Windows, Linux or macOS operating systems which have Python 3.7 support. Windows users who plan to use the already built/frozen/compiled binary must make sure that they have the latest Windows Updates installed which include all required "Universal C Runtime (CRT)" libraries.

#### **Prerequisites**

To run the python script or its built/frozen/compiled binary, you need to have the following 3rd party tool at the same directory:

* [7-Zip Console](https://www.7-zip.org/) (i.e. 7z.exe)

#### **Build/Freeze/Compile with PyInstaller**

PyInstaller can build/freeze/compile the utility at all three supported platforms, it is simple to run and gets updated often.

1. Make sure Python 3.7.0 or newer is installed:

> python --version

2. Use pip to install PyInstaller:

> pip3 install pyinstaller

3. Build/Freeze/Compile:

> pyinstaller --noupx --onefile VAIO_Package_Extract.py

At dist folder you should find the final utility executable

#### **Anti-Virus False Positives**

Some Anti-Virus software may claim that the built/frozen/compiled executable contains viruses. Any such detections are false positives, usually of PyInstaller. You can switch to a better Anti-Virus software, report the false positive to their support, add the executable to the exclusions, build/freeze/compile yourself or use the Python script directly.

## **Fujitsu SFX Packager Extractor**

![](https://i.imgur.com/NlZGBsy.png)
<sub><sup>*Icon owned by FUJITSU*</sup></sub>

#### **Description**

Parses Fujitsu SFX Packager executables and extracts their contents. The utility automatically uses [Igor Pavlov's 7-Zip](https://www.7-zip.org/) tool in order to decompress the initially obfuscated Microsoft CAB compressed contents.

#### **Usage**

You can either Drag & Drop or manually enter the full path of a folder containing Fujitsu SFX Packager executables.

#### **Download**

An already built/frozen/compiled binary is provided by me for Windows only. Thus, **you don't need to manually build/freeze/compile it under Windows**. Instead, download the latest version from the [Releases](https://github.com/platomav/BIOSUtilities/releases) tab. To extract the already built/frozen/compiled archive, you need to use programs which support RAR5 compression. Note that you need to manually apply any prerequisites.

#### **Compatibility**

Should work at all Windows, Linux or macOS operating systems which have Python 3.7 support. Windows users who plan to use the already built/frozen/compiled binary must make sure that they have the latest Windows Updates installed which include all required "Universal C Runtime (CRT)" libraries.

#### **Prerequisites**

To run the python script or its built/frozen/compiled binary, you need to have the following 3rd party tool at the same directory:

* [7-Zip Console](https://www.7-zip.org/) (i.e. 7z.exe)

#### **Build/Freeze/Compile with PyInstaller**

PyInstaller can build/freeze/compile the utility at all three supported platforms, it is simple to run and gets updated often.

1. Make sure Python 3.7.0 or newer is installed:

> python --version

2. Use pip to install PyInstaller:

> pip3 install pyinstaller

3. Build/Freeze/Compile:

> pyinstaller --noupx --onefile Fujitsu_Package_Extract.py

At dist folder you should find the final utility executable

#### **Anti-Virus False Positives**

Some Anti-Virus software may claim that the built/frozen/compiled executable contains viruses. Any such detections are false positives, usually of PyInstaller. You can switch to a better Anti-Virus software, report the false positive to their support, add the executable to the exclusions, build/freeze/compile yourself or use the Python script directly.

## **Award BIOS Module Extractor**

#### **Description**

Parses Award BIOS images and extracts their modules. The utility automatically uses [Igor Pavlov's 7-Zip](https://www.7-zip.org/) tool in order to decompress the initially LZH compressed sub-modules.

#### **Usage**

You can either Drag & Drop or manually enter the full path of a folder containing Award BIOS firmware.

#### **Download**

An already built/frozen/compiled binary is provided by me for Windows only. Thus, **you don't need to manually build/freeze/compile it under Windows**. Instead, download the latest version from the [Releases](https://github.com/platomav/BIOSUtilities/releases) tab. To extract the already built/frozen/compiled archive, you need to use programs which support RAR5 compression. Note that you need to manually apply any prerequisites.

#### **Compatibility**

Should work at all Windows, Linux or macOS operating systems which have Python 3.7 support. Windows users who plan to use the already built/frozen/compiled binary must make sure that they have the latest Windows Updates installed which include all required "Universal C Runtime (CRT)" libraries.

#### **Prerequisites**

To run the python script or its built/frozen/compiled binary, you need to have the following 3rd party tool at the same directory:

* [7-Zip Console](https://www.7-zip.org/) (i.e. 7z.exe)

#### **Build/Freeze/Compile with PyInstaller**

PyInstaller can build/freeze/compile the utility at all three supported platforms, it is simple to run and gets updated often.

1. Make sure Python 3.7.0 or newer is installed:

> python --version

2. Use pip to install PyInstaller:

> pip3 install pyinstaller

3. Build/Freeze/Compile:

> pyinstaller --noupx --onefile Award_BIOS_Extract.py

At dist folder you should find the final utility executable

#### **Anti-Virus False Positives**

Some Anti-Virus software may claim that the built/frozen/compiled executable contains viruses. Any such detections are false positives, usually of PyInstaller. You can switch to a better Anti-Virus software, report the false positive to their support, add the executable to the exclusions, build/freeze/compile yourself or use the Python script directly.

###### _Donate Button Card Image: [Credit and Loan Pack](https://flaticon.com/free-icon/credit-card_3898076) by **Freepik** under Flaticon license_
###### _Donate Button Paypal Image: [Credit Cards Pack](https://flaticon.com/free-icon/paypal_349278) by **Freepik** under Flaticon license_