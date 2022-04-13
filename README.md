# BIOSUtilities
**Various BIOS Utilities for Modding/Research**

[BIOS Utilities News Feed](https://twitter.com/platomaniac)

<a href="https://www.paypal.com/cgi-bin/webscr?cmd=_s-xclick&hosted_button_id=DJDZD3PRGCSCL"><img border="0" title="BIOS Utilities Donation via Paypal or Debit/Credit Card" alt="BIOS Utilities Donation via Paypal or Debit/Credit Card" src="https://user-images.githubusercontent.com/11527726/109392268-e0f68280-7923-11eb-83d8-0a63f0d20783.png"></a>

* [**Dell PFS Update Extractor**](#dell-pfs-update-extractor)
* [**AMI UCP BIOS Extractor**](#ami-ucp-bios-extractor)
* [**AMI BIOS Guard Extractor**](#ami-bios-guard-extractor)

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

Should work at all Windows, Linux or macOS operating systems which have Python 3.7 support.

#### **Prerequisites**

Optionally, to decompile the Intel BIOS Guard (PFAT) Scripts, you must have the following 3rd party utility at the "external" project directory:

* [BIOS Guard Script Tool](https://github.com/allowitsme/big-tool/tree/sdk-compat) (i.e. big_script_tool.py)

#### **Build/Freeze/Compile with PyInstaller**

PyInstaller can build/freeze/compile the utility at all three supported platforms, it is simple to run and gets updated often.

1. Make sure Python 3.7.0 or newer is installed:

> python --version

2. Use pip to install PyInstaller:

> pip3 install pyinstaller

3. Place any appropriate prerequisite at the project directory:

> BIOS Guard Script Tool

4. Build/Freeze/Compile:

> pyinstaller --noupx --onefile \<path-to-project\>\/Dell_PFS_Extract.py

You should find the final utility executable at "dist" folder

#### **Anti-Virus False Positives**

Some Anti-Virus software may claim that the built/frozen/compiled executable contains viruses. Any such detections are false positives, usually of PyInstaller. You can switch to a better Anti-Virus software, report the false positive to their support, add the executable to the exclusions, build/freeze/compile yourself or use the Python script directly.

#### **Pictures**

![]()

## **AMI UCP BIOS Extractor**

![]()

#### **Description**

Parses AMI UCP (Utility Configuration Program) BIOS executables, extracts their firmware components (e.g. SPI/BIOS/UEFI, EC, ME etc) and shows all relevant info. It supports all AMI UCP revisions and formats, including those with nested AMI PFAT, AMI UCP or Insyde SFX structures. The output comprises only final firmware components and utilities which are directly usable by end users.

#### **Usage**

You can either Drag & Drop or manually enter AMI UCP BIOS executable file(s). Optional arguments:
  
* -h or --help : show help message and exit
* -v or --version : show utility name and version
* -i or --input-dir : extract from given input directory
* -o or --output-dir : extract in given output directory
* -e or --auto-exit : skip press enter to exit prompts
* -c or --checksum : verify AMI UCP Checksums (slow)

#### **Compatibility**

Should work at all Windows, Linux or macOS operating systems which have Python 3.7 support.

#### **Prerequisites**

To run the utility, you must have the following 3rd party tools at the "external" project directory:

* [TianoCompress](https://github.com/tianocore/edk2/tree/master/BaseTools/Source/C/TianoCompress/) (e.g. [TianoCompress.exe for Windows](https://github.com/tianocore/edk2-BaseTools-win32/) or TianoCompress)
* [7-Zip Console](https://www.7-zip.org/) (i.e. 7z.exe for Windows or 7zz|7zzs)

Optionally, to decompile the AMI UCP \> AMI PFAT \> Intel BIOS Guard Scripts (when applicable), you must have the following 3rd party utility at the "external" project directory:

* [BIOS Guard Script Tool](https://github.com/allowitsme/big-tool/tree/sdk-compat) (i.e. big_script_tool.py)

#### **Build/Freeze/Compile with PyInstaller**

PyInstaller can build/freeze/compile the utility at all three supported platforms, it is simple to run and gets updated often.

1. Make sure Python 3.7.0 or newer is installed:

> python --version

2. Use pip to install PyInstaller:

> pip3 install pyinstaller

3. Place any appropriate prerequisite at the project directory:

> TianoCompress, 7-Zip Console, BIOS Guard Script Tool

4. Build/Freeze/Compile:

> pyinstaller --noupx --onefile \<path-to-project\>\/AMI_UCP_Extract.py

You should find the final utility executable at "dist" folder

#### **Anti-Virus False Positives**

Some Anti-Virus software may claim that the built/frozen/compiled executable contains viruses. Any such detections are false positives, usually of PyInstaller. You can switch to a better Anti-Virus software, report the false positive to their support, add the executable to the exclusions, build/freeze/compile yourself or use the Python script directly.

#### **Pictures**

![]()

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

Should work at all Windows, Linux or macOS operating systems which have Python 3.7 support.

#### **Prerequisites**

Optionally, to decompile the AMI PFAT \> Intel BIOS Guard Scripts, you must have the following 3rd party utility at the "external" project directory:

* [BIOS Guard Script Tool](https://github.com/allowitsme/big-tool/tree/sdk-compat) (i.e. big_script_tool.py)

#### **Build/Freeze/Compile with PyInstaller**

PyInstaller can build/freeze/compile the utility at all three supported platforms, it is simple to run and gets updated often.

1. Make sure Python 3.7.0 or newer is installed:

> python --version

2. Use pip to install PyInstaller:

> pip3 install pyinstaller

3. Place any appropriate prerequisite at the project directory:

> BIOS Guard Script Tool

4. Build/Freeze/Compile:

> pyinstaller --noupx --onefile \<path-to-project\>\/AMI_PFAT_Extract.py

You should find the final utility executable at "dist" folder

#### **Anti-Virus False Positives**

Some Anti-Virus software may claim that the built/frozen/compiled executable contains viruses. Any such detections are false positives, usually of PyInstaller. You can switch to a better Anti-Virus software, report the false positive to their support, add the executable to the exclusions, build/freeze/compile yourself or use the Python script directly.

#### **Pictures**

![]()

###### _Donate Button Card Image: [Credit and Loan Pack](https://flaticon.com/free-icon/credit-card_3898076) by **Freepik** under Flaticon license_
###### _Donate Button Paypal Image: [Credit Cards Pack](https://flaticon.com/free-icon/paypal_349278) by **Freepik** under Flaticon license_