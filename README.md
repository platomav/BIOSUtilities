# BIOSUtilities

## About

Various BIOS/UEFI-related utilities which aid in modding and/or research

## Usage

### Main

The "main" script provides a simple way to check and parse each of the user provided files against all utilities, in succession. It is ideal for quick drag & drop operations but lacks the finer control of the BIOSUtility method. If needed, a few options can be set, by using the command line:

``` bash
usage: [-h] [-e] [-o OUTPUT_DIR] paths [paths ...]

positional arguments:
  paths

options:
  -h, --help                              show help and exit
  -e, --auto-exit                         do not pause on exit
  -o OUTPUT_DIR, --output-dir OUTPUT_DIR  extraction directory
```

``` bash
python ./main.py "/path/to/input/file.bin" --output-dir "/path/to/file extractions"
```

### BIOSUtility

Each utility is derived from a base template: BIOSUtility. The base BIOSUtility offers the following options, applicable to all utilities:

``` bash
usage: [-h] [-e] [-o OUTPUT_DIR] [paths ...]

positional arguments:
  paths

options:
  -h, --help                              show help and exit
  -e, --auto-exit                         skip user action prompts
  -o OUTPUT_DIR, --output-dir OUTPUT_DIR  output extraction directory
```

``` bash
python -m biosutilities.ami_pfat_extract -e "/path/to/input/file1.bin" "/path/to/input/file2.bin" "/path/to/input/folder/with/files/" -o "/path/to/output_directory"
```

If no arguments are provided, the BIOSUtility.run_utility() method gets executed, which will request the input and output paths from the user. If no output path is provided, the utility will use the parent directory of the first input file or fallback to the runtime execution directory.

``` bash
Enter input file or directory path: "C:\P5405CSA.303"

Enter output directory path: "C:\P5405CSA.303_output"
```

### Package

All utilities form the "biosutilities" python package, which can be installed from PyPi:

``` bash
python -m pip install --upgrade biosutilities
```

Installing the python package is the recommended way to call one or more utilities programatically, while fully controlling arguments and options.

``` python
from biosutilities.ami_pfat_extract import AmiPfatExtract

ami_pfat_extractor = AmiPfatExtract()

ami_pfat_extractor.check_format(input_object='/path/to/input/file.bin')
ami_pfat_extractor.parse_format(input_object='/path/to/input/file.bin', extract_path='/path/to/output/folder/')
```

``` python
from biosutilities.dell_pfs_extract import DellPfsExtract

dell_pfs_extractor = DellPfsExtract()

with open(file='/path/to/input/file.bin', mode='rb') as pfs_file:
    pfs_buffer = pfs_file.read()

dell_pfs_extractor.check_format(input_object=pfs_buffer)
dell_pfs_extractor.parse_format(input_object=pfs_buffer, extract_path='/path/to/output/directory/', padding=8)
```

``` python
from biosutilities.phoenix_tdk_extract import PhoenixTdkExtract

phoenix_tdk_extractor = PhoenixTdkExtract(arguments=['-e', '/path/to/input/file.bin', '-o', '/path/to/output/folder/'])

phoenix_tdk_extractor.run_utility(padding=4)
```

``` python
from biosutilities.apple_efi_pbzx import AppleEfiPbzxExtract

apple_efi_pbzx_extractor = AppleEfiPbzxExtract()

apple_efi_pbzx_extractor.show_version(is_boxed=False, padding=12)
```

It also allows to use directly the four public methods which are inherited by every utility from the base BIOSUtility class.

#### run_utility

Run utility after checking for supported format

``` python
run_utility(padding: int = 0) -> bool
```

#### check_format

Check if input object is of specific supported format

``` python
check_format(input_object: str | bytes | bytearray) -> bool
```

#### parse_format

Process input object as a specific supported format

``` python
parse_format(input_object: str | bytes | bytearray, extract_path: str, padding: int = 0) -> bool
```

#### show_version

Show title and version of utility

``` python
show_version(is_boxed: bool = True, padding: int = 0) -> None
```

## Requirements

There are two main types of requirements (dependencies), depending on the utility.

### Python Packages

Python packages can be installed via Pypi (e.g. pip)

``` bash
python -m pip install --upgrade -r requirements.txt
```

``` bash
python -m pip install --upgrade pefile dissect.util
```

### External Executables / Scripts

External executables and/or scripts (e.g. TianoCompress.exe, big_script_tool.py, 7z.exe) need to be found via the "PATH" environment variable, which is configured differently depending on the operating system.

Alternatively, if neither modifying PATH environment variable nor copying the executables in standard OS PATH directories is an option, you can create a folder "external" at the root of the "biosutilities" project.

#### Linux

[Linux Path](https://www.digitalocean.com/community/tutorials/how-to-view-and-update-the-linux-path-environment-variable)

or

``` bash
sudo install "/path/to/downloaded/external/executable/to/install" /usr/local/bin
```

#### Windows

[Windows Path](https://www.computerhope.com/issues/ch000549.htm)

**Note:** In the "Environment Variables" window, you can modify the "Path" variable under "User variables" instead of "System variables", as many guides suggest.

#### MacOS

[Mac Path](https://mac.install.guide/terminal/path)

## Utilities

* [**AMI BIOS Guard Extractor**](#ami-bios-guard-extractor)
* [**AMI UCP Update Extractor**](#ami-ucp-update-extractor)
* [**Apple EFI IM4P Splitter**](#apple-efi-im4p-splitter)
* [**Apple EFI Image Identifier**](#apple-efi-image-identifier)
* [**Apple EFI Package Extractor**](#apple-efi-package-extractor)
* [**Apple EFI PBZX Extractor**](#apple-efi-pbzx-extractor)
* [**Award BIOS Module Extractor**](#award-bios-module-extractor)
* [**Dell PFS Update Extractor**](#dell-pfs-update-extractor)
* [**Fujitsu SFX BIOS Extractor**](#fujitsu-sfx-bios-extractor)
* [**Fujitsu UPC BIOS Extractor**](#fujitsu-upc-bios-extractor)
* [**Insyde iFlash/iFdPacker Extractor**](#insyde-iflashifdpacker-extractor)
* [**Panasonic BIOS Package Extractor**](#panasonic-bios-package-extractor)
* [**Phoenix TDK Packer Extractor**](#phoenix-tdk-packer-extractor)
* [**Portwell EFI Update Extractor**](#portwell-efi-update-extractor)
* [**Toshiba BIOS COM Extractor**](#toshiba-bios-com-extractor)
* [**VAIO Packaging Manager Extractor**](#vaio-packaging-manager-extractor)

### **AMI BIOS Guard Extractor**

#### **Description**

Parses AMI BIOS Guard (a.k.a. PFAT, Platform Firmware Armoring Technology) images, extracts their SPI/BIOS/UEFI firmware components and optionally decompiles the Intel BIOS Guard Scripts. It supports all AMI PFAT revisions and formats, including those with Index Information tables or nested AMI PFAT structures. The output comprises only final firmware components which are directly usable by end users.

Note that the AMI PFAT structure may not have an explicit component order. AMI's BIOS Guard Firmware Update Tool (AFUBGT) updates components based on the user/OEM provided Parameters and Options or Index Information table, when applicable. Thus, merging all the components together does not usually yield a proper SPI/BIOS/UEFI image. The utility does generate such a merged file with the name "00 -- \<filename\>\_ALL.bin" but it is up to the end user to determine its usefulness. Additionally, any custom OEM data, after the AMI PFAT structure, is stored in the last file with the name "\<n+1\> -- \_OOB.bin" and it is once again up to the end user to determine its usefulness. In cases where the trailing custom OEM data includes a nested AMI PFAT structure, the utility will process and extract it automatically as well.

#### **Usage**

No additional optional arguments are provided for this utility.

#### **Compatibility**

Should work at all Windows, Linux or macOS operating systems which have Python 3.10 or newer support.

#### **Prerequisites**

Optionally, to decompile the AMI PFAT \> Intel BIOS Guard Scripts, you must have the following 3rd party python script at PATH or "external":

* [BIOS Guard Script Tool](https://github.com/platomav/BGScriptTool) (i.e. big_script_tool.py)

### **AMI UCP Update Extractor**

#### **Description**

Parses AMI UCP (Utility Configuration Program) Update executables, extracts their firmware components (e.g. SPI/BIOS/UEFI, EC, ME etc) and shows all relevant info. It supports all AMI UCP revisions and formats, including those with nested AMI PFAT, AMI UCP or Insyde iFlash/iFdPacker structures. The output comprises only final firmware components and utilities which are directly usable by end users.

#### **Usage**

Additional optional arguments are provided for this utility:

* -c or --checksum : verify AMI UCP Checksums (slow)

#### **Compatibility**

Should work at all Windows, Linux or macOS operating systems which have Python 3.10 or newer support.

#### **Prerequisites**

To run the utility, you must have the following 3rd party tools at PATH or "external":

* [TianoCompress](https://github.com/tianocore/edk2/tree/master/BaseTools/Source/C/TianoCompress/) (i.e. [TianoCompress.exe for Windows](https://github.com/tianocore/edk2-BaseTools-win32/) or TianoCompress for Linux/macOS)
* [7-Zip Console](https://www.7-zip.org/) (i.e. 7z.exe for Windows or 7zz for macOS or 7zz, 7zzs for Linux)

Optionally, to decompile the AMI UCP \> AMI PFAT \> Intel BIOS Guard Scripts (when applicable), you must have the following 3rd party python script at PATH or "external":

* [BIOS Guard Script Tool](https://github.com/platomav/BGScriptTool) (i.e. big_script_tool.py)

### **Apple EFI IM4P Splitter**

#### **Description**

Parses Apple IM4P multi-EFI files and splits all detected EFI firmware into separate Intel SPI/BIOS images. The output comprises only final firmware components and utilities which are directly usable by end users.

#### **Usage**

No additional optional arguments are provided for this utility.

#### **Compatibility**

Should work at all Windows, Linux or macOS operating systems which have Python 3.10 or newer support.

Note: On Linux and macOS, you'll need to compile TianoCompress from sources as no pre-built binary exists.

#### **Prerequisites**

To run the utility, you do not need any prerequisites.

### **Apple EFI Image Identifier**

#### **Description**

Parses Apple EFI images and identifies them based on Intel's official "IBIOSI" tag, which contains info such as Model, Version, Build, Date and Time. Additionally, the utility can provide both "IBIOSI" and "Apple ROM Version" structure info, when available, as well as a suggested EFI image filename, while also making sure to differentiate any EFI images with the same "IBIOSI" tag (e.g. Production, Pre-Production) by appending a checksum of their data.

#### **Usage**

No additional optional arguments are provided for this utility.

#### **Compatibility**

Should work at all Windows, Linux or macOS operating systems which have Python 3.10 or newer support.

#### **Prerequisites**

To run the utility, you must have the following 3rd party tools at PATH or "external":

* [UEFIFind](https://github.com/LongSoft/UEFITool/) (i.e. [UEFIFind.exe for Windows or UEFIFind for Linux/macOS](https://github.com/LongSoft/UEFITool/releases))
* [UEFIExtract](https://github.com/LongSoft/UEFITool/) (i.e. [UEFIExtract.exe for Windows or UEFIExtract for Linux/macOS](https://github.com/LongSoft/UEFITool/releases))

### **Apple EFI Package Extractor**

#### **Description**

Parses Apple EFI PKG firmware packages (e.g. FirmwareUpdate.pkg, BridgeOSUpdateCustomer.pkg, InstallAssistant.pkg, iMacEFIUpdate.pkg, iMacFirmwareUpdate.tar), extracts their EFI images, splits those in IM4P format and identifies/renames the final Intel SPI/BIOS images accordingly. The output comprises only final firmware components which are directly usable by end users.

#### **Usage**

No additional optional arguments are provided for this utility.

#### **Compatibility**

Should work at all Windows, Linux or macOS operating systems which have Python 3.10 or newer support.

#### **Prerequisites**

To run the utility, you must have the following 3rd party tools at PATH or "external":

* [7-Zip Console](https://www.7-zip.org/) (i.e. 7z.exe for Windows or 7zz for macOS or 7zz, 7zzs for Linux)

### **Apple EFI PBZX Extractor**

#### **Description**

Parses Apple EFI PBZX images, re-assembles their CPIO payload and extracts its firmware components (e.g. IM4P, EFI, Utilities, Scripts etc). It supports CPIO re-assembly from both Raw and XZ compressed PBZX Chunks. The output comprises only final firmware components and utilities which are directly usable by end users.

#### **Usage**

No additional optional arguments are provided for this utility.

#### **Compatibility**

Should work at all Windows, Linux or macOS operating systems which have Python 3.10 or newer support.

#### **Prerequisites**

To run the utility, you must have the following 3rd party tools at PATH or "external":

* [7-Zip Console](https://www.7-zip.org/) (i.e. 7z.exe for Windows or 7zz for macOS or 7zz, 7zzs for Linux)

### **Award BIOS Module Extractor**

#### **Description**

Parses Award BIOS images and extracts their modules (e.g. RAID, MEMINIT, \_EN_CODE, awardext etc). It supports all Award BIOS image revisions and formats, including those which contain LZH compressed files. The output comprises only final firmware components which are directly usable by end users.

#### **Usage**

No additional optional arguments are provided for this utility.

#### **Compatibility**

Should work at all Windows, Linux or macOS operating systems which have Python 3.10 or newer support.

#### **Prerequisites**

To run the utility, you must have the following 3rd party tool at PATH or "external":

* [7-Zip Console](https://www.7-zip.org/) (i.e. 7z.exe for Windows or 7zz for macOS or 7zz, 7zzs for Linux)

### **Dell PFS Update Extractor**

#### **Description**

Parses Dell PFS Update images and extracts their Firmware (e.g. SPI, BIOS/UEFI, EC, ME etc) and Utilities (e.g. Flasher etc) component sections. It supports all Dell PFS revisions and formats, including those which are originally LZMA compressed in ThinOS packages (PKG), ZLIB compressed or Intel BIOS Guard (PFAT) protected. The output comprises only final firmware components which are directly usable by end users.

#### **Usage**

Additional optional arguments are provided for this utility:

* -a or --advanced : extract signatures and metadata
* -s or --structure : show PFS structure information

#### **Compatibility**

Should work at all Windows, Linux or macOS operating systems which have Python 3.10 or newer support.

#### **Prerequisites**

Optionally, to decompile the Intel BIOS Guard (PFAT) Scripts, you must have the following 3rd party utility at PATH or "external":

* [BIOS Guard Script Tool](https://github.com/platomav/BGScriptTool) (i.e. big_script_tool.py)

### **Fujitsu SFX BIOS Extractor**

#### **Description**

Parses Fujitsu SFX BIOS images and extracts their obfuscated Microsoft CAB archived firmware (e.g. SPI, BIOS/UEFI, EC, ME etc) and utilities (e.g. WinPhlash, PHLASH.INI etc) components. The output comprises only final firmware components which are directly usable by end users.

#### **Usage**

No additional optional arguments are provided for this utility.

#### **Compatibility**

Should work at all Windows, Linux or macOS operating systems which have Python 3.10 or newer support.

#### **Prerequisites**

To run the utility, you must have the following 3rd party tool at PATH or "external":

* [7-Zip Console](https://www.7-zip.org/) (i.e. 7z.exe for Windows or 7zz for macOS or 7zz, 7zzs for Linux)

### **Fujitsu UPC BIOS Extractor**

#### **Description**

Parses Fujitsu UPC BIOS images and extracts their EFI compressed SPI/BIOS/UEFI firmware component. The output comprises only a final firmware component which is directly usable by end users.

#### **Usage**

No additional optional arguments are provided for this utility.

#### **Compatibility**

Should work at all Windows, Linux or macOS operating systems which have Python 3.10 or newer support.

#### **Prerequisites**

To run the utility, you must have the following 3rd party tool at PATH or "external":

* [TianoCompress](https://github.com/tianocore/edk2/tree/master/BaseTools/Source/C/TianoCompress/) (i.e. [TianoCompress.exe for Windows](https://github.com/tianocore/edk2-BaseTools-win32/) or TianoCompress for Linux/macOS)

### **Insyde iFlash/iFdPacker Extractor**

#### **Description**

Parses Insyde iFlash/iFdPacker Update images and extracts their firmware (e.g. SPI, BIOS/UEFI, EC, ME etc) and utilities (e.g. InsydeFlash, H2OFFT, FlsHook, iscflash, platform.ini etc) components. It supports all Insyde iFlash/iFdPacker revisions and formats, including those which are 7-Zip SFX 7z compressed in raw, obfuscated or password-protected form. The output comprises only final firmware components which are directly usable by end users.

#### **Usage**

No additional optional arguments are provided for this utility.

#### **Compatibility**

Should work at all Windows, Linux or macOS operating systems which have Python 3.10 or newer support.

Note: On Linux and macOS, you'll need to compile TianoCompress from sources as no pre-built binary exists.

#### **Prerequisites**

To run the utility, you do not need any prerequisites.

### **Panasonic BIOS Package Extractor**

#### **Description**

Parses Panasonic BIOS Package executables and extracts their firmware (e.g. SPI, BIOS/UEFI, EC etc) and utilities (e.g. winprom, configuration etc) components. It supports all Panasonic BIOS Package revisions and formats, including those which contain LZNT1 compressed files and/or AMI PFAT payloads. The output comprises only final firmware components which are directly usable by end users.

#### **Usage**

No additional optional arguments are provided for this utility.

#### **Compatibility**

Should work at all Windows, Linux or macOS operating systems which have Python 3.10 or newer support.

#### **Prerequisites**

To run the utility, you must have the following 3rd party Python modules installed:

* [pefile](https://pypi.org/project/pefile/)
* [dissect.util](https://pypi.org/project/dissect.util/)

Moreover, you must have the following 3rd party tool at PATH or "external":

* [7-Zip Console](https://www.7-zip.org/) (i.e. 7z.exe for Windows or 7zz for macOS or 7zz, 7zzs for Linux)

### **Phoenix TDK Packer Extractor**

#### **Description**

Parses Phoenix Tools Development Kit (TDK) Packer executables and extracts their firmware (e.g. SPI, BIOS/UEFI, EC etc) and utilities (e.g. WinFlash etc) components. It supports all Phoenix TDK Packer revisions and formats, including those which contain LZMA compressed files. The output comprises only final firmware components which are directly usable by end users.

#### **Usage**

No additional optional arguments are provided for this utility.

#### **Compatibility**

Should work at all Windows, Linux or macOS operating systems which have Python 3.10 or newer support.

#### **Prerequisites**

To run the utility, you must have the following 3rd party Python module installed:

* [pefile](https://pypi.org/project/pefile/)

### **Portwell EFI Update Extractor**

#### **Description**

Parses Portwell UEFI Unpacker EFI executables (usually named "Update.efi") and extracts their firmware (e.g. SPI, BIOS/UEFI, EC etc) and utilities (e.g. Flasher etc) components. It supports all known Portwell UEFI Unpacker revisions (v1.1, v1.2, v2.0) and formats (used, empty, null), including those which contain EFI compressed files. The output comprises only final firmware components and utilities which are directly usable by end users.

#### **Usage**

No additional optional arguments are provided for this utility.

#### **Compatibility**

Should work at all Windows, Linux or macOS operating systems which have Python 3.10 or newer support.

#### **Prerequisites**

To run the utility, you must have the following 3rd party Python module installed:

* [pefile](https://pypi.org/project/pefile/)

Moreover, you must have the following 3rd party tool at PATH or "external":

* [TianoCompress](https://github.com/tianocore/edk2/tree/master/BaseTools/Source/C/TianoCompress/) (i.e. [TianoCompress.exe for Windows](https://github.com/tianocore/edk2-BaseTools-win32/) or TianoCompress for Linux/macOS)

### **Toshiba BIOS COM Extractor**

#### **Description**

Parses Toshiba BIOS COM images and extracts their raw or compressed SPI/BIOS/UEFI firmware component. This utility is effectively a python wrapper around [ToshibaComExtractor by LongSoft](https://github.com/LongSoft/ToshibaComExtractor). The output comprises only a final firmware component which is directly usable by end users.

#### **Usage**

No additional optional arguments are provided for this utility.

#### **Compatibility**

Should work at all Windows, Linux or macOS operating systems which have Python 3.10 or newer support.

Note: On Linux and macOS, you'll need to compile TianoCompress from sources as no pre-built binary exists.

#### **Prerequisites**

To run the utility, you must have the following 3rd party tool at PATH or "external":

* [ToshibaComExtractor](https://github.com/LongSoft/ToshibaComExtractor) (i.e. [comextract.exe for Windows or comextract for Linux/macOS](https://github.com/LongSoft/ToshibaComExtractor/releases))

### **VAIO Packaging Manager Extractor**

#### **Description**

Parses VAIO Packaging Manager executables and extracts their firmware (e.g. SPI, BIOS/UEFI, EC, ME etc), utilities (e.g. WBFLASH etc) and driver (audio, video etc) components. If direct extraction fails, it attempts to unlock the executable in order to run at all non-VAIO systems and allow the user to choose the extraction location. It supports all VAIO Packaging Manager revisions and formats, including those which contain obfuscated Microsoft CAB archives or obfuscated unlock values. The output comprises only final firmware components which are directly usable by end users.

#### **Usage**

No additional optional arguments are provided for this utility.

#### **Compatibility**

Should work at all Windows, Linux or macOS operating systems which have Python 3.10 or newer support.

Note: On Linux, you'll need to compile comextract from sources as no pre-built binary exists.

#### **Prerequisites**

To run the utility, you must have the following 3rd party tool at PATH or "external":

* [7-Zip Console](https://www.7-zip.org/) (i.e. 7z.exe for Windows or 7zz for macOS or 7zz, 7zzs for Linux)
