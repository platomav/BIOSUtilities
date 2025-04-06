# BIOSUtilities

## Description

BIOSUtilities is a collection of various BIOS/UEFI-related utilities which aid in research and/or modding purposes.

## Installation

BIOSUtilities is a Python 3 project at its core, but also relies on various external utilities and/or dependencies.

### Python

First, you must make sure that a compatible Python version (i.e. 3.10.x - 3.13.x) is installed:

1. Download the latest official [Python 3.13.x installer](https://www.python.org/downloads/)
2. During installation, make sure that the Optional Features "pip" and "py launcher" are both selected
3. In the Advanced Options, make sure to "associate files with Python" and add to "environment variables"
4. Once installation is complete, make sure you install all "Python Packages" and "External Dependencies"

Note: On Windows, avoid installing Python from the Microsoft Store and prefer the ["installer"](https://www.python.org/downloads/) from the official website instead.

### Requirements

There are two main types of requirements, depending on the utility: "Python Packages" and "External Executables / Scripts".

#### Python Packages

* [pefile](https://pypi.org/project/pefile/2023.2.7/)
* [dissect.util](https://pypi.org/project/dissect.util/3.20/)

Python packages can be installed via Pypi (e.g. pip)

``` bash
python -m pip install --upgrade -r requirements.txt
```

or

``` bash
python -m pip install pefile==2023.2.7 dissect.util==3.20
```

#### External Executables / Scripts

External executables and/or scripts (e.g. TianoCompress.exe, big_script_tool.py, 7z.exe) are expected to be found via the "PATH" local environment variable, by default, which is configured differently depending on the operating system.

##### Setup "PATH" on Linux

[Linux Path](https://www.digitalocean.com/community/tutorials/how-to-view-and-update-the-linux-path-environment-variable)

or

``` bash
sudo install "/path/to/downloaded/executable" /usr/local/bin
```

##### Setup "PATH" on Windows

[Windows Path](https://www.computerhope.com/issues/ch000549.htm)

Note: In the "Environment Variables" window, you can modify the "Path" variable under "User variables" instead of "System variables", contrary to what many guides suggest.

##### Setup "PATH" on MacOS

[Mac Path](https://mac.install.guide/terminal/path)

Alternatively, you can create a folder named "external" at the root of the "biosutilities" project (i.e. next to "common" directory) and place all external dependencies there.

* [7-Zip](https://www.7-zip.org/) (i.e. 7z.exe for Windows or 7zz for macOS or 7zz, 7zzs for Linux)
* [UEFIFind](https://github.com/LongSoft/UEFITool/) (i.e. [UEFIFind.exe for Windows or UEFIFind for Linux/macOS](https://github.com/LongSoft/UEFITool/releases))
* [UEFIExtract](https://github.com/LongSoft/UEFITool/) (i.e. [UEFIExtract.exe for Windows or UEFIExtract for Linux/macOS](https://github.com/LongSoft/UEFITool/releases))
* [TianoCompress](https://github.com/tianocore/edk2/tree/master/BaseTools/Source/C/TianoCompress/) (i.e. [TianoCompress.exe for Windows](https://github.com/tianocore/edk2-BaseTools-win32/) or TianoCompress for Linux/macOS)
* [ToshibaComExtractor](https://github.com/LongSoft/ToshibaComExtractor) (i.e. [comextract.exe for Windows or comextract for Linux/macOS](https://github.com/LongSoft/ToshibaComExtractor/releases))

Note: On Linux, you need to compile "comextract" from sources as no pre-built binary exists.

Note: On Linux and macOS, you need to compile "TianoCompress" from sources as no pre-built binary exists.

Optionally, to decompile the Intel BIOS Guard Scripts (when applicable), you must have the following 3rd party python script at PATH or "external":

* [BIOS Guard Script Tool](https://github.com/platomav/BGScriptTool) (i.e. big_script_tool.py)

Note: On Windows, in the "Environment Variables" window, you need to add ".PY" to the PATHEX system variable, as it may not have been added when installing Python.

## Compatibility

Unless explicitely noted, all utilities should work under Windows, Linux or macOS operating systems which have Python 3.10 - 3.13 support.

## Usage

There are two different possible flows when using the BIOSUtilities project:

* Main (simple)
* Package (advanced)

You can use either one or the other, depending on your needs. Most end-users should probably choose the "Main" flow, which is very simple to use and automatically attempts to process one or more input files against all available utilities in one run. The "Package" flow is for those who are more familiar with python and/or need to use the project programmatically as a library/dependency.

### Main

The "main" script provides a simple way to check and parse each of the user provided files against all utilities, in succession. It is ideal for quick drag & drop operations but lacks the finer control of the "Package" method.

1. Download or clone the repository to a local directory
2. Install the requirements ($PATH or "external" directory)
3. Drag and drop one or more files to the "main.py" script

If you use Linux, macOS, or the Windows command prompt/terminal, you may also call "main.py" via arguments and options, as such:

``` text
usage: main.py [-h] [-e] [-o OUTPUT_DIR] [paths ...]

positional arguments:
  paths

options:
  -h, --help                              show help and exit
  -e, --auto-exit                         do not pause on exit
  -o OUTPUT_DIR, --output-dir OUTPUT_DIR  extraction directory
```

``` text
python ./main.py "/path/to/input/file.bin" --output-dir "/path/to/file extractions"
```

If no arguments/options are provided, the "main" script requests the input and output paths from the user. If no output path is provided, the utility will use the parent directory of the first input file or fallback to the runtime execution directory.

``` text
Enter input file or directory path: "C:\P5405CSA.303"

Enter output directory path: "C:\P5405CSA.303_output"
```

### Package

Each utility is derived from a base "BIOSUtility" template and all utilities form the "biosutilities" python package, which can be installed from PyPi:

``` bash
python -m pip install --upgrade biosutilities[pefile,lznt1]
```

Installing the python package is the recommended way to call one or more utilities programatically, while fully controlling arguments and options.

``` python
from biosutilities.ami_pfat_extract import AmiPfatExtract

ami_pfat_extractor = AmiPfatExtract(input_object='/path/to/input/file.bin', extract_path='/path/to/output/folder/')

is_supported = ami_pfat_extractor.check_format()
is_extracted = ami_pfat_extractor.parse_format()
```

``` python
from biosutilities.dell_pfs_extract import DellPfsExtract

with open('/path/to/input/file.bin', 'rb') as pfs_file:
    pfs_data = pfs_file.read()

dell_pfs_extractor = DellPfsExtract(input_object=pfs_data, extract_path='/path/to/output/directory/', padding=8)

is_supported = dell_pfs_extractor.check_format()
is_extracted = dell_pfs_extractor.parse_format()
```

#### Arguments

Each BIOSUtility expects the following required and optional arguments to check and/or parse a given file format:

##### input_object (required)

``` python
input_object: str | bytes | bytearray = b''
```

##### extract_path (required)

``` python
extract_path: str = runtime_root()
```

##### padding (optional)

``` python
padding: int = 0
```

If the required arguments are not provided, placeholder values are set so that it is possible to use the BIOSUtility-inherited instance to access auxiliary public methods and class constants. However, checking and/or parsing of file formats will not yield results.

#### Methods

Once the BIOSUtility-inherited object is initialized with arguments, its two public methods can be called:

##### check_format

Check if input object is of specific supported format

``` python
is_supported: bool = check_format()
```

##### parse_format

Process input object as a specific supported format

``` python
is_extracted: bool = parse_format()
```

## Utilities

* [AMI BIOS Guard Extractor](#ami-bios-guard-extractor)
* [AMI UCP Update Extractor](#ami-ucp-update-extractor)
* [Apple EFI IM4P Splitter](#apple-efi-im4p-splitter)
* [Apple EFI Image Identifier](#apple-efi-image-identifier)
* [Apple EFI Package Extractor](#apple-efi-package-extractor)
* [Apple EFI PBZX Extractor](#apple-efi-pbzx-extractor)
* [Award BIOS Module Extractor](#award-bios-module-extractor)
* [Dell PFS Update Extractor](#dell-pfs-update-extractor)
* [Fujitsu SFX BIOS Extractor](#fujitsu-sfx-bios-extractor)
* [Fujitsu UPC BIOS Extractor](#fujitsu-upc-bios-extractor)
* [Insyde iFlash/iFdPacker Extractor](#insyde-iflashifdpacker-extractor)
* [Panasonic BIOS Package Extractor](#panasonic-bios-package-extractor)
* [Phoenix TDK Packer Extractor](#phoenix-tdk-packer-extractor)
* [Portwell EFI Update Extractor](#portwell-efi-update-extractor)
* [Toshiba BIOS COM Extractor](#toshiba-bios-com-extractor)
* [VAIO Packaging Manager Extractor](#vaio-packaging-manager-extractor)

### AMI BIOS Guard Extractor

#### Description

Parses AMI BIOS Guard (a.k.a. PFAT, Platform Firmware Armoring Technology) images, extracts their SPI/BIOS/UEFI firmware components and optionally decompiles the Intel BIOS Guard Scripts. It supports all AMI PFAT revisions and formats, including those with Index Information tables or nested AMI PFAT structures. The output comprises only final firmware components which are directly usable by end users.

Note that the AMI PFAT structure may not have an explicit component order. AMI's BIOS Guard Firmware Update Tool (AFUBGT) updates components based on the user/OEM provided Parameters and Options or Index Information table, when applicable. Thus, merging all the components together does not usually yield a proper SPI/BIOS/UEFI image. The utility does generate such a merged file with the name "00 -- ALL" but it is up to the end user to determine its usefulness. Additionally, any custom OEM data, after the AMI PFAT structure of "n" components, is stored in the last file with the name "\<n + 1\> -- OOB" and it is once again up to the end user to determine its usefulness. In cases where the data of a component includes a nested AMI PFAT structure, the utility will process and extract it automatically as well.

#### Arguments

No additional optional arguments are provided for this utility.

#### Requirements

* BIOS Guard Script Tool (optional)

### AMI UCP Update Extractor

#### Description

Parses AMI UCP (Utility Configuration Program) Update executables, extracts their firmware components (e.g. SPI/BIOS/UEFI, EC, ME etc) and shows all relevant info. It supports all AMI UCP revisions and formats, including those with nested AMI PFAT, AMI UCP or Insyde iFlash/iFdPacker structures. The output comprises only final firmware components and utilities which are directly usable by end users.

#### Arguments

Additional optional arguments are provided for this utility:

* checksum -> bool : verify AMI UCP Checksums (slow)

#### Requirements

* 7-Zip (required)
* TianoCompress (required)
* BIOS Guard Script Tool (optional)

### Apple EFI IM4P Splitter

#### Description

Parses Apple IM4P multi-EFI files and splits all detected EFI firmware into separate Intel SPI/BIOS images. The output comprises only final firmware components and utilities which are directly usable by end users.

#### Arguments

No additional optional arguments are provided for this utility.

#### Requirements

No additional requirements are needed for this utility.

### Apple EFI Image Identifier

#### Description

Parses Apple EFI images and identifies them based on Intel's official "IBIOSI" tag, which contains info such as Model, Version, Build, Date and Time. Additionally, the utility can provide both "IBIOSI" and "Apple ROM Version" structure info, when available, as well as a suggested EFI image filename, while also making sure to differentiate any EFI images with the same "IBIOSI" tag (e.g. Production, Pre-Production) by appending a checksum of their data.

#### Arguments

Additional optional arguments are provided for this utility:

* silent -> bool : suppress structure display

The utility exposes certain public class attributes, once parse_format() method has been successfully executed:

* efi_file_name -> str : Suggested image filename, based on Intel "IBIOSI" information
* intel_bios_info -> dict[str, str] : Information contained at Intel "IBIOSI" structure
* apple_rom_version -> dict[str, str] : Information contained at "Apple ROM Version" structure

#### Requirements

* UEFIFind (required)
* UEFIExtract (required)

### Apple EFI Package Extractor

#### Description

Parses Apple EFI PKG firmware packages (e.g. FirmwareUpdate.pkg, BridgeOSUpdateCustomer.pkg, InstallAssistant.pkg, iMacEFIUpdate.pkg, iMacFirmwareUpdate.tar), extracts their EFI images, splits those in IM4P format and identifies/renames the final Intel SPI/BIOS images accordingly. The output comprises only final firmware components which are directly usable by end users.

#### Arguments

No additional optional arguments are provided for this utility.

#### Requirements

* 7-Zip (required)
* UEFIFind (required)
* UEFIExtract (required)

### Apple EFI PBZX Extractor

#### Description

Parses Apple EFI PBZX images, re-assembles their CPIO payload and extracts its firmware components (e.g. IM4P, EFI, Utilities, Scripts etc). It supports CPIO re-assembly from both Raw and XZ compressed PBZX Chunks. The output comprises only final firmware components and utilities which are directly usable by end users.

#### Arguments

No additional optional arguments are provided for this utility.

#### Requirements

* 7-Zip (required)

### Award BIOS Module Extractor

#### Description

Parses Award BIOS images and extracts their modules (e.g. RAID, MEMINIT, \_EN_CODE, awardext etc). It supports all Award BIOS image revisions and formats, including those which contain LZH compressed files. The output comprises only final firmware components which are directly usable by end users.

#### Arguments

No additional optional arguments are provided for this utility.

#### Requirements

* 7-Zip (required)

### Dell PFS Update Extractor

#### Description

Parses Dell PFS Update images and extracts their Firmware (e.g. SPI, BIOS/UEFI, EC, ME etc) and Utilities (e.g. Flasher etc) component sections. It supports all Dell PFS revisions and formats, including those which are originally LZMA compressed in ThinOS packages (PKG), ZLIB compressed or Intel BIOS Guard (PFAT) protected. The output comprises only final firmware components which are directly usable by end users.

#### Arguments

Additional optional arguments are provided for this utility:

* advanced -> bool : extract signatures and metadata
* structure -> bool : show PFS structure information

#### Requirements

* BIOS Guard Script Tool (optional)

### Fujitsu SFX BIOS Extractor

#### Description

Parses Fujitsu SFX BIOS images and extracts their obfuscated Microsoft CAB archived firmware (e.g. SPI, BIOS/UEFI, EC, ME etc) and utilities (e.g. WinPhlash, PHLASH.INI etc) components. The output comprises only final firmware components which are directly usable by end users.

#### Arguments

No additional optional arguments are provided for this utility.

#### Requirements

* 7-Zip (required)

### Fujitsu UPC BIOS Extractor

#### Description

Parses Fujitsu UPC BIOS images and extracts their EFI compressed SPI/BIOS/UEFI firmware component. The output comprises only a final firmware component which is directly usable by end users.

#### Arguments

No additional optional arguments are provided for this utility.

#### Requirements

* TianoCompress (required)

### Insyde iFlash/iFdPacker Extractor

#### Description

Parses Insyde iFlash/iFdPacker Update images and extracts their firmware (e.g. SPI, BIOS/UEFI, EC, ME etc) and utilities (e.g. InsydeFlash, H2OFFT, FlsHook, iscflash, platform.ini etc) components. It supports all Insyde iFlash/iFdPacker revisions and formats, including those which are 7-Zip SFX 7z compressed in raw, obfuscated or password-protected form. The output comprises only final firmware components which are directly usable by end users.

#### Arguments

No additional optional arguments are provided for this utility.

#### Requirements

No additional requirements are needed for this utility.

### Panasonic BIOS Package Extractor

#### Description

Parses Panasonic BIOS Package executables and extracts their firmware (e.g. SPI, BIOS/UEFI, EC etc) and utilities (e.g. winprom, configuration etc) components. It supports all Panasonic BIOS Package revisions and formats, including those which contain LZNT1 compressed files and/or AMI PFAT payloads. The output comprises only final firmware components which are directly usable by end users.

#### Arguments

No additional optional arguments are provided for this utility.

#### Requirements

* 7-Zip (required)
* pefile (required)
* dissect.util (required)

### Phoenix TDK Packer Extractor

#### Description

Parses Phoenix Tools Development Kit (TDK) Packer executables and extracts their firmware (e.g. SPI, BIOS/UEFI, EC etc) and utilities (e.g. WinFlash etc) components. It supports all Phoenix TDK Packer revisions and formats, including those which contain LZMA compressed files. The output comprises only final firmware components which are directly usable by end users.

#### Arguments

No additional optional arguments are provided for this utility.

#### Requirements

* pefile (required)

### Portwell EFI Update Extractor

#### Description

Parses Portwell UEFI Unpacker EFI executables (usually named "Update.efi") and extracts their firmware (e.g. SPI, BIOS/UEFI, EC etc) and utilities (e.g. Flasher etc) components. It supports all known Portwell UEFI Unpacker revisions (v1.1, v1.2, v2.0) and formats (used, empty, null), including those which contain EFI compressed files. The output comprises only final firmware components and utilities which are directly usable by end users.

#### Arguments

No additional optional arguments are provided for this utility.

#### Requirements

* pefile (required)
* TianoCompress (required)

### Toshiba BIOS COM Extractor

#### Description

Parses Toshiba BIOS COM images and extracts their raw or compressed SPI/BIOS/UEFI firmware component. This utility is effectively a python wrapper around [ToshibaComExtractor by LongSoft](https://github.com/LongSoft/ToshibaComExtractor). The output comprises only a final firmware component which is directly usable by end users.

#### Arguments

No additional optional arguments are provided for this utility.

#### Requirements

* ToshibaComExtractor (required)

### VAIO Packaging Manager Extractor

#### Description

Parses VAIO Packaging Manager executables and extracts their firmware (e.g. SPI, BIOS/UEFI, EC, ME etc), utilities (e.g. WBFLASH etc) and driver (audio, video etc) components. If direct extraction fails, it attempts to unlock the executable in order to run at all non-VAIO systems and allow the user to choose the extraction location. It supports all VAIO Packaging Manager revisions and formats, including those which contain obfuscated Microsoft CAB archives or obfuscated unlock values. The output comprises only final firmware components which are directly usable by end users.

#### Arguments

No additional optional arguments are provided for this utility.

#### Requirements

* 7-Zip (required)
