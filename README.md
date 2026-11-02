Title: EVGA SMARTEIO64.SYS physical memory map

Vendor: EVGA Technology Inc.
Product: Windows Vista64 Smart IO Device
Component: SMARTEIO64.SYS
SHA-256: 3c95ebf3f1a87f67d2861dbd1c85dc26c118610af0c9fbf4180428e653ac3e50
MD5: bdd8dc8880dfbc19d729ca51071de288
SHA-1: 87d2b638e5dfab1e37961d27ca734b83ece02804
Size: 20456 bytes
PE timestamp: 2008-11-18 11:53:50 UTC
FileVersion: 5.13.01.2008-1.00
ProductVersion: 5.13.01.2008-1.00
OriginalFilename: SMARTEIO64.SYS
Authenticode status: Valid
Signer: CN=EVGA, OU=Digital ID Class 3 - Microsoft Software Validation v2, O=EVGA, L=Brea, S=California, C=US
Certificate thumbprint: 0264582638037B0BB2E74AD1289450D1584AED8A
Certificate not before: 2008-04-16 00:00:00 UTC
Certificate not after: 2010-04-16 23:59:59 UTC
Device: \\.\SMARTEIO64
PDB: d:\product\xpdriver\io\io64\amd64\SMARTEIO64.pdb

CVE:

Description:
SMARTEIO64.SYS in EVGA Technology Inc. Windows Vista64 Smart IO Device FileVersion 5.13.01.2008-1.00 (SHA-256 3c95ebf3f1a87f67d2861dbd1c85dc26c118610af0c9fbf4180428e653ac3e50, 20456 bytes, PE timestamp 2008-11-18 11:53:50 UTC) passes a caller-supplied 32-bit physical address and a caller-supplied length to MmMapIoSpace for command 0xD, clears the high 32 bits of that address before the call, does not validate the address range, maps the range as non-cached, and returns a writable user-mode mapping while storing only the low 32 bits of the user address, which allows a local user to read and write arbitrary physical memory at a caller-chosen 32-bit physical address and to escalate privileges locally via \\.\SMARTEIO64. The driver does not compare IoControlCode. The tested call used buffered IOCTL 0x00222000 so the mapping address was copied back to the caller. VERSIONINFO CompanyName is EVGA Technology Inc., ProductName and FileDescription are Windows Vista64 Smart IO Device, FileVersion and ProductVersion are 5.13.01.2008-1.00, and OriginalFilename is SMARTEIO64.SYS. The Authenticode status is Valid, signed by CN=EVGA, OU=Digital ID Class 3 - Microsoft Software Validation v2, O=EVGA, L=Brea, S=California, C=US, thumbprint 0264582638037B0BB2E74AD1289450D1584AED8A. On 2026-11-03, on an isolated Windows 10 Enterprise LTSC 2021 virtual machine (10.0.19044.7807), an administrator loaded this file and the service started. The administrator locked one of its own pages at physical address 0xbb904000 and did not send command 0xD. Local account aida-low, a member of Users and not a member of Administrators, opened \\.\SMARTEIO64 and sent command 0xD for that address with length 0x10. The driver returned user address 0x00180000. Through that mapping, aida-low wrote 0x5A and read 0x5A back, then wrote 0xA5 and read 0xA5 back. The administrator read the first byte of that physical page and saw 0x5A, then 0xA5. The test did not show a crash. The device security descriptor was O:BAG:SYD:(A;;0x1201bf;;;WD)(A;;FA;;;SY)(A;;FA;;;BA)(A;;0x1200a9;;;RC)S:AI(ML;;NW;;;LW). Everyone (WD) has access mask 0x1201bf, which includes FILE_READ_DATA and FILE_WRITE_DATA.

Suggested fix: on command 0xD, map only a physical address chosen inside the driver, and limit access to \\.\SMARTEIO64 to Administrators and SYSTEM.
