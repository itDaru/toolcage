use std::env;
use std::fs::File;
use std::io::{self, Read};
use std::path::Path;

// Defines the number of bytes to display.
const DISPLAY_BYTES_LENGTH: usize = 8;
// Defines the maximum number of bytes to read from the file.
const READ_BUFFER_SIZE: usize = 40;

/// Identifies a file type based on its magic number.
///
/// This function checks the provided byte slice against a known set of magic numbers
/// to determine the file type. It can check for magic numbers at different offsets.
///
/// # Arguments
///
/// * `buffer` - A byte slice containing the file's initial bytes.
///
/// # Returns
///
/// A string slice (`&'static str`) with the name of the file type or
/// "Unknown magic number" if no match is found.
fn identify_file_type(buffer: &[u8]) -> &'static str {
    // The magic number "database" is implemented as a series of `if` checks.
    // This approach is efficient for a small, fixed set of patterns and handles
    // variable-length magic numbers cleanly.

    if buffer.starts_with(b"-----BEGIN CERTIFICATE-----") {
        "PEM encoded X.509 certificate"
    } else if buffer.starts_with(b"-----BEGIN CERTIFICATE REQUEST-----") {
        "PEM encoded X.509 Certificate Signing Request"
    } else if buffer.starts_with(b"-----BEGIN PRIVATE KEY-----") {
        "PEM encoded X.509 PKCS#8 private key"
    } else if buffer.starts_with(b"-----BEGIN DSA PRIVATE KEY-----") {
        "PEM encoded X.509 PKCS#1 DSA private key"
    } else if buffer.starts_with(b"-----BEGIN RSA PRIVATE KEY-----") {
        "PEM encoded X.509 PKCS#1 RSA private key"
    } else if buffer.starts_with(b"PuTTY-User-Key-File-2:") {
        "PuTTY private key file version 2"
    } else if buffer.starts_with(b"PuTTY-User-Key-File-3:") {
        "PuTTY private key file version 3"
    } else if buffer.starts_with(b"-----BEGIN OPENSSH PRIVATE KEY-----") {
        "OpenSSH private key file"
    } else if buffer.starts_with(b"-----BEGIN SSH2 PUBLIC KEY-----") {
        "OpenSSH public key file"
    } else if buffer.starts_with(&[0x89, 0x50, 0x4E, 0x47, 0x0D, 0x0A, 0x1A, 0x0A]) {
        "PNG image"
    } else if buffer.starts_with(&[0x50, 0x4B, 0x03, 0x04]) {
        "ZIP archive"
    } else if buffer.starts_with(&[0xFF, 0xD8, 0xFF, 0xE0]) {
        "JPEG image (JFIF)"
    } else if buffer.starts_with(&[0xFF, 0xD8, 0xFF, 0xE1]) {
        "JPEG image (Exif)"
    } else if buffer.starts_with(&[0x47, 0x49, 0x46, 0x38, 0x37, 0x61]) || buffer.starts_with(&[0x47, 0x49, 0x46, 0x38, 0x39, 0x61]) {
        "GIF image"
    } else if buffer.starts_with(&[0x25, 0x50, 0x44, 0x46]) {
        "PDF document"
    } else if buffer.starts_with(&[0x7F, 0x45, 0x4C, 0x46]) {
        "ELF executable"
    } else if buffer.starts_with(&[0x42, 0x4D]) {
        "Bitmap format (.bmp)"
    } else if buffer.starts_with(&[0x53, 0x49, 0x4D, 0x50, 0x4C, 0x45]) {
        "FITS format (.fits)"
    } else if buffer.starts_with(&[0x47, 0x4B, 0x53, 0x4D]) {
        "Graphics Kernel System (.gks)"
    } else if buffer.starts_with(&[0x01, 0xDA]) {
        "IRIS rgb format (.rgb)"
    } else if buffer.starts_with(&[0xF1, 0x00, 0x40, 0xBB]) {
        "ITC (CMU WM) format (.itc)"
    } else if buffer.starts_with(&[0x49, 0x49, 0x4E, 0x31]) {
        "NIFF (Navy TIFF) (.nif)"
    } else if buffer.starts_with(&[0x56, 0x49, 0x45, 0x57]) {
        "PM format (.pm)"
    } else if buffer.starts_with(&[0x25, 0x21]) {
        "Postscript format (.ps, .eps)"
    } else if buffer.starts_with(&[0x59, 0xA6, 0x6A, 0x95]) {
        "Sun Rasterfile (.ras)"
    } else if buffer.starts_with(&[0x4D, 0x4D, 0x00, 0x2A]) {
        "TIFF format (Motorola - big endian) (.tif)"
    } else if buffer.starts_with(&[0x49, 0x49, 0x2A, 0x00]) {
        "TIFF format (Intel - little endian) (.tif)"
    } else if buffer.starts_with(&[0x67, 0x69, 0x6D, 0x70, 0x20, 0x78, 0x63, 0x66]) {
        "XCF Gimp file structure (.xcf)"
    } else if buffer.starts_with(&[0x23, 0x46, 0x49, 0x47]) {
        "Xfig format (.fig)"
    } else if buffer.starts_with(&[0x2F, 0x2A, 0x20, 0x58, 0x50, 0x4D]) {
        "XPM format (.xpm)"
    } else if buffer.starts_with(&[0x42, 0x5A]) {
        "Bzip (.bz)"
    } else if buffer.starts_with(&[0x1F, 0x9D]) {
        "Compress (.Z)"
    } else if buffer.starts_with(&[0x1F, 0x8B]) {
        "gzip format (.gz)"
    } else if buffer.starts_with(&[0x4D, 0x5A]) {
        "MS-DOS, OS/2 or MS Windows executable"
    } else if buffer.starts_with(&[0x99, 0x00]) {
        "pgp public ring"
    } else if buffer.starts_with(&[0x95, 0x01]) {
        "pgp security ring"
    } else if buffer.starts_with(&[0x95, 0x00]) {
        "pgp security ring"
    } else if buffer.starts_with(&[0xA6, 0x00]) {
        "pgp encrypted data"
    } else if buffer.starts_with(&[0x23, 0x21]) {
        "Script or data to be passed to the program following the shebang (#!)"
    } else if buffer.starts_with(&[0x02, 0x00, 0x5A, 0x57, 0x52, 0x54, 0x00, 0x00]) {
        "Claris Works word processing doc"
    } else if buffer.starts_with(&[0x00, 0x00, 0x02, 0x00, 0x06, 0x04, 0x06, 0x00]) {
        "Lotus 1-2-3 spreadsheet (v1) file"
    } else if buffer.starts_with(&[0x00, 0x00, 0x1A, 0x00, 0x00, 0x10, 0x04, 0x00]) {
        "Lotus 1-2-3 spreadsheet (v3) file"
    } else if buffer.starts_with(&[0x00, 0x00, 0x1A, 0x00, 0x02, 0x10, 0x04, 0x00]) {
        "Lotus 1-2-3 spreadsheet (v4, v5) file"
    } else if buffer.starts_with(&[0x00, 0x00, 0x1A, 0x00, 0x05, 0x10, 0x04]) {
        "Lotus 1-2-3 spreadsheet (v9) file"
    } else if buffer.starts_with(&[0x00, 0x00, 0x03, 0xF3]) {
        "Amiga Hunk executable file"
    } else if buffer.starts_with(&[0x00, 0x00, 0x49, 0x49, 0x58, 0x50, 0x52]) {
        "Quark Express document (little-endian)"
    } else if buffer.starts_with(&[0x00, 0x00, 0x4D, 0x4D, 0x58, 0x50, 0x52]) {
        "Quark Express document (big-endian)"
    } else if buffer.starts_with(&[0x50, 0x57, 0x53, 0x33]) {
        "Password Gorilla Password Database"
    } else if buffer.starts_with(&[0xD4, 0xC3, 0xB2, 0xA1]) {
        "Libpcap File Format (little-endian)"
    } else if buffer.starts_with(&[0xA1, 0xB2, 0xC3, 0xD4]) {
        "Libpcap File Format (big-endian)"
    } else if buffer.starts_with(&[0x4D, 0x3C, 0xB2, 0xA1]) {
        "Libpcap File Format (nanosecond-resolution, little-endian)"
    } else if buffer.starts_with(&[0xA1, 0xB2, 0x3C, 0x4D]) {
        "Libpcap File Format (nanosecond-resolution, big-endian)"
    } else if buffer.starts_with(&[0x0A, 0x0D, 0x0D, 0x0A]) {
        "PCAP Next Generation Dump File Format"
    } else if buffer.starts_with(&[0xED, 0xAB, 0xEE, 0xDB]) {
        "RedHat Package Manager (RPM) package"
    } else if buffer.starts_with(&[0x53, 0x51, 0x4C, 0x69, 0x74, 0x65, 0x20, 0x66]) {
        "SQLite Database"
    } else if buffer.starts_with(&[0x53, 0x50, 0x30, 0x31]) {
        "Amazon Kindle Update Package"
    } else if buffer.starts_with(&[0x49, 0x57, 0x41, 0x44]) {
        "internal WAD (main resource file of Doom)"
    } else if buffer.starts_with(&[0x00]) {
        "IBM Storyboard bitmap file, Windows Program Information File, Mac Stuffit Self-Extracting Archive, or IRIS OCR data file"
    } else if buffer.starts_with(&[0xBE, 0xBA, 0xFE, 0xCA]) {
        "Palm Desktop Calendar Archive"
    } else if buffer.starts_with(&[0x00, 0x01, 0x42, 0x44]) {
        "Palm Desktop To Do Archive"
    } else if buffer.starts_with(&[0x00, 0x01, 0x44, 0x54]) {
        "Palm Desktop Calendar Archive"
    } else if buffer.starts_with(&[0x54, 0x44, 0x46, 0x24]) {
        "Telegram Desktop File"
    } else if buffer.starts_with(&[0x54, 0x44, 0x45, 0x46]) {
        "Telegram Desktop Encrypted File"
    } else if buffer.starts_with(&[0x00, 0x01, 0x00, 0x00]) {
        "Palm Desktop Data File (Access format)"
    } else if buffer.starts_with(&[0x00, 0x00, 0x01, 0x00]) {
        "Computer icon encoded in ICO file format"
    } else if buffer.starts_with(&[0x69, 0x63, 0x6E, 0x73]) {
        "Apple Icon Image format"
    } else if buffer.starts_with(&[0x1F, 0xA0]) {
        "Compressed file (often tar zip) using LZH algorithm"
    } else if buffer.starts_with(&[0x42, 0x41, 0x43, 0x4B, 0x4D, 0x49, 0x4B, 0x45]) {
        "AmiBack Amiga Backup data file"
    } else if buffer.starts_with(&[0x49, 0x4E, 0x44, 0x58]) {
        "AmiBack Amiga Backup index file"
    } else if buffer.starts_with(&[0x62, 0x70, 0x6C, 0x69, 0x73, 0x74]) {
        "Binary Property List file"
    } else if buffer.starts_with(&[0x42, 0x5A, 0x68]) {
        "Compressed file using Bzip2 algorithm"
    } else if buffer.starts_with(&[0x49, 0x49, 0x2B, 0x00]) {
        "BigTIFF (little-endian)"
    } else if buffer.starts_with(&[0x4D, 0x4D, 0x00, 0x2B]) {
        "BigTIFF (big-endian)"
    } else if buffer.starts_with(&[0x49, 0x49, 0x2A, 0x00, 0x10, 0x00, 0x00, 0x00]) {
        "Canon RAW Format Version 2"
    } else if buffer.starts_with(&[0x66, 0x74, 0x79, 0x70, 0x63, 0x72, 0x78]) {
        "Canon RAW Format Version 3"
    } else if buffer.starts_with(&[0x80, 0x2A, 0x5F, 0xD7]) {
        "Kodak Cineon image"
    } else if buffer.starts_with(&[0x52, 0x4E, 0x43, 0x01]) || buffer.starts_with(&[0x52, 0x4E, 0x43, 0x02]) {
        "Compressed file using Rob Northen Compression (version 1 and 2) algorithm"
    } else if buffer.starts_with(&[0x4E, 0x55, 0x52, 0x55, 0x49, 0x4D, 0x47]) {
        "nuru ASCII/ANSI image file"
    } else if buffer.starts_with(&[0x4E, 0x55, 0x52, 0x55, 0x50, 0x41, 0x4C]) {
        "nuru ASCII/ANSI palette file"
    } else if buffer.starts_with(&[0x53, 0x44, 0x50, 0x58]) {
        "SMPTE DPX image (big-endian format)"
    } else if buffer.starts_with(&[0x58, 0x50, 0x44, 0x53]) {
        "SMPTE DPX image (little-endian format)"
    } else if buffer.starts_with(&[0x76, 0x2F, 0x31, 0x01]) {
        "OpenEXR image"
    } else if buffer.starts_with(&[0x42, 0x50, 0x47, 0xFB]) {
        "Better Portable Graphics format"
    } else if buffer.starts_with(&[0xFF, 0xD8, 0xFF, 0xDB]) {
        "JPEG raw or in the JFIF or Exif file format"
    } else if buffer.starts_with(&[0xFF, 0xD8, 0xFF, 0xEE]) {
        "JPEG raw or in the JFIF or Exif file format"
    } else if buffer.starts_with(&[0x00, 0x00, 0x00, 0x0C, 0x6A, 0x50, 0x20, 0x20]) {
        "JPEG 2000 format"
    } else if buffer.starts_with(&[0xFF, 0x4F, 0xFF, 0x51]) {
        "JPEG 2000 format"
    } else if buffer.starts_with(&[0x71, 0x6f, 0x69, 0x66]) {
        "QOI - The “Quite OK Image Format”"
    } else if buffer.starts_with(&[0x4C, 0x5A, 0x49, 0x50]) {
        "lzip compressed file"
    } else if buffer.starts_with(&[0x30, 0x37, 0x30, 0x37, 0x30, 0x37]) {
        "cpio archive file"
    } else if buffer.starts_with(&[0x53, 0x4D, 0x53, 0x4E, 0x46, 0x32, 0x30, 0x30]) {
        "SmartSniff Packets File"
    } else if buffer.starts_with(&[0x5A, 0x4D]) {
        "DOS ZM executable and its descendants (rare)"
    } else if buffer.starts_with(&[0x52, 0x61, 0x72, 0x21, 0x1A, 0x07, 0x00]) {
        "Roshal ARchive compressed archive v1.50 onwards"
    } else if buffer.starts_with(&[0x52, 0x61, 0x72, 0x21, 0x1A, 0x07, 0x01, 0x00]) {
        "Roshal ARchive compressed archive v5.00 onwards"
    } else if buffer.starts_with(&[0x0E, 0x03, 0x13, 0x01]) {
        "Data stored in version 4 of the Hierarchical Data Format."
    } else if buffer.starts_with(&[0x89, 0x48, 0x44, 0x46, 0x0D, 0x0A, 0x1A, 0x0A]) {
        "Data stored in version 5 of the Hierarchical Data Format."
    } else if buffer.starts_with(&[0xC9]) {
        "CP/M 3 and higher with overlays"
    } else if buffer.starts_with(&[0xCA, 0xFE, 0xBA, 0xBE]) {
        "Java class file, Mach-O Fat Binary"
    } else if buffer.starts_with(&[0xEF, 0xBB, 0xBF]) {
        "UTF-8 byte order mark"
    } else if buffer.starts_with(&[0xFF, 0xFE]) {
        "UTF-16LE byte order mark"
    } else if buffer.starts_with(&[0xFE, 0xFF]) {
        "UTF-16BE byte order mark"
    } else if buffer.starts_with(&[0xFF, 0xFE, 0x00, 0x00]) {
        "UTF-32LE byte order mark for text"
    } else if buffer.starts_with(&[0x00, 0x00, 0xFE, 0xFF]) {
        "UTF-32BE byte order mark for text"
    } else if buffer.starts_with(&[0x2B, 0x2F, 0x76, 0x38]) || buffer.starts_with(&[0x2B, 0x2F, 0x76, 0x39]) || buffer.starts_with(&[0x2B, 0x2F, 0x76, 0x2B]) || buffer.starts_with(&[0x2B, 0x2F, 0x76, 0x2F]) {
        "UTF-7 byte order mark for text"
    } else if buffer.starts_with(&[0x0E, 0xFE, 0xFF]) {
        "SCSU byte order mark for text"
    } else if buffer.starts_with(&[0xDD, 0x73, 0x66, 0x73]) {
        "UTF-EBCDIC byte order mark for text"
    } else if buffer.starts_with(&[0xFE, 0xED, 0xFA, 0xCE]) {
        "Mach-O binary (32-bit)"
    } else if buffer.starts_with(&[0xFE, 0xED, 0xFA, 0xCF]) {
        "Mach-O binary (64-bit)"
    } else if buffer.starts_with(&[0xFE, 0xED, 0xFE, 0xED]) {
        "JKS Javakey Store"
    } else if buffer.starts_with(&[0xCE, 0xFA, 0xED, 0xFE]) {
        "Mach-O binary (reverse byte ordering scheme, 32-bit)"
    } else if buffer.starts_with(&[0xCF, 0xFA, 0xED, 0xFE]) {
        "Mach-O binary (reverse byte ordering scheme, 64-bit)"
    } else if buffer.starts_with(&[0x25, 0x21, 0x50, 0x53]) {
        "PostScript document"
    } else if buffer.starts_with(&[0x49, 0x54, 0x53, 0x46, 0x03, 0x00, 0x00, 0x00]) {
        "MS Windows HtmlHelp Data"
    } else if buffer.starts_with(&[0x3F, 0x5F]) {
        "Windows 3.x/95/98 Help file"
    } else if buffer.starts_with(&[0x30, 0x26, 0xB2, 0x75, 0x8E, 0x66, 0xCF, 0x11]) {
        "Advanced Systems Format"
    } else if buffer.starts_with(&[0x24, 0x53, 0x44, 0x49, 0x30, 0x30, 0x30, 0x31]) {
        "System Deployment Image"
    } else if buffer.starts_with(&[0x4F, 0x67, 0x67, 0x53]) {
        "Ogg, an open source media container format"
    } else if buffer.starts_with(&[0x38, 0x42, 0x50, 0x53]) {
        "Photoshop Document file"
    } else if buffer.starts_with(&[0x52, 0x49, 0x46, 0x46]) {
        "Waveform Audio File Format or Audio Video Interleave video format"
    } else if buffer.starts_with(&[0xFF, 0xFB]) || buffer.starts_with(&[0xFF, 0xF3]) || buffer.starts_with(&[0xFF, 0xF2]) {
        "MPEG-1 Layer 3 file without an ID3 tag or with an ID3v1 tag"
    } else if buffer.starts_with(&[0x49, 0x44, 0x33]) {
        "MP3 file with an ID3v2 container"
    } else if buffer.starts_with(&[0x6D, 0x61, 0x69, 0x6E, 0x2E, 0x62, 0x73]) {
        "Nintendo Game & Watch image file"
    } else if buffer.starts_with(&[0x4E, 0x45, 0x53]) {
        "Nintendo Entertainment System image file"
    } else if buffer.starts_with(&[0x47, 0x53, 0x52, 0x2D, 0x31, 0x35, 0x34, 0x31]) {
        "Commodore 64 1541 disk image (G64 format)"
    } else if buffer.starts_with(&[0x43, 0x36, 0x34, 0x20, 0x74, 0x61, 0x70, 0x65, 0x20, 0x69, 0x6D, 0x61, 0x67, 0x65, 0x20, 0x66, 0x69, 0x6C, 0x65]) {
        "Commodore 64 tape image"
    } else if buffer.starts_with(&[0x43, 0x36, 0x34, 0x20, 0x43, 0x41, 0x52, 0x54, 0x52, 0x49, 0x44, 0x47, 0x45, 0x20, 0x20, 0x20]) {
        "Commodore 64 cartridge image"
    } else if buffer.starts_with(&[0x66, 0x4C, 0x61, 0x43]) {
        "Free Lossless Audio Codec"
    } else if buffer.starts_with(&[0x4D, 0x54, 0x68, 0x64]) {
        "MIDI sound file"
    } else if buffer.starts_with(&[0xD0, 0xCF, 0x11, 0xE0, 0xA1, 0xB1, 0x1A, 0xE1]) {
        "Compound File Binary Format"
    } else if buffer.starts_with(&[0x64, 0x65, 0x78, 0x0A, 0x30, 0x33, 0x35, 0x00]) {
        "Dalvik Executable"
    } else if buffer.starts_with(&[0x4B, 0x44, 0x4D]) {
        "VMDK files"
    } else if buffer.starts_with(&[0x23, 0x20, 0x44, 0x69, 0x73, 0x6B, 0x20, 0x44, 0x65, 0x73, 0x63, 0x72, 0x69, 0x70, 0x74, 0x6F]) {
        "VMware 4 Virtual Disk description file (split disk)"
    } else if buffer.starts_with(&[0x43, 0x72, 0x32, 0x34]) {
        "Google Chrome extension or packaged app"
    } else if buffer.starts_with(&[0x41, 0x47, 0x44, 0x33]) {
        "FreeHand 8 document"
    } else if buffer.starts_with(&[0x05, 0x07, 0x00, 0x00, 0x42, 0x4F, 0x42, 0x4F]) {
        "AppleWorks 5 document"
    } else if buffer.starts_with(&[0x06, 0x07, 0xE1, 0x00, 0x42, 0x4F, 0x42, 0x4F]) {
        "AppleWorks 6 document"
    } else if buffer.starts_with(&[0x45, 0x52, 0x02, 0x00, 0x00, 0x00]) {
        "Roxio Toast disc image file"
    } else if buffer.starts_with(&[0x8B, 0x45, 0x52, 0x02, 0x00, 0x00, 0x00]) {
        "Roxio Toast disc image file"
    } else if buffer.starts_with(&[0x78, 0x61, 0x72, 0x21]) {
        "eXtensible ARchive format"
    } else if buffer.starts_with(&[0x50, 0x4D, 0x4F, 0x43, 0x43, 0x4D, 0x4F, 0x43]) {
        "Windows Files And Settings Transfer Repository"
    } else if buffer.starts_with(&[0x4E, 0x45, 0x53, 0x1A]) {
        "Nintendo Entertainment System ROM file"
    } else if buffer.starts_with(&[0x4F, 0x41, 0x52]) {
        "OAR file archive format"
    } else if buffer.starts_with(&[0x74, 0x6F, 0x78, 0x33]) {
        "Open source portable voxel file"
    } else if buffer.starts_with(&[0x4D, 0x4C, 0x56, 0x49]) {
        "Magic Lantern Video file"
    } else if buffer.starts_with(&[0x44, 0x43, 0x4D, 0x01, 0x50, 0x41, 0x33, 0x30]) {
        "Windows Update Binary Delta Compression file"
    } else if buffer.starts_with(&[0x37, 0x7A, 0xBC, 0xAF, 0x27, 0x1C]) {
        "7-Zip File Format"
    } else if buffer.starts_with(&[0xFD, 0x37, 0x7A, 0x58, 0x5A, 0x00]) {
        "XZ compression utility using LZMA2 compression"
    } else if buffer.starts_with(&[0x04, 0x22, 0x4D, 0x18]) {
        "LZ4 Frame Format"
    } else if buffer.starts_with(&[0x4D, 0x53, 0x43, 0x46]) {
        "Microsoft Cabinet file"
    } else if buffer.starts_with(&[0x53, 0x5A, 0x44, 0x44, 0x88, 0xF0, 0x27, 0x33]) {
        "Microsoft compressed file in Quantum format"
    } else if buffer.starts_with(&[0x46, 0x4C, 0x49, 0x46]) {
        "Free Lossless Image Format"
    } else if buffer.starts_with(&[0x1A, 0x45, 0xDF, 0xA3]) {
        "Matroska media container, including WebM"
    } else if buffer.starts_with(&[0x4D, 0x49, 0x4C, 0x20]) {
        "SEAN : Session Analysis Training file"
    } else if buffer.starts_with(&[0x41, 0x54, 0x26, 0x54, 0x46, 0x4F, 0x52, 0x4D]) {
        "DjVu document"
    } else if buffer.starts_with(&[0x77, 0x4F, 0x46, 0x46]) {
        "WOFF File Format 1.0"
    } else if buffer.starts_with(&[0x77, 0x4F, 0x46, 0x32]) {
        "WOFF File Format 2.0"
    } else if buffer.starts_with(&[0x3C, 0x3F, 0x78, 0x6D, 0x6C, 0x20]) {
        "eXtensible Markup Language (UTF-8 or other 8-bit encodings)"
    } else if buffer.starts_with(&[0x00, 0x61, 0x73, 0x6D]) {
        "WebAssembly binary format"
    } else if buffer.starts_with(&[0xCF, 0x84, 0x01]) {
        "Lepton compressed JPEG image"
    } else if buffer.starts_with(&[0x43, 0x57, 0x53]) {
        "Adobe Flash .swf"
    } else if buffer.starts_with(&[0x46, 0x57, 0x53]) {
        "Adobe Flash .swf"
    } else if buffer.starts_with(&[0x21, 0x3C, 0x61, 0x72, 0x63, 0x68, 0x3E, 0x0A]) {
        "linux deb file"
    } else if buffer.starts_with(&[0x27, 0x05, 0x19, 0x56]) {
        "U-Boot / uImage"
    } else if buffer.starts_with(&[0x7B, 0x5C, 0x72, 0x74, 0x66, 0x31]) {
        "Rich Text Format"
    } else if buffer.starts_with(&[0x54, 0x41, 0x50, 0x45]) {
        "Microsoft Tape Format"
    } else if buffer.starts_with(&[0x47]) {
        "MPEG Transport Stream (MPEG-2 Part 1)"
    } else if buffer.starts_with(&[0x00, 0x00, 0x01, 0xBA]) {
        "MPEG Program Stream (MPEG-1 Part 1 and MPEG-2 Part 1)"
    } else if buffer.starts_with(&[0x00, 0x00, 0x01, 0xB3]) {
        "MPEG-1 video and MPEG-2 video"
    } else if buffer.starts_with(&[0x78, 0x01]) {
        "zlib No Compression (no preset dictionary)"
    } else if buffer.starts_with(&[0x78, 0x5E]) {
        "zlib Best speed (no preset dictionary)"
    } else if buffer.starts_with(&[0x78, 0x9C]) {
        "zlib Default Compression (no preset dictionary)"
    } else if buffer.starts_with(&[0x78, 0xDA]) {
        "zlib Best Compression (no preset dictionary)"
    } else if buffer.starts_with(&[0x78, 0x20]) {
        "zlib No Compression (with preset dictionary)"
    } else if buffer.starts_with(&[0x78, 0x7D]) {
        "zlib Best speed (with preset dictionary)"
    } else if buffer.starts_with(&[0x78, 0xBB]) {
        "zlib Default Compression (with preset dictionary)"
    } else if buffer.starts_with(&[0x78, 0xF9]) {
        "zlib Best Compression (with preset dictionary)"
    } else if buffer.starts_with(&[0x62, 0x76, 0x78, 0x32]) {
        "LZFSE - Lempel-Ziv style data compression algorithm using Finite State Entropy coding"
    } else if buffer.starts_with(&[0x4F, 0x52, 0x43]) {
        "Apache ORC (Optimized Row Columnar) file format"
    } else if buffer.starts_with(&[0x4F, 0x62, 0x6A, 0x01]) {
        "Apache Avro binary file format"
    } else if buffer.starts_with(&[0x53, 0x45, 0x51, 0x36]) {
        "RCFile columnar file format"
    } else if buffer.starts_with(&[0x3C, 0x72, 0x6F, 0x62, 0x6C, 0x6F, 0x78, 0x21]) {
        "Roblox place file"
    } else if buffer.starts_with(&[0x65, 0x87, 0x78, 0x56]) {
        "PhotoCap Object Templates"
    } else if buffer.starts_with(&[0x55, 0x55, 0xAA, 0xAA]) {
        "PhotoCap Vector"
    } else if buffer.starts_with(&[0x78, 0x56, 0x34]) {
        "PhotoCap Template"
    } else if buffer.starts_with(&[0x50, 0x41, 0x52, 0x31]) {
        "Apache Parquet columnar file format"
    } else if buffer.starts_with(&[0x45, 0x4D, 0x58, 0x32]) {
        "Emulator Emaxsynth samples"
    } else if buffer.starts_with(&[0x45, 0x4D, 0x55, 0x33]) {
        "Emulator III synth samples"
    } else if buffer.starts_with(&[0x1B, 0x4C, 0x75, 0x61]) {
        "Lua bytecode"
    } else if buffer.starts_with(&[0x62, 0x6F, 0x6F, 0x6B, 0x00, 0x00, 0x00, 0x00]) {
        "macOS file Alias (Symbolic link)"
    } else if buffer.starts_with(&[0x62, 0x6F, 0x6F, 0x6B]) {
        "macOS bookmark format"
    } else if buffer.starts_with(&[0x5B, 0x5A, 0x6F, 0x6E, 0x65, 0x54, 0x72, 0x61]) {
        "Microsoft Zone Identifier for URL Security Zones"
    } else if buffer.starts_with(&[0x52, 0x65, 0x63, 0x65, 0x69, 0x76, 0x65, 0x64]) {
        "Email Message"
    } else if buffer.starts_with(&[0x20, 0x02, 0x01, 0x62, 0xA0, 0x1E, 0xAB, 0x07]) {
        "Tableau Datasource"
    } else if buffer.starts_with(&[0x37, 0x48, 0x03, 0x02, 0x00, 0x00, 0x00, 0x00]) {
        "KDB file"
    } else if buffer.starts_with(&[0x28, 0xB5, 0x2F, 0xFD]) {
        "Zstandard compress"
    } else if buffer.starts_with(&[0x52, 0x53, 0x56, 0x4B, 0x44, 0x41, 0x54, 0x41]) {
        "QuickZip rs compressed archive"
    } else if buffer.starts_with(&[0x3A, 0x29, 0x0A]) {
        "Smile file"
    } else if buffer.starts_with(&[0x4A, 0x6F, 0x79, 0x21]) {
        "Preferred Executable Format"
    } else if buffer.starts_with(&[0x34, 0x12, 0xAA, 0x55]) {
        "VPK file"
    } else if buffer.starts_with(&[0x60, 0xEA]) {
        "ARJ"
    } else if buffer.starts_with(&[0x49, 0x53, 0x63, 0x28]) {
        "InstallShield CAB Archive File"
    } else if buffer.starts_with(&[0x4B, 0x57, 0x41, 0x4A]) {
        "Windows 3.1x Compressed File"
    } else if buffer.starts_with(&[0x53, 0x5A, 0x44, 0x44]) {
        "Windows 9x Compressed File"
    } else if buffer.starts_with(&[0x5A, 0x4F, 0x4F]) {
        "Zoo (file format)"
    } else if buffer.starts_with(&[0x50, 0x31, 0x0A]) {
        "Portable bitmap ASCII"
    } else if buffer.starts_with(&[0x50, 0x34, 0x0A]) {
        "Portable bitmap binary"
    } else if buffer.starts_with(&[0x50, 0x32, 0x0A]) {
        "Portable Gray Map ASCII"
    } else if buffer.starts_with(&[0x50, 0x35, 0x0A]) {
        "Portable Gray Map binary"
    } else if buffer.starts_with(&[0x50, 0x33, 0x0A]) {
        "Portable Pixmap ASCII"
    } else if buffer.starts_with(&[0x50, 0x36, 0x0A]) {
        "Portable Pixmap binary"
    } else if buffer.starts_with(&[0xD7, 0xCD, 0xC6, 0x9A]) {
        "Windows Metafile"
    } else if buffer.starts_with(&[0x41, 0x46, 0x46]) {
        "Advanced Forensics Format"
    } else if buffer.starts_with(&[0x45, 0x56, 0x46, 0x32]) {
        "EnCase EWF version 2 format"
    } else if buffer.starts_with(&[0x45, 0x56, 0x46]) {
        "EnCase EWF version 1 format"
    } else if buffer.starts_with(&[0x51, 0x46, 0x49]) {
        "qcow file format"
    } else if buffer.starts_with(&[0x46, 0x4C, 0x56]) {
        "Flash Video file"
    } else if buffer.starts_with(&[0x3C, 0x3C, 0x3C, 0x20, 0x4F, 0x72, 0x61, 0x63]) {
        "VirtualBox Virtual Hard Disk file format"
    } else if buffer.starts_with(&[0x63, 0x6F, 0x6E, 0x65, 0x63, 0x74, 0x69, 0x78]) {
        "Windows Virtual PC Virtual Hard Disk file format"
    } else if buffer.starts_with(&[0x76, 0x68, 0x64, 0x78, 0x66, 0x69, 0x6C, 0x65]) {
        "Windows Virtual PC Windows 8 Virtual Hard Disk file format"
    } else if buffer.starts_with(&[0x49, 0x73, 0x5A, 0x21]) {
        "Compressed ISO image"
    } else if buffer.starts_with(&[0x44, 0x41, 0x41]) {
        "Direct Access Archive PowerISO"
    } else if buffer.starts_with(&[0x4C, 0x66, 0x4C, 0x65]) {
        "Windows Event Viewer file format"
    } else if buffer.starts_with(&[0x45, 0x6C, 0x66, 0x46, 0x69, 0x6C, 0x65]) {
        "Windows Event Viewer XML file format"
    } else if buffer.starts_with(&[0x73, 0x64, 0x62, 0x66]) {
        "Windows customized database"
    } else if buffer.starts_with(&[0x50, 0x4D, 0x43, 0x43]) {
        "Windows 3.x Program Manager Program Group file format"
    } else if buffer.starts_with(&[0x4B, 0x43, 0x4D, 0x53]) {
        "ICC profile"
    } else if buffer.starts_with(&[0x72, 0x65, 0x67, 0x66]) {
        "Windows Registry file"
    } else if buffer.starts_with(&[0x21, 0x42, 0x44, 0x4E]) {
        "Microsoft Outlook Personal Storage Table file"
    } else if buffer.starts_with(&[0x44, 0x52, 0x41, 0x43, 0x4F]) {
        "3D model compressed with Google Draco"
    } else if buffer.starts_with(&[0x47, 0x52, 0x49, 0x42]) {
        "Gridded data (commonly weather observations or forecasts) in the WMO GRIB or GRIB2 format"
    } else if buffer.starts_with(&[0x42, 0x4C, 0x45, 0x4E, 0x44, 0x45, 0x52]) {
        "Blender File Format"
    } else if buffer.starts_with(&[0x00, 0x00, 0x00, 0x0C, 0x4A, 0x58, 0x4C, 0x20]) {
        "Image encoded in the JPEG XL format"
    } else if buffer.starts_with(&[0xFF, 0x0A]) {
        "Image encoded in the JPEG XL format"
    } else if buffer.starts_with(&[0x00, 0x01, 0x00, 0x00, 0x00]) {
        "TrueType font"
    } else if buffer.starts_with(&[0x4F, 0x54, 0x54, 0x4F]) {
        "OpenType font"
    } else if buffer.starts_with(&[0x23, 0x25, 0x4D, 0x6F, 0x64, 0x75, 0x6C, 0x65]) {
        "Modulefile for Environment Modules"
    } else if buffer.starts_with(&[0x4D, 0x53, 0x57, 0x49, 0x4D, 0x00, 0x00, 0x00]) {
        "Windows Imaging Format file"
    } else if buffer.starts_with(&[0x21, 0x2D, 0x31, 0x53, 0x4C, 0x4F, 0x42, 0x1F]) {
        "Slob (sorted list of Object storages)"
    } else if buffer.starts_with(&[0xAC, 0xED]) {
        "Serialized Java Data"
    } else if buffer.starts_with(&[0x43, 0x72, 0x65, 0x61, 0x74, 0x69, 0x76, 0x65, 0x20, 0x56, 0x6F, 0x69, 0x63, 0x65, 0x20, 0x46, 0x69, 0x6C, 0x65, 0x1A, 0x1A, 0x00]) {
        "Creative Voice file"
    } else if buffer.starts_with(&[0x2E, 0x73, 0x6E, 0x64]) {
        "Au audio file format"
    } else if buffer.starts_with(&[0xDB, 0x0A, 0xCE, 0x00]) {
        "OpenGL Iris Perfomer .PFB (Performer Fast Binary)"
    } else if buffer.starts_with(&[0x48, 0x5A, 0x4C, 0x52, 0x00, 0x00, 0x00, 0x18]) {
        "Noodlesoft Hazel"
    } else if buffer.starts_with(&[0x46, 0x4C, 0x68, 0x64]) {
        "FL Studio Project File"
    } else if buffer.starts_with(&[0x31, 0x30, 0x4C, 0x46]) {
        "FL Studio Mobile Project File"
    } else if buffer.starts_with(&[0x52, 0x4b, 0x4d, 0x43, 0x32, 0x31, 0x30]) {
        "Vormetric Encryption DPM Version 2.1 Header"
    } else if buffer.starts_with(&[0x00, 0x01, 0x00, 0x00, 0x4D, 0x53, 0x49, 0x53, 0x41, 0x4D, 0x20, 0x44, 0x61, 0x74, 0x61, 0x62, 0x61, 0x73, 0x65]) {
        "Microsoft Money file"
    } else if buffer.starts_with(&[0x00, 0x01, 0x00, 0x00, 0x53, 0x74, 0x61, 0x6E, 0x64, 0x61, 0x72, 0x64, 0x20, 0x41, 0x43, 0x45, 0x20, 0x44, 0x42]) {
        "Microsoft Access 2007 Database"
    } else if buffer.starts_with(&[0x00, 0x01, 0x00, 0x00, 0x53, 0x74, 0x61, 0x6E, 0x64, 0x61, 0x72, 0x64, 0x20, 0x4A, 0x65, 0x74, 0x20, 0x44, 0x42]) {
        "Microsoft Access Database"
    } else if buffer.starts_with(&[0x01, 0xFF, 0x02, 0x04, 0x03, 0x02]) {
        "Micrografx vector graphic file"
    } else if buffer.starts_with(&[0x02, 0x64, 0x73, 0x73]) {
        "Digital Speech Standard (Olympus, Grundig, & Phillips) v2"
    } else if buffer.starts_with(&[0x03, 0x64, 0x73, 0x73]) {
        "Digital Speech Standard (Olympus, Grundig, & Phillips) v3"
    } else if buffer.starts_with(&[0x03, 0x00, 0x00, 0x00, 0x41, 0x50, 0x50, 0x52]) {
        "Approach index file"
    } else if buffer.starts_with(&[0x06, 0x06, 0xED, 0xF5, 0xD8, 0x1D, 0x46, 0xE5]) {
        "Adobe InDesign document"
    } else if buffer.starts_with(&[0x07, 0x53, 0x4B, 0x46]) {
        "SkinCrafter skin file"
    } else if buffer.starts_with(&[0x07, 0x64, 0x74, 0x32, 0x64, 0x64, 0x74, 0x64]) {
        "DesignTools 2D Design file"
    } else if buffer.starts_with(&[0x0A, 0x16, 0x6F, 0x72, 0x67, 0x2E, 0x62, 0x69]) {
        "MultiBit Bitcoin wallet file"
    } else if buffer.starts_with(&[0x0D, 0x44, 0x4F, 0x43]) {
        "DeskMate Document file"
    } else if buffer.starts_with(&[0x0E, 0x4E, 0x65, 0x72, 0x6F, 0x49, 0x53, 0x4F]) {
        "Nero CD Compilation"
    } else if buffer.starts_with(&[0x0E, 0x57, 0x4B, 0x53]) {
        "DeskMate Worksheet"
    } else if buffer.starts_with(&[0x0F, 0x53, 0x49, 0x42, 0x45, 0x4C, 0x49, 0x55, 0x53]) {
        "Sibelius Music - Score file"
    } else if buffer.starts_with(&[0x23, 0x20, 0x4D, 0x69, 0x63, 0x72, 0x6F, 0x73, 0x6F, 0x66, 0x20, 0x44, 0x65, 0x76, 0x65, 0x6C, 0x6F, 0x70, 0x65, 0x72, 0x20, 0x53, 0x74, 0x75, 0x64, 0x69, 0x6F]) {
        "Microsoft Developer Studio project file"
    } else if buffer.starts_with(&[0x23, 0x21, 0x41, 0x4D, 0x52]) {
        "Adaptive Multi-Rate ACELP (Algebraic Code Excited Linear Prediction) Codec"
    } else if buffer.starts_with(&[0x23, 0x21, 0x53, 0x49, 0x4C, 0x4B, 0x0A]) {
        "Audio compression format developed by Skype"
    } else if buffer.starts_with(&[0x23, 0x3F, 0x52, 0x41, 0x44, 0x49, 0x41, 0x4E, 0x43, 0x45, 0x0A]) {
        "Radiance High Dynamic Range image file"
    } else if buffer.starts_with(&[0x23, 0x40, 0x7E, 0x5E]) {
        "VBScript Encoded script"
    } else if buffer.starts_with(&[0x0D, 0xF0, 0x1D, 0xC0]) {
        "MikroTik WinBox Connection Database (Address Book)"
    } else if buffer.starts_with(&[0x23, 0x45, 0x58, 0x54, 0x4D, 0x33, 0x55]) {
        "Multimedia playlist"
    } else if buffer.starts_with(&[0x6D, 0x64, 0x66, 0x00]) {
        "M2 Archive"
    } else if buffer.starts_with(&[0x4B, 0x50, 0x4B, 0x41]) {
        "Capcom RE Engine game data archives"
    } else if buffer.starts_with(&[0x41, 0x52, 0x43]) {
        "Capcom MT Framework game data archives"
    } else if buffer.starts_with(&[0x41, 0x72, 0x43]) {
        "FreeArc file"
    } else if buffer.starts_with(&[0xD0, 0x4F, 0x50, 0x53]) {
        "Interleaf PrinterLeaf / WorldView document format"
    } else if buffer.starts_with(&[0x52, 0x41, 0x46, 0x36, 0x34]) {
        "Report Builder file from Digital Metaphors"
    } else if buffer.starts_with(&[0x56, 0x49, 0x53, 0x33]) {
        "Resource file Visionaire 3.x Engine"
    } else if buffer.starts_with(&[0x70, 0x77, 0x72, 0x64, 0x61, 0x74, 0x61]) {
        "SAP Power Monitor (version 1.1.0 and higher) data file"
    } else if buffer.starts_with(&[0x1a, 0x08]) {
        "ARC archive file"
    } else if buffer.starts_with(&[0x3a, 0x42, 0x61, 0x73, 0x65, 0x20]) {
        "Windows 3.x - Windows 95 Help Contents"
    } else if buffer.starts_with(&[0x41, 0x53, 0x54, 0x4d, 0x2d, 0x45, 0x35, 0x37]) {
        "ASTM E57 3D file format"
    } else if buffer.starts_with(&[0xaa, 0xaa, 0xaa, 0xaa]) {
        "Crowdstrike Channel File"
    } else if buffer.starts_with(&[0x8C, 0x0A, 0x00]) {
        "Unreal Engine Compressed Asset Storage file"
    } else if buffer.starts_with(&[0x2D, 0x3D, 0x3D, 0x2D, 0x2D, 0x3D, 0x3D, 0x2D, 0x2D, 0x3D, 0x3D, 0x2D, 0x2D, 0x3D, 0x3D, 0x2D]) {
        "Unreal Engine Table of Contents file"
    } else if buffer.starts_with(&[0x43, 0x36, 0x34, 0x46, 0x69, 0x6C, 0x65, 0x00]) {
        "Commodore 64 binary file"
    }
    // Check for ISO 9660 magic number at different offsets
    else if buffer.len() >= 0x8001 + 5 && &buffer[0x8001..0x8001 + 5] == b"CD001" {
        "ISO 9660 CD/DVD image file"
    } else if buffer.len() >= 0x8801 + 5 && &buffer[0x8801..0x8801 + 5] == b"CD001" {
        "ISO 9660 CD/DVD image file"
    } else if buffer.len() >= 0x9001 + 5 && &buffer[0x9001..0x9001 + 5] == b"CD001" {
        "ISO 9660 CD/DVD image file"
    } else {
        "Unknown magic number"
    }
}

/// Reads a chunk of bytes from a file.
///
/// # Arguments
///
/// * `file_path` - The path to the file to be read.
///
/// # Returns
///
/// A `Result` containing a `Vec<u8>` with the read bytes, or an `io::Error`
/// if the file cannot be opened or read.
fn read_file_chunk(file_path: &Path) -> io::Result<Vec<u8>> {
    let file = File::open(file_path)?;
    let mut buffer = Vec::with_capacity(READ_BUFFER_SIZE);
    file.take(READ_BUFFER_SIZE as u64).read_to_end(&mut buffer)?;
    Ok(buffer)
}

/// Converts a byte slice to a space-separated hexadecimal string.
///
/// # Arguments
///
/// * `bytes` - The byte slice to convert.
///
/// # Returns
///
/// A `String` containing the hexadecimal representation.
fn to_hex_string(bytes: &[u8]) -> String {
    bytes
        .iter()
        .map(|b| format!("{:02X}", b))
        .collect::<Vec<String>>()
        .join(" ")
}

fn main() {
    // 1. Input: Get the file path from command-line arguments.
    let args: Vec<String> = env::args().collect();
    if args.len() != 2 {
        eprintln!("Usage: {} <file_path>", args[0]);
        std::process::exit(1);
    }
    let file_path_str = &args[1];
    let file_path = Path::new(file_path_str);

    // 2. Byte Reading: Read a chunk of the file to identify the magic number.
    match read_file_chunk(file_path) {
        Ok(file_chunk) => {
            // 3. Hexadecimal Conversion: Convert the first few bytes to a hex string for display.
            let display_bytes = &file_chunk[..std::cmp::min(file_chunk.len(), DISPLAY_BYTES_LENGTH)];
            let hex_string = to_hex_string(display_bytes);

            // 4. Magic Number Database: Identify the file type.
            let file_type = identify_file_type(&file_chunk);

            // 5. Output: Print the results.
            println!("File Path: {}", file_path_str);
            println!("Magic Bytes (Hex): {}", hex_string);
            println!("Detected File Type: {}", file_type);
        }
        Err(e) => {
            // 6. Error Handling: Manage file access and reading errors.
            eprintln!("Error processing file '{}': {}", file_path_str, e);
            std::process::exit(1);
        }
    }
}
