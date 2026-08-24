---
title: Digimaze PDF DRM Reversing
layout: posts.liquid
is_draft: false
published_date: 2026-08-25 01:11:09 +0330
description: Full offline recovery of per-book passwords from Digimaze PDF Reader - Dart/Flutter reversing with blutter, crypto layer mapping, and all the dead ends along the way
categories: ['Technology', 'Reverse Engineering']
---

<p class="notice" style="color: red">
This post is for educational purposes only. The author does not endorse piracy or unauthorized access to copyrighted material.
</p>

### Introduction

This is a follow-up to my earlier post about Digimaze PDF Reader. Last time, I found the password sitting in memory next to the PDF path - separated by three stars. That worked, but it felt like cheating, it was fixed by them :) . I wanted to understand *where* the password comes from, how it's derived, and whether the entire chain could be reproduced offline from files on disk.

The answer turned out to be yes. This post documents everything: the toolchain, the wrong turns, the dead ends, and the final working script that takes a user's app data directory and spits out decryptable PDFs.

The target is **Digimaze PDF Reader** (`com.vnegar.digimaze.reader`), available as a Windows UWP/MSIX app (version 1.1.114.0) and an Android APK (`Digimaze_PDF_Reader_V2.1.10.apk`). The interesting logic lives in Dart/Flutter - the Windows desktop build uses Flutter 2.21.1, the Android build uses Flutter 3.44.4 with Dart AOT compilation.

The goal: recover the per-book password of standard-password-protected PDFs the app downloads, entirely offline.

The outcome: **success**. The full chain is reproduced in one script (`digimaze_drm.py`), verified against real user data and validated with qpdf on an actual encrypted book.

### Toolchain

Before diving in, here's what I used:

| Tool | Role | Notes |
|---|---|---|
| **Ghidra** | Static analysis of Windows PE binaries | Good for x86 PE with RTTI; useless on Dart AOT snapshots |
| **blutter** (worawit/blutter) | Dart AOT snapshot → annotated asm + class names | **Essential.** Without this, libapp.so is opaque |
| **qpdf** | PDF encryption inspection & decryption | `--show-encryption`, `--decrypt`, `--check` |
| **python3 + pycryptodome** | AES/CBC experiments | Debian package `python3-cryptodome`; module name `Cryptodome`, NOT `Crypto` |
| **DPAPI / CryptUnprotectData** | Decrypt flutter_secure_storage.dat | Must run as the same Windows user that ran the app |
| **sqlite3** | Main app DB inspection | Plain SQLite, no encryption |
| **readelf / xxd / file** | Quick triage of ELF/binary blobs | Standard binutils |
| **fdfind** (fd-find) | Locate app dirs on the Windows drive | `apt install fd-find` provides `fdfind` |

#### Why Ghidra could not decompile libapp.so

Dart AOT snapshots are not normal machine code. Code lives inside a snapshot blob with Dart's own calling convention - arguments in specific registers, object pool references via a register. Function boundaries and names exist only in snapshot metadata tables that Ghidra's ELF loader doesn't parse. Strings ARE present but as pool objects referenced by offset from a thread-local "object pool" register (`x27` on arm64), not classic `.rodata`.

The result in Ghidra: thousands of undifferentiated `FUN_xxxxxx` functions with no imports, no strings resolved, no calls resolved. Effectively unreadable.

Blutter parses the snapshot header, walks the class/function tables, resolves object-pool constants, and emits pseudo-assembly annotated like:

```
// 0xcdbed0: r16 = "password"
//     0xcdbed0: add             x16, PP, #0x1d, lsl #12  ; [pp+0x1d478] "password"
```

Every later finding hinged on this. **Do not skip blutter.**

### Phase 0 - Reconnaissance

#### Locating the binaries

```bash
$ ls [DRIVE]/"Program Files"/WindowsApps/com.vnegar.digimaze.reader_1.1.114.0_x64__0qn9w5rgp5tx0/
RDPDFReader.exe   RDPDFLIb.dll   RDPDFREADER.DLL   …
```

The Ghidra project listing first included three files: `RDPDFREADER.DLL`, `RDPDFLIb.dll`, and `RDPDFReader.exe`.

Program info for RDPDFReader.dll showed:
```json
{"executable_path":"…/com.vnegar.digimaze.reader_1.1.114.0_x64__0qn9w5rgp5tx0/RDPDFReader.dll",
 "image_base":"180000000","function_count":56939,"symbol_count":335307}
```

#### Identifying the .NET shell vs native engine

Searching function names for crypto keywords in `RDPDFReader.dll` returned nothing useful directly, but string search revealed it's managed C#:

```
"ms-appx:///PDFMainPage/DlgPassword.xaml"
"RDPDFReader.Dialogs.DlgPassword"
"IPasswordBox", "PasswordCredential"
"<EncryptTextWithDefaultPassword>", "<DecryptTextWithDefaultPassword>"
"Windows.Security.Credentials.PasswordCredential"
```

And branding:
```
"https://help.digimaze.org/pdf-reader-light"
"Digimaze_PDF_Reader.exe"
```

Meanwhile `RDPDFLIb.dll` had full OpenSSL statically linked:

```
"AES-128-ECB", "AES-256-CBC", "id-aes128-wrap",
"PBE-SHA1-RC4-128", "RC4-HMAC-MD5",
"unable to decrypt certificate's signature"
```

…and RTTI typeinfo strings revealing PDFium-derived classes:

```
.?AVCPDFEncrypt@@        @ 180460e20
.?AVCPDFEncryptStd@@     @ 180460e48
.?AVCPDFFuncIdentity@@   @ 180461d20
```

#### Finding the standard-security-handler code

The canonical PDF padding constant (ISO 32000 §7.6.3):

```
28 bf 4e 5e 4e 75 8a 41 64 00 4e 56 ff fa 01 08
2e 2e 00 b6 d0 68 3e 80 2f 0c a9 fe 64 53 69 7a
```

was found via byte-pattern search at `0x18035d6a8`, immediately before the `CPDFEncryptStd` vtable at `0x18035d6c8`. Ten cross-references to it all came from functions in `0x1800BA600–0x1800BB100` - the key derivation cluster.

Decompiled `FUN_1800baa00` showed textbook Algorithm 3:

```c
if (this->revision == 2) {
    alg2(this, pw); rc4_ksa(prga, key, len);
}
if (this->revision >= 3 && this->revision <= 4) {
    md5_init(&ctx);
    md5_update(&ctx, PAD_CONST, 32);          // ← our found constant
    md5_update(&ctx, this->O_value, this->O_len);
    md5_final(&ctx, digest);
    rc4_ksa(prga, key, len);
    for (i = 1; i < 20; i++) {                 // 50 iterations? No-20.
        for (j = 0; j < len; j++) key[j] ^= i; // XOR each byte with round #
        md5(key, len, digest);                  // re-hash
    }
    // AES key expansion follows for AESV2
}
```

Then `FUN_1800B93C0` = `CPDFEncryptStd::Init`:
- Reads `/Filter == "Standard"`
- Parses `/V`, `/R`, `/Length`, `/O` (+0x68), `/U` (+0x78), `/P`, `/OE` (+0x90), `/UE` (+0x80), `/EncryptMetadata`
- Detects cipher by CFM string: `"V2"` → RC4 mode 1, `"AESV2"` → mode 2, `"AESV3"` → mode 3
- Runs Algorithm 2 or 3 on the password, compares to `/O` and `/U`

**Conclusion:** The native side implements only standard PDF encryption. Every non-standard thing happens in Dart, before the file reaches this library.

### Phase 1 - Ghidra on the Windows PE binaries

I spent significant time here before realizing the real target was elsewhere. What I accomplished:

- Located `CPDFEncrypt`/`CPDFEncryptStd` vtables via typeinfo cross-references
- Identified OpenSSL static linkage from cipher-name strings
- Confirmed the engine is a PDFium fork (class naming convention)
- Decompiled the standard security handler init and key derivation
- Found `CRDSecMD5` (their MD5 wrapper class)

What I did NOT find: any custom DRM layer, any per-book key storage, anything proprietary. The native side is standards-compliant.

**Time wasted here:** roughly half the session. The lesson: when an app has both a native engine AND a managed/Dart layer, check the Dart layer FIRST for custom logic. Native engines are usually stock libraries.

### Phase 2 - Discovering the real target is Dart/Flutter

Laster I found out that the actual app is Dart compiled to `libapp.so`, I had already loaded it in Ghidra but it was undecompilable.

Verification:

```bash
$ file libapp.so
arm64-v8a/libapp.so: ELF 64-bit LSB shared object, ARM aarch64, version 1 (SYSV), dynamically linked, BuildID[md5/uuid]=b71885091d005194f90d3cfa97d87501, stripped

$ readelf -h libapp.so
ELF Header:
  Magic:   7f 45 4c 46 02 01 01 00 00 00 00 00 00 00 00 00 
  Class:                             ELF64
  Data:                              2's complement, little endian
  Version:                           1 (current)
  OS/ABI:                            UNIX - System V
  ABI Version:                       0
  Type:                              DYN (Shared object file)
  Machine:                           AArch64
  Version:                           0x1
  Entry point address:               0x0
  Start of program headers:          64 (bytes into file)
  Start of section headers:          19136720 (bytes into file)
  Flags:                             0x0
  Size of this header:               64 (bytes)
  Size of program headers:           56 (bytes)
  Number of program headers:         7
  Size of section headers:           64 (bytes)
  Number of section headers:         11
  Section header string table index: 10
```

Strings leaked the Flutter version:

```bash
$ strings -n 20 libapp.so | grep -iE "version" | head
3.44.4 (stable) - Git hash ad70ec4617 - Git URL https://github.com/flutter/flutter.git
dart:convert/byte_conversion.dart
_getPlatformVersionStatus@1504418800
package:digimaze/domain/entities/version_status.dart
```

And package paths confirming the app structure:

```
package:digimaze/domain/entities/version_status.dart
package:sentry/src/protocol/sdk_version.dart
Starting database upgrade to version 2
https://files.digimaze.org/Digimaze_PDF_Reader_V2.1.10.apk
```

### Phase 3 - Installing and running blutter

```bash
cd /home/alireza/Desktop/digimaze
git clone https://github.com/worawit/blutter
python3 blutter/blutter.py arm64-v8a/ digimaze-blutter-output
```

The output structure:

```
digimaze-blutter-output/
├── asm/
│   ├── digimaze/                    ← the app's own code
│   │   ├── core/common/utils/encryption.dart
│   │   ├── data/repository/impl/book_repo.dart
│   │   ├── presentation/pages/book/widgets/general_book/utils/pdf_reader/
│   │   │   ├── base_pdf_reader_utils.dart
│   │   │   ├── lagacy_pdf_reader_utils.dart
│   │   │   └── adavnced_pdf_reader_utils.dart   (typo theirs, not ours)
│   │   └── ...
│   ├── encrypt/                     ← third-party pub packages
│   ├── cryptography/
│   ├── sqflite_common/
│   └── ...147 package dirs total
├── ida_script/
├── blutter_frida.js                 675K
├── objs.txt                         1.8M
└── pp.txt                           4.1M   (object pool dump)
```

Each `.dart` file contains pseudo-assembly with resolved names, source-line comments, and object-pool annotations. Here's a sample showing how readable it becomes:

```
// 0xcab23c: r1 = Instance_Base64Codec
//     0xcab23c: ldr             x1, [PP, #0x1150]  ; [pp+0x1150] Obj!Base64Codec@10e33f1
// 0xcab240: r0 = decode()
//     0xcab240: bl              #0x10ab7dc  ; [dart:convert] Base64Codec::decode
// 0xcab248: r0 = Encrypted()
//     0xcab248: bl              #0xcab4dc  ; AllocateEncryptedStub -> Encrypted (size=0xc)
```

### Phase 4 - Mapping the crypto layers

#### Finding the encryption utility class

```bash
$ grep -rln -iE "decrypt|aes|rc4|cipher" digimaze encrypt
digimaze/core/common/utils/encryption.dart
digimaze/presentation/utils/security.dart
encrypt/encrypt.dart                       ← pub package "encrypt"
cryptography/src/dart/aes_cbc.dart         ← pub package "cryptography"
```

The main file `encryption.dart` defines:

```
class EncryptionParams extends Object {}          // class id 4641, size 0x18
class Encryption extends Object {                  // class id 4642, size 0x8
  Future<String>      decryptText(ct, keyStr, ivSeed)          @ 0xca6a84
  Future<Uint8List>   decryptBinaryText(data, keyStr, ivSeed)  @ 0xca9b2c
  Future<String>      encryptText(plain, keyStr)               @ 0xcd3118
  Future<bool>        decryptFile(srcPath, dstPath, keyStr, ivSeed, ?) @ 0xd27a54
  String              utf8ToHex(String s, {bool havePadding})   @ 0xca8f68
}
```

#### Decoding `utf8ToHex` (addr `0xca8f68`)

From the asm, I reconstructed the algorithm:

```python
def utf8ToHex(s, havePadding=False):
    out = ''
    for ch in s:
        h = ch.encode('utf-8').hex()       # bytes → hex
        if havePadding and len(h) == 2:
            h = '00' + h                   # pad single-byte chars to 4 hex digits
        out += h
    return out
```

Key evidence from the asm (trimmed):

```
// 0xca9044: r1 = Instance_Utf8Encoder
//     0xca9044: ldr             x1, [PP, #0xff0]  ; [pp+0xff0] Obj!Utf8Encoder@10e34d1
// 0xca904c: r0 = convert()
//     0xca904c: bl              #0x10b8674  ; [dart:convert] Utf8Encoder::convert
// 0xca9054: r1 = Instance_HexEncoder
//     0xca9054: add             x1, PP, #0x18, lsl #12  ; [pp+0x184c8] Obj!HexEncoder@10e3481
// 0xca905c: r0 = convert()
//     0xca905c: bl              #0x10b9904  ; [package:convert/src/hex/encoder.dart] HexEncoder::convert
// 0xca9068: cmp             w1, #4              ; hex length == 4?
// 0xca9074: tbnz            w3, #4, #0xca90a4   ; havePadding branch
// 0xca9084: r16 = "00"                          ; the pad prefix
```

Examples:
- `'A'` no-pad → `"41"`, padded → `"0041"`
- `'ع'` (U+0639, UTF-8 `d8 b9`) → `"d8b9"` regardless of padding flag

#### Decoding `decryptText` (addr `0xca6a84`)

Setup parameters show THREE arguments beyond `this`:

```
// 0xca6a90: SetupParameters(Encryption this /* r1 => r4, fp-0xb0 */,
//                             dynamic _ /* r2 => r3, fp-0xc8 */,    ← ct
//                             dynamic _ /* r3 => r2, fp-0xc0 */)    ← keyStr
// then later x5 (4th arg) → ivSeed
```

Body flow (from asm, condensed):

```
1. keyMaterial = utf8ToHex("11111" + keyArg.substring(0,22))
                NO padding flag here
2. keyBytes   = Utf8Encoder.convert(keyMaterial)      ← ascii of hex STRING
3. secretKey  = newSecretKeyFromBytes(keyBytes)       ← DartAesCbc.secretKeyLength=32
4. ivSeed     = ctArg.substring(0, 8)                 ← FIRST 8 CHARS OF CT STRING
5. ivBytes    = Utf8Encoder.convert(utf8ToHex(ivSeed, havePadding:true))
6. plain      = DartAesCbc.decrypt(SecretBox(key, iv), base64Decode(ct))
7. return     = utf8.decode(plain)
```

The critical detail confirmed by finding the literal in the pool:

```
// 0xca6b28: r16 = "11111"
//     0xca6b28: add             x16, PP, #0x18, lsl #12  ; [pp+0x183d0] "11111"
// 0xca6b34: r16 = 22                            ; substring length
// 0xca6bbc: r0 = substring()                    ; on ctArg? No-on KEY arg
```

Careful reading shows `substring(0,22)` is applied to `fp-0xc0` which is the KEY argument (arg3), not the ct. The `"11111"` gets prepended to the KEY, not the IV. This distinction cost me hours.

#### The three call sites and where their args come from

**Call site A: `decryptText(user_drm_info_ct, phone, name)`**

Found in `StorageRepository::getUserDrm` (`0xca6478`):

```
// 0xca6818: r0 = getUser()
//     0xca6818: bl  #0x75f86c  ; LocalPref::getUser
// 0xca6834: LoadField: r1 = r0->field_f        ← repository field_f
// 0xca683c: LoadField: r3 = r1->field_13       ← UserModel.field_13 = PHONE
// 0xca6844: mov x1, x3                          ← becomes arg2 (keyStr)
// 0xca6848: r0 = getUserDrmInfo()               ← returns stored b64 ct
//     0xca6848: bl  #0xca69f0  ; LocalPref::getUserDrmInfo
// 0xca6874: LoadField: r3 = r0->field_13        ← ??? field on result?
// 0xca6880: LoadField: r5 = r0->field_1b        ← ???
```

This was confusing because `getUserDrmInfo()` returns `Future<String?>` per its own signature, yet the code reads `.field_13` off it. The resolution: those LoadFields are actually operating on the USER object still in flight, not on the string result. Blutter mis-attributes some loads across await boundaries. The net effect after disentangling:

```
decryptText(ct=stored_user_drm_info, key=user.phone, ivSeed=user.name[:8])
```

This was verified empirically once implemented (see the successful chain section).

**Call site B: `decryptBinaryText(backup_bytes, drmJson.key, drmJson.iv)`**

In `BookRepository::getBookPassword` closure (`0xca9e5c`):

```
// 0xca9f04: r0 = setBookEncryptedPassword()
// args: x2 = raw downloaded bytes, x3 = drm.key, x5 = drm.iv
```

Where `drm` comes from step A's decrypted JSON.

**Call site C: `decryptFile(srcPath, dstPath, keyStr, ivSeed, ?)` @ `0xd27a54`**

Used for outer-layer decryption of downloaded attachments. Same structure as B.

#### Locating the backup download

`Downloader::downloadBookFileConfig` @ `0xca94dc`:

```
// 0xca9548: r2 = "BASE_URL"
// 0xca9594: r16 = "/storage/v3/books/"
// 0xca95bc: r16 = "/file/backup"
// 0xca95f8: r16 = "Authorization"
// → GET {BASE_URL}/storage/v3/books/{bookId}/file/backup
```

The response body is 48 raw bytes - one AES block payload plus one block PKCS7 padding. It's saved locally as `backup_<bookId>.time`.

#### Where the PDF password actually goes

`AdvancedPdfReaderUtils::_prepareSecureParams` (`0xca9ff0`):
1. Calls `GetBookPassword::call(bookId)` → returns 32-char password
2. Calls `BasePdfReaderUtils::getPasswordKey(true)` → static transport key
3. Calls `Encryption::encryptObfuscatedParams(...)` which:
   - Generates 5 random 8-char strings
   - Obfuscates them with PositionObfuscator
   - Encrypts with `encryptText`
4. Sends over MethodChannel `"openBook"` with `{path, params}`

The native mupdf plugin receives, de-obfuscates, and opens the PDF with the password.

The legacy path (`lagacy_pdf_reader_utils.dart` @ `0xcdbd48`):
MethodChannel `"open"` with map `{path, bookId, password}` - password sent as `encryptText(getPasswordKey())`.

Neither channel carries the actual PDF password in plaintext over the wire; it's always wrapped in the transport layer first.

### Dead ends and wrong assumptions

This section documents everything I tried that didn't work, why, and what I learned.

#### Dead end 1: Static password tables unlock the PDFs

**What I found:** In `BasePdfReaderUtils::getPasswordKey` (`0xcd5b74`), two hardcoded arrays selected by argument bit #4:

```
Branch A: [94,204,88,168,212,182,248,100,104,146,176,110,214,240,154,104]
Branch B: [198,162,114,130,252,124,112,86,150,116,158,254,216,118,212,244]
```

A closure at `0xcd5d84` applies `byte ^ 8` to each element, then UTF-8-decodes.

**What I computed:**

```python
>>> bytes((x>>1)^8 for x in A)   # account for Smi tagging then xor
b"'n$\\x08St:<AP?cpE<"

>>> bytes((x>>1)^8 for x in B)
b'kY1Iv60#C2Gwd3br'              # clean printable!
```

**What I assumed:** Branch B looks like a proper random password. It must be THE password. I tested it against `attachment_1060_….pdf`:

```bash
$ qpdf --show-encryption --password=kY1Iv60#C2Gwd3br attachment_1060_….pdf
Incorrect password supplied
R = 5
P = -3904
```

Also tried Branch A, both without the `>>1` shift, both without XOR, and multiple combinations. All failed.

**Why I was wrong:** These arrays feed `encryptObfuscatedParams` - they're transport keys between Dart UI and native plugin over MethodChannel. They never touch the PDF file itself. They're also used as fallback key material for other features.

**Lesson:** A clean printable string appearing after decoding feels like a win. It was a decoy. Always trace where a candidate value is consumed before celebrating.

#### Dead end 2: "The DRM key is in shared_preferences.json"

I grepped every key. Contents include `flutter.user_v2` (full profile JSON with id=334934, phone, name, major, grade, province), `auth_token_v2`, `refresh_token_v2`, feature flags, SMS templates. No DRM material anywhere.

#### Dead end 3: "The DRM key is in the JWT"

Decoded `auth_token_v2` payload:

```json
{"sub":564935, "phone":"[REDACTED]", "device":"WINDOWS",
 "deviceId":194369, "iat":1776779369, "exp":1779371369}
```

I tried each claim as key material with multiple derivation variants (raw, SHA-256, hex-encoded). None produced valid plaintext.

The reason: the DRM info comes from a separate server endpoint (`/v2/user/books/info`) and is stored encrypted with a phone-derived key. The JWT is unrelated to DRM.

#### Dead end 4: "IV comes from the ciphertext" (partially wrong)

For `decryptBinaryText` on binary files (like `backup_*.time`), yes - the IV derivation uses the ciphertext. But for `decryptText` when called from `getUserDrm`, the IV argument is the user's NAME, passed separately as the 4th positional parameter.

Mixing these up produced output where blocks 2..N decoded cleanly but block 1 was garbage. In CBC mode, a wrong IV corrupts exactly one block (the first) - which made it look like "almost working".

Symptom example (wrong IV variant):

```
b'/*:h-+6udj>fcic3-80ea-4c01-b0cc-4b7f08994312","i'
                                  ^^^^^^^^^^^^^^^^ blocks 2+ perfect
^^^^^^^^^^^^^^^^^^ block 1 garbage
```

Once I realized block 1 should start with `{"key":"` (JSON opening), I could do known-plaintext recovery of the correct IV:

```python
# required_iv = AES_ECB_decrypt(key, ct_block1) XOR known_plain_block1
# required_iv[0:8] = 'd8b9d984'  ← ASCII, matching u8hex(name[:8],pad=True)[:8]
```

That pinned down the correct IV source: the NAME, padded-hex-encoded.

**Lesson:** In CBC, garbage limited to block 1 means your KEY is right and your IV is wrong. Don't throw away the key.

#### Dead end 5: "utf8ToHex always pads"

Nope. The named `havePadding` argument controls whether single-byte chars get `"00"` prefix. Different call sites pass different values:

- Key derivation sites: NO padding (each ascii char contributes 2 hex chars)
- IV derivation sites: YES padding (each char contributes exactly 4 hex chars)

Getting this wrong also corrupts exactly the first block (since only IV length changes, not the key schedule). Same symptom as dead end 4.

#### Attempt: brute-force guessing the missing GUID chars

After getting blocks 2..N clean, I briefly considered brute-forcing the missing 9 leading characters of the GUID in block 1. Pointless - once the correct IV was identified, everything decoded cleanly. Never brute-force what you can derive.

#### Misreading blutter output across async boundaries

Several times I saw `LoadField: rX = rY->field_NN` applied to what appeared to be a String return value. Strings don't have fields. What was actually happening: blutter attributes loads across `await` boundaries imprecisely, and the load was really hitting the USER object captured in the closure scope, not the freshly-returned string.

The fix: trace register lifetimes manually through the `AwaitStub` calls rather than trusting variable-to-variable attribution.

### The successful chain, end to end with real outputs

Inputs needed:
1. `shared_preferences.json` - for `flutter.user_v2.phone` (key seed) and `.name` (IV seed)
2. `flutter_secure_storage.dat` - DPAPI blob containing `user_drm_info`
3. One or more `backup_<bookId>.time` files

All paths are relative to `%APPDATA%\com.vnegar\digimaze\` on Windows, or the copied equivalent on Linux.

#### Step 1 - Unprotect the secure storage

Verify it's DPAPI:

```bash
$ xxd flutter_secure_storage.dat | head -3
00000000: 0100 0000 d08c 9ddf 0115 d111 8c7a 00c0  .............z..
00000010: 4fc2 97eb 0100 0000 6036 445b 8b7c 6547  O.......`6D[.|eG
```

Magic `01 00 00 00 D0 8C 9D DF` = CRYPTPROTECTPROTECTED structure.

Decrypt on Windows (same user):

```powershell
Add-Type -AssemblyName System.Security
$b = [IO.File]::ReadAllBytes("$env:APPDATA\com.vnegar\digimaze\flutter_secure_storage.dat")
[Text.Encoding]::UTF8.GetString(
  [Security.Cryptography.ProtectedData]::Unprotect(
    $b, $null, [System.Security.Cryptography.DataProtectionScope]::CurrentUser))
```

**Gotcha:** passing the string `"CurrentUserScope"` fails type conversion. You must use `[DataProtectionScope]::CurrentUser` explicitly.

Real output:

```json
{"last_read_book":"1279",
 "user_drm_info":"4LQb/8gjnDPE3D7fOtcxOH+DlMcgNWp8rTeAN4Mb6DauRp0O6DNlvpmQgWAWlg6GHM6YqHZHl9P55FLl2SBhMb8qX2Au16cYdbbx6ZYMLpL3uDCfmvZeJb+zCrE/KKLx"}
```

#### Step 2 - Decrypt user_drm_info

From `shared_preferences.json`:

```json
"flutter.user_v2": {"id":334934, "phone":"[REDACTED]",
                    "name":"علیرضا آهنی", ...}
```

Python implementation (final version from `digimaze_drm.py`):

```python
def u8hex(s, pad=False):
    out = ''
    for ch in s:
        h = ch.encode('utf-8').hex()
        if pad and len(h) == 2:
            h = '00' + h
        out += h
    return out

def derive_key(seed_str):
    return u8hex('11111' + seed_str[:22]).encode()[:32]

def decrypt_drm_info(b64_blob, phone, name):
    ct = base64.b64decode(b64_blob)
    key = derive_key(phone)
    iv  = u8hex(name[:8], pad=True).encode()[:16]
    p = AES.new(key, AES.MODE_CBC, iv).decrypt(ct)
    n = p[-1]
    if 1 <= n <= 16 and p[-n:] == bytes([n]) * n:
        p = p[:-n]
    return json.loads(p.decode('utf-8'))

drm = decrypt_drm_info(
    "4LQb/8gjnDPE3D7fOtcxOH+DlMcgNWp8rTeAN4Mb6DauRp0O6DNlvpmQgWAWlg6GHM…",
    '[REDACTED]', 'علیرضا آهنی')
# → {'key': '08347a70-80ea-4c01-b0cc-4b7f08994312',
#    'iv':  '570aeeae-e960-4a7a-b779-efc30efd793a'}
```

Note that Persian characters in the name produce multi-byte UTF-8 sequences handled naturally by `u8hex(pad=True)`.

#### Step 3 - Decrypt backup_<bookId>.time

```python
def decrypt_backup(path, drm_json):
    raw = open(path, 'rb').read()
    key = derive_key(drm_json['key'])                      # '11111'+uuid[:22]
    iv  = u8hex(drm_json['iv'][:8], pad=True).encode()[:16]
    p = AES.new(key, AES.MODE_CBC, iv).decrypt(raw)
    n = p[-1]
    return p[:-n]                                          # strip PKCS7
```

Each file is 48 bytes: one AES block (16 B) of payload plus one block of pure PKCS7 padding (16 × `\x10`). The plaintext is exactly 32 chars.

Results from the test machine:

```
book 1060: rTBRPDocEN8BZxC6r%ey2@wV%drfaJDn
book 1221: Kp%sTnuE8cJ9%3pfHks%TPk6oD4EtfdJ
book 1222: r*7!84D&o3^ZLr3v8w@Eke@g^cC3WRvZ
book 1233: 8az4a^w%w8iQg&u49DejXA#wfaCMk7yM
book 1235: t79!tApbPZG7aJw9qS&tEMt5G^PUa9rk
book 1279: LiMc&iq2Z@k2zDBgHaP33!stnw%o7JDp
book 1539: Kp%sTnuE8cJ9%3pfHks%TPk6oD4EtfdJ   ← identical to 1221
book 422:  c3hzGDhv!H2TmjGB$SmWnFZhUW#V4wNA
```

(1221 & 1539 sharing a password suggests same underlying content or same license group.)

#### Step 4 - Open the PDF

```bash
$ qpdf --show-encryption --password='rTBRPDocEN8BZxC6r%ey2@wV%drfaJDn' \
      attachment_1060_681c5e30ed5482472fb9d3ff.pdf
R = 5
P = -3904
User password = rTBRPDocEN8BZxC6r%ey2@wV%drfaJDn
Supplied password is user password
extract for accessibility: not allowed
...

$ qpdf --decrypt --password='rTBRPDocEN8BZxC6r%ey2@wV%drfaJDn' \
      attachment_1060_681c5e30ed5482472fb9d3ff.pdf decrypted_1060.pdf
operation succeeded with warnings; resulting file may have some problems

$ qpdf --check decrypted_1060.pdf
PDF Version: 1.7
File is not encrypted
✓
```

14 MB output file, fully readable.

### Filesystem layout on Windows

Located via:

```bash
$ fdfind "com.vnegar"
AppData/Roaming/com.vnegar/
AppData/Local/Packages/com.vnegar.digimaze.reader_0qn9w5rgp5tx0/
AppData/Local/Microsoft/WindowsApps/com.vnegar.digimaze.reader_0qn9w5rgp5tx0/

$ fdfind "database.db"
(nothing relevant under com.vnegar)

$ fdfind "uMUcLeML9ab"
(none)
$ fdfind "xQoqbsXxix"
(none)
```

Everything important lives under `AppData\Roaming\com.vnegar\digimaze\`:

```
.db/database.db                                    SQLite 3.x, user version 21
attachment_1060_681c5e30ed5482472fb9d3ff           14.1M  raw download
attachment_1060_681c5e30ed5482472fb9d3ff.pdf       14.1M  outer-decrypted, still PDF-encrypted
backup_1060.time                                   48B    ← our target
backup_1221.time                                   48B
...
backup_422.time                                    48B
flutter_secure_storage.dat                         390B   DPAPI blob
shared_preferences.json                            32.9K  cleartext prefs
sqlite3.dll                                        2.1M   bundled sqlite
```

SQLite schema inspection:

```bash
$ sqlite3 .db/database.db ".tables"
annotations_actions        download_manager
attachment_download_log    last_active_time
audio_chapters             last_watched_video_second
book_attachment_types      library
book_attachments           shelf_table
book_download_log          upload_manager
book_sync_md5              usage_time

$ sqlite3 .db/database.db ".schema book_attachments"
CREATE TABLE book_attachments (id TEXT NOT NULL, title TEXT, description TEXT,
  fileName TEXT, fileSize INTEGER, bookId INTEGER, typeId INTEGER, sort INTEGER,
  fileType TEXT);
```

`shared_preferences.json` notable keys (cleartext):

```json
"flutter.auth_token_v2":   "eyJhbG...wNzg",   ← JWT access token, UNENCRYPTED
"flutter.refresh_token_v2":"eyJhbG...wNzg",
"flutter.user_v2":         "{\"id\":334934,\"phone\":\"[REDACTED]\",…}",
"flutter.ANDROID_VERSION": "2.21.1",
"flutter.WINDOWS_VERSION": "2.21.1",
…
```

Absent despite being in the code: no `.tostore_data` directory, no `uMUcLeML9ab` folder, no `xQoqbsXxix`. On Windows the build apparently routes KV storage through `flutter_secure_storage` instead of ToStore's own file format. Worth verifying if you specifically care about ToStore internals.

UWP sandbox dirs exist but are empty of interest:

```
AppData/Local/Packages/com.vnegar.digimaze.reader_0qn9w5rgp5tx0/{LocalState,LocalCache,…}
```

Android equivalents (inferred from code, not tested live):
- `/data/data/com.vnegar.digimaze.reader/databases/database.db`
- `/data/data/com.vnegar.digimaze.reader/files/.tostore_data/uMUcLeML9ab/`
- `shared_prefs/` XML files instead of `shared_preferences.json`

### The final script

A single self-contained file: `digimaze_drm.py`. The full source is in the repo; key excerpts are above. Usage:

```bash
# On Windows, as the user who ran the app (auto-DPAPI):
python digimaze_drm.py "%APPDATA%\com.vnegar\digimaze"

# On Linux/macOS, after manually decrypting the .dat:
python3 digimaze_drm.py --drm drm.json <appdata_dir>

# Decrypt a specific PDF with a recovered password:
python3 digimaze_drm.py --pdf attachment_1060_….pdf 'rTBRPDocEN8BZxC6r%ey2@wV%drfaJDn' out.pdf
```

### Security assessment

Weaknesses observed, ranked by impact:

1. **Per-book PDF password is stored client-side in recoverable form.** Anyone with local access (or the user's own credentials) can extract it. No hardware-backed keystore involvement. The DPAPI wrapper only helps against *other* users on the same machine, not against the owner.

2. **Key derivation uses weak entropy**: `"11111"` literal salt plus the user's own phone number. Both are guessable/leakable (phone numbers leak constantly). An attacker who knows a target's phone number can derive the DRM key given any single `backup_*.time` file.

3. **IV reuse across books**: the same `{key, iv}` pair decrypts every `backup_*.time` for a given user. Compromise once, read all. Also, IVs are deterministic (derived from GUID prefix), not random per encryption.

4. **Auth tokens in cleartext JSON**: `auth_token_v2` and `refresh_token_v2` sit unencrypted next to everything else. Malware or a curious roommate can steal the session.

5. **Standard PDF encryption only** (AESV3, R=5): once you have the password, any standards-compliant tool opens the file. No custom crypto on content. Owner-level restrictions (no-print/no-copy) are enforced by reader policy only, trivially bypassable with `qpdf --decrypt`.

6. **Obfuscation ≠ encryption**: `PositionObfuscator` and the XOR-8 tables are trivially reversible and provide zero resistance against a determined analyst.

What they do right:
- Platform DPAPI for the secure-storage blob (keeps other local users out)
- AES-256-CBC with PKCS7 instead of something homebrew
- Per-book passwords distinct rather than global
- Root/debugger detection present (though bypassable)

### Appendix A - Key addresses (arm64 libapp.so, Flutter 3.44.4 build)

| Symbol / role | Address |
|---|---|
| `Encryption::decryptText` | `0xca6a84` |
| `Encryption::encryptText` | `0xcd3118` |
| `Encryption::decryptBinaryText` | `0xca9b2c` |
| `Encryption::decryptFile` | `0xd27a54` |
| `Encryption::utf8ToHex` | `0xca8f68` |
| `BasePdfReaderUtils::getPasswordKey` | `0xcd5b74` |
| `BasePdfReaderUtils::encryptObfuscatedParams` | `0xcd4ff8` |
| `BasePdfReaderUtils::generateRandomString` | `0xcd5a34` |
| `PositionObfuscator::obfuscate` | `0xcd540c` |
| `PositionObfuscator::_permutation` | `0xcd55fc` |
| `PositionObfuscator::_seedFromKeyAndLength` | `0xcd585c` |
| `PositionObfuscator::_toCodePoints` | `0xcd59e8` |
| `BookRepository::getBookPassword` | `0xca604c` |
| `BookRepository::_fetchBookPrivateInfo` | `0xcd836c` |
| `BookRepository::downloadBookAttachment` | `0xd2656c` |
| `StorageRepository::getUserDrm` | `0xca6478` |
| `StorageRepository::getBookLic` | `0xcaa56c` |
| `LocalPref::getUserDrmInfo` | `0xca69f0` |
| `LocalPref::setUserDrmInfo` | `0x913f68` |
| `LocalPref::hasBookEncryptedPassword` | `0xca991c` |
| `LocalPref::getBookEncryptedPassword` | `0xca942c` |
| `LocalPref::setBookEncryptedPassword` | `0xca9f04` |
| `Downloader::downloadBookFileConfig` | `0xca94dc` |
| `AdvancedPdfReaderUtils::_prepareSecureParams` | `0xca9ff0` |
| `_StorageServiceClient::getUserDrm` | `0x914000` |
| `_StorageServiceClient::getBookPrivateInfo` | `0xcd8504` |
| Legacy open-channel | MethodChannel `"open"`, keys `{path, bookId, password}` |
| Advanced open-channel | MethodChannel `"openBook"`, keys `{path, params}` |
| getFileContentUri channel | `"getFileContentUri"` |
| Backup URL pattern | `GET {BASE_URL}/storage/v3/books/{bookId}/file/backup` |
| DRM info URL | `GET {BASE_URL}/v2/user/books/info` |
| Private info URL | `GET {BASE_URL}/v1/books/{bookId}/info` |

### Appendix B - Object-pool constants worth grepping for

Constant pool entries that jump out when scanning blutter output:

| Constant | Meaning | Pool addr |
|---|---|---|
| `"11111"` | Universal key-derivation salt | `pp+0x183d0` |
| `"uMUcLeML9ab"` | ToStore dbPath component | `pp+0x31328` |
| `"xQoqbsXxix"` | ToStore dbPath config name | `pp+0x31330` |
| `"havePadding"` | Named arg marker for utf8ToHex | `pp+0x184c0` |
| `"Bearer "` | Auth header prefix | `pp+0x19c30` |
| `"Cant decrypt password file => DeleteFile"` | Failure breadcrumb | `pp+0x183c0` |
| `"/database.db"` | Main SQLite filename | `pp+0x1c6e8` |
| `"user_drm_info"` | KvStore key | `pp+0x185c8` |
| `"auth_token_v2"` | KvStore key | `pp+0x19c18` |
| `"book_"` / `"_backup"` | KvStore key parts for per-book pw cache | `pp+0x18360` / `pp+0x18368` |
| `".tostore_data"` | ToStore directory name | `pp+0x35c88` |
| `"/storage/v3/books/"` | Backup download path | `pp+0x19ba0` |
| `"/file/backup"` | Backup download suffix | `pp+0x19ba8` |
| `"/v2/user/books/info"` | DRM info endpoint | `pp+0x19b58` |
| `"Standard"`, `"V2"`, `"AESV2"`, `"AESV3"` | PDF cipher identifiers (native side) | - |

### Appendix C - What I did NOT do

- Did not dump or reverse the Android Java/Kotlin side (mupdf JNI bridge). The Dart-side analysis made it unnecessary - all interesting logic is in Dart.
- Did not inspect `IDatabaseImpl::onUpgrade` migrations past noting their existence (code targets version 28; disk had version 21).
- Did not attempt to defeat the root/debugger checks in `Security::verifyAndroidDeviceSecurity` (wraps `security_plus` package). Irrelevant for offline extraction since the app was never run.
- Did not verify behaviour on iOS. The Dart code is cross-platform so the same chain should hold, but secure-storage backend differs (Keychain instead of DPAPI), so step 1 changes.
- Did not test whether the desktop Windows build (Flutter, non-UWP) stores things identically to the UWP build. Both were present; I analyzed the UWP one because that's where the files were.
- Did not attempt to write a Frida hook using `blutter_frida.js`. Static analysis sufficed.

### Known limitations

- Addresses are specific to the analyzed build (Flutter 3.44.4, app version 1.1.114.0 / 2.21.1). Any app update shifts them.
- The `PositionObfuscator` reconstruction was verified by round-trip only, not against a live capture of actual obfuscated traffic between Dart and native. If the native side uses a slightly different permutation direction, the reconstruction may need sign flips. Doesn't affect password recovery.
- Android paths are inferred from Dart code (`path_provider` conventions) and not confirmed by pulling files from a live device.
