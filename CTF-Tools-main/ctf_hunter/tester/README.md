# CTF Hunter Test Files

This folder contains sample CTF challenge files for testing CTF Hunter's
analysis capabilities. Every file contains one or more flags using the
format `flag{...}`.

## Test Files

| # | File | Category | Flag | Description |
|---|------|----------|------|-------------|
| 1 | `plain_text.txt` | Generic | `flag{plaintext_is_the_easiest}` | Flag in plain text among log entries |
| 2 | `base64_encoded.txt` | Encoding | `flag{base64_decode_me}` | Base64-encoded flag |
| 3 | `base32_encoded.txt` | Encoding | `flag{base32_hidden_flag}` | Base32-encoded flag |
| 4 | `hex_encoded.txt` | Encoding | `flag{hex_encoded_secret}` | Hex-encoded flag |
| 5 | `base85_encoded.txt` | Encoding | `flag{base85_encoded_data}` | Ascii85/Base85-encoded flag |
| 6 | `rot13_encoded.txt` | Encoding / Cipher | `flag{rot13_classic_cipher}` | ROT13-encoded flag |
| 7 | `morse_code.txt` | Encoding | `flag{morse_code_master}` | Flag alongside Morse code |
| 8 | `binary_encoded.txt` | Encoding | `flag{binary_bits_flag}` | Flag encoded as 8-bit binary groups |
| 9 | `caesar_cipher.txt` | Classical Cipher | `flag{caesar_shift_three}` | Caesar cipher with shift of 3 |
| 10 | `atbash_cipher.txt` | Classical Cipher | `flag{atbash_mirror_text}` | Atbash cipher (reversed alphabet) |
| 11 | `rail_fence.txt` | Classical Cipher | `flag{rail_fence_cipher}` | Rail Fence transposition cipher (3 rails) |
| 12 | `reversed_string.txt` | Steganalysis | `flag{reverse_me_back}` | Flag string reversed |
| 13 | `xor_encrypted.bin` | Crypto | `flag{xor_single_byte_key}` | XOR encrypted with single byte key `0x42` |
| 14 | `nested_encoding.txt` | Encoding | `flag{nested_encoding_fun}` | Nested encoding: Base64(Hex(flag)) |
| 15 | `appended_data.png` | Image | `flag{hidden_after_png_iend}` | Valid PNG with flag appended after IEND chunk |
| 16 | `png_metadata.png` | Image | `flag{png_metadata_hidden}` | PNG with flag in tEXt metadata chunk |
| 17 | `image_with_comment.jpg` | Image | `flag{jpeg_exif_comment_flag}` | JPEG with flag in COM (comment) marker |
| 18 | `archive_with_flag.zip` | Archive | `flag{zip_archive_contents}` | ZIP archive containing a text file with flag |
| 19 | `zip_with_comment.zip` | Archive | `flag{zip_comment_treasure}` | ZIP archive with flag in the archive comment |
| 20 | `compressed_flag.gz` | Archive | `flag{gzip_compressed_flag}` | Gzip-compressed file containing flag |
| 21 | `database_with_flag.db` | Database | `flag{sqlite_database_find}`, `flag{database_hidden_note}` | SQLite database with flags in table rows |
| 22 | `zero_width_steg.txt` | Steganalysis | `flag{zero_width_steganography}` | Flag hidden using zero-width Unicode characters (U+200B/U+200C) |
| 23 | `config_with_flag.json` | Generic | `flag{json_nested_secret}` | JSON config file with flag in a nested field |
| 24 | `webpage_with_flag.html` | Generic | `flag{html_comment_hidden}` | HTML file with flag in an HTML comment |
| 25 | `whitespace_encoded.txt` | Encoding | `flag{whitespace_tab_spaces}` | Flag encoded in whitespace (tabs and spaces) |

## Analyzer Coverage

These test files exercise the following CTF Hunter analyzers:

- **Generic** — string extraction, entropy analysis (`plain_text.txt`, `config_with_flag.json`, `webpage_with_flag.html`)
- **Encoding** — Base64, Base32, Base85, hex, ROT13, Morse, binary-to-ASCII (`base64_encoded.txt`, `base32_encoded.txt`, `hex_encoded.txt`, `base85_encoded.txt`, `rot13_encoded.txt`, `morse_code.txt`, `binary_encoded.txt`, `nested_encoding.txt`, `whitespace_encoded.txt`)
- **Classical Cipher** — Caesar, Atbash, Rail Fence (`caesar_cipher.txt`, `atbash_cipher.txt`, `rail_fence.txt`)
- **Crypto** — XOR recovery (`xor_encrypted.bin`)
- **Image** — appended data, metadata, EXIF (`appended_data.png`, `png_metadata.png`, `image_with_comment.jpg`)
- **Archive** — ZIP extraction, ZIP comments, gzip decompression (`archive_with_flag.zip`, `zip_with_comment.zip`, `compressed_flag.gz`)
- **Database** — SQLite row scanning (`database_with_flag.db`)
- **Steganalysis** — zero-width characters, reversed strings (`zero_width_steg.txt`, `reversed_string.txt`)

## Usage

1. Open CTF Hunter
2. Load any file from this folder (or use the workspace feature to load the entire folder)
3. Run analysis in **Auto** or **Deep** mode
4. Check the Findings Tree and Flag Summary for extracted flags
