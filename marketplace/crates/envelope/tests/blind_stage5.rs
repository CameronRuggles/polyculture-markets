//! BLIND Stage 5 security suite — spec section 22 process.
//!
//! Authored from the amended spec section 14 rules + the API contract ONLY.
//! The author has not read crates/envelope/src or any earlier spike code.
//!
//! ---------------------------------------------------------------------
//! API CONTRACT (as given, including the CONTRACT ADDENDUM):
//!
//!   pub use modules_api::EnvelopeError; // unit variants, in order:
//!     Empty, NotEncrypted, Malformed, UnsupportedPacket, HiddenRecipient,
//!     RecipientKeyRetired, WrongRecipient, ExtraRecipient
//!
//!   #[derive(Clone, Debug)]
//!   pub struct KeyRef { /* opaque */ }
//!   impl KeyRef {
//!       pub fn from_cert(cert_bytes: &[u8]) -> Option<KeyRef>;
//!       pub fn from_fingerprint(fingerprint: &str) -> KeyRef;
//!       pub fn fingerprint(&self) -> &str;
//!   }
//!
//!   pub struct EnvelopeContext {
//!       pub sender: KeyRef,
//!       pub recipient: KeyRef,
//!       pub recipient_retired_shown: Vec<KeyRef>,
//!   }
//!   pub struct EnvelopeInfo { pub recipient_fingerprints: Vec<String> }
//!   pub fn validate_envelope(bytes: &[u8], ctx: &EnvelopeContext)
//!       -> Result<EnvelopeInfo, EnvelopeError>;
//!   pub fn extra_recipient_key_id(bytes: &[u8], ctx: &EnvelopeContext)
//!       -> Option<String>;
//!
//! Contract points relied on below:
//!  * KeyRef::from_cert knows every key handle in the cert: matching is at
//!    CERTIFICATE level (a PKESK naming the encryption SUBKEY matches the
//!    cert that owns it). GnuPG encrypts to the encryption subkey, so every
//!    positive fixture exercises subkey matching.
//!  * KeyRef::from_fingerprint matching is limited to that primary
//!    fingerprint and its key ID (last 16 hex). It does NOT know subkeys,
//!    so it must NOT match a PKESK that names a subkey.
//!  * EnvelopeInfo.recipient_fingerprints holds PRIMARY fingerprints.
//!
//! ---------------------------------------------------------------------
//! FIXTURE PROVENANCE (all generated 2026-10-14 with GnuPG 2.4.4 in a
//! throwaway GNUPGHOME; batch mode, --trust-model always, test keys with
//! %no-protection; keys are ed25519 sign primary + cv25519 encryption
//! subkey, v4):
//!   gpg --batch --gen-key  (params: Key-Type eddsa/ed25519,
//!     Subkey-Type ecdh/cv25519, Name "Blind <n>", <n>@blind.test)
//!   gpg --armor --export <n>@blind.test                       -> CERT_*
//!   gpg --batch --yes --trust-model always --armor \
//!       --compress-algo none --encrypt -r <addrs...> pt.txt  -> MSG_*
//!   gpg --batch --yes --armor --cipher-algo AES256 --symmetric \
//!       --passphrase 'blind-fixture-passphrase'              -> MSG_SYMMETRIC
//!   gpg --clearsign -u sender@blind.test                     -> MSG_CLEARSIGNED
//!
//! Verified with gpg --list-packets: the default GnuPG 2.4.4 output for
//! these keys is a LibrePGP AED packet (tag 20: cipher=9 AES-256,
//! aead=2 OCB, chunk-size octet 16) behind v3 PKESKs naming the
//! encryption SUBKEY key ID. --force-mdc and --rfc4880 did NOT switch
//! GnuPG to SEIPD v1 for these AEAD-capable keys, so the SEIPD v1
//! positive fixture is built by splicing (below): a real recipient v3
//! PKESK followed by a hand-built tag-18 packet. The validator never
//! decrypts, so the spliced container body is inert filler bytes.
//!
//! ---------------------------------------------------------------------
//! AMBIGUITIES FOUND (recorded for the spec owners; tests follow the
//! brief's rules text where it is explicit):
//!  A1. Literal-only structures: the brief's rule 6 says NotEncrypted.
//!      (A doc comment in the contract crate groups "literal data" under
//!      UnsupportedPacket.) This suite follows the brief: NotEncrypted.
//!  A2. The brief's rule 6 says "legacy SED (tag 18, no integrity)", but
//!      in OpenPGP the SED packet is tag 9; tag 18 is SEIPD. The SED test
//!      below uses tag 9.
//!  A3. >8 PKESKs: the rules cap the sequence at 8 but name no variant.
//!      Asserted as UnsupportedPacket (packet-structure violation).
//!  A4. PKESK/container pairing violations (rule 3) name no variant.
//!      Asserted as UnsupportedPacket.
//!  A5. extra_recipient_key_id: hex case is unspecified (asserted
//!      case-insensitively), and "that key's ID" is read as the key the
//!      PKESK actually names — the encryption SUBKEY's key ID for v4
//!      (GnuPG addresses PKESKs to subkeys), i.e. the last 16 hex of the
//!      SUBKEY fingerprint, not of the primary.
//!  A6. AED "sane chunk-size octet" gives no numeric bound. The test
//!      uses octet 0xFF, absurd under any encoding of chunk size.
//!  A7. Trailing bytes after the armor footer: asserted as Malformed
//!      (armor-structure failure).

use envelope::{extra_recipient_key_id, validate_envelope, EnvelopeContext, EnvelopeError, KeyRef};

// Primary fingerprints (uppercase hex, v4) of the fixture certs.
const SENDER_FPR: &str = "682FB74BFC12E3A277EAF58D93115D75C1477CB5";
const RECIPIENT_FPR: &str = "D4461BB29B9B30049A053399D43C9351FE45B57F";
const RETIRED_FPR: &str = "7BC57FD6BF82C4E250BCCCCAA89A714D29AA5EB3";
const THIRD_FPR: &str = "AA837465760E8AB24F77976572C1FA0629309BF5";
// Key ID (last 16 hex of the SUBKEY fingerprint) that a v4 PKESK uses to
// name the third party's encryption subkey A901766C...C63C7328.
const THIRD_SUBKEY_KEY_ID: &str = "9E7A1EF8C63C7328";

// Armored public cert: Blind sender <sender@blind.test> (ed25519 + cv25519 subkey).
const CERT_SENDER: &str = r#"-----BEGIN PGP PUBLIC KEY BLOCK-----

mDMEas+oGBYJKwYBBAHaRw8BAQdA3IXmZNhDZtfgafaKaI/WS0cfgfI/3Fgw130C
OgdKUW20IEJsaW5kIHNlbmRlciA8c2VuZGVyQGJsaW5kLnRlc3Q+iJMEExYKADsW
IQRoL7dL/BLjonfq9Y2TEV11wUd8tQUCas+oGAIbIwULCQgHAgIiAgYVCgkICwIE
FgIDAQIeBwIXgAAKCRCTEV11wUd8tffEAQDQbcHtXFlNxP+UMeHYytlz8wwQ1PPi
j2kaTFMjStuwywD+Om/sEyEfpsI7DgDFAQgPrRf1+dIppkkmWPn6MJYEMAm4OARq
z6gYEgorBgEEAZdVAQUBAQdAV3n/oJBH/d0R52UyQPdQEwo3Smt519CGuur07mzJ
Hm8DAQgHiHgEGBYKACAWIQRoL7dL/BLjonfq9Y2TEV11wUd8tQUCas+oGAIbDAAK
CRCTEV11wUd8tU0nAQCU6vCLcwtTKyBWk5bfsXf3Dxj0BN/Jkto0dRViRJ0puwEA
joxiFrBFDNKnCyW+fhof7CG4wEXVrt90ftNQ7jF2zA8=
=eb4F
-----END PGP PUBLIC KEY BLOCK-----"#;

// Armored public cert: Blind recipient <recipient@blind.test> — the current key.
const CERT_RECIPIENT: &str = r#"-----BEGIN PGP PUBLIC KEY BLOCK-----

mDMEas+oGBYJKwYBBAHaRw8BAQdAdr/GiIQTHZomPsfJfmB9I/YiM1f5rfmr46rW
Hbt0j8u0JkJsaW5kIHJlY2lwaWVudCA8cmVjaXBpZW50QGJsaW5kLnRlc3Q+iJME
ExYKADsWIQTURhuym5swBJoFM5nUPJNR/kW1fwUCas+oGAIbIwULCQgHAgIiAgYV
CgkICwIEFgIDAQIeBwIXgAAKCRDUPJNR/kW1fxkxAQDYtqvZbv+VntRDiq53a2Dq
Elo+C5Odzmb2BDGwhPq//AD+OJZ/jy3i/2OYSrjZ/MluLE6v+Q2ytrfPj8db/GdJ
4ga4OARqz6gYEgorBgEEAZdVAQUBAQdAgBsIjCwSeq4wUCF2LeEQ0I++xFkn4sZ0
SxSnzwLoCWkDAQgHiHgEGBYKACAWIQTURhuym5swBJoFM5nUPJNR/kW1fwUCas+o
GAIbDAAKCRDUPJNR/kW1f89sAQDoL12AyirMsyPIXEYcHYEp2LyAj5jfofwTme56
wIvNTQEAwyLMllW+mVWzR3JTSazKBLkW6eRnw46VdfbnY+yBYww=
=Y4kZ
-----END PGP PUBLIC KEY BLOCK-----"#;

// Armored public cert: Blind retired <retired@blind.test> — the recipient's rotated-away key.
const CERT_RETIRED: &str = r#"-----BEGIN PGP PUBLIC KEY BLOCK-----

mDMEas+oGBYJKwYBBAHaRw8BAQdAFD9iEJld/yX/k4WKqAtTtYKifSxcIILBDIYc
7GVBJpu0IkJsaW5kIHJldGlyZWQgPHJldGlyZWRAYmxpbmQudGVzdD6IkwQTFgoA
OxYhBHvFf9a/gsTiULzMyqiacU0pql6zBQJqz6gYAhsjBQsJCAcCAiICBhUKCQgL
AgQWAgMBAh4HAheAAAoJEKiacU0pql6zTWQBAJwHCfkeoUzCNoE1hz+ru34PZRDL
kxzWgXUT5Rn5hlzaAQDAmTZpKIdYxllPztzupTuLFp8rfyJcu1f2/ZdCmg5QB7g4
BGrPqBgSCisGAQQBl1UBBQEBB0DyUG+p0j6CIGPDsEh0ENGG4d9WoTKJTpfytEpF
WyrGDAMBCAeIeAQYFgoAIBYhBHvFf9a/gsTiULzMyqiacU0pql6zBQJqz6gYAhsM
AAoJEKiacU0pql6zCM0A/2cMaov6dPGLDYtkYI0i39p7i5XvYx3XfEucqRVDtN/d
AQD180WOtmzD6//YNqCgpeS616KyXW8HCJlTyNxuEX1gCQ==
=zMBe
-----END PGP PUBLIC KEY BLOCK-----"#;

// Armored public cert: Blind third <third@blind.test> — an unrelated third party.
const CERT_THIRD: &str = r#"-----BEGIN PGP PUBLIC KEY BLOCK-----

mDMEas+oGBYJKwYBBAHaRw8BAQdAcpsJMvEDPD5EiwSjrPLJ6y09bw0f8AcrAHlm
F3cXkcO0HkJsaW5kIHRoaXJkIDx0aGlyZEBibGluZC50ZXN0PoiTBBMWCgA7FiEE
qoN0ZXYOirJPd5dlcsH6Bikwm/UFAmrPqBgCGyMFCwkIBwICIgIGFQoJCAsCBBYC
AwECHgcCF4AACgkQcsH6Bikwm/UrXAEA31E8yUExUw/X65l8VY1W4/Dht+yknrkI
kaUDx+LKC6sA/RnP4yB66Z5WQJwci5Ud8uRRNitzFaUZLfDnAnGK48wEuDgEas+o
GBIKKwYBBAGXVQEFAQEHQO5oF2976+dNmiC7J9DCqh6y/jVkXxuAETlO2v55Ty0e
AwEIB4h4BBgWCgAgFiEEqoN0ZXYOirJPd5dlcsH6Bikwm/UFAmrPqBgCGwwACgkQ
csH6Bikwm/Vp3wD/aJ1DaqSJ/Jt7AcNzqQOwELUCD/vJM+8Z68BIUXFejLABAN+O
qFNUY4kx4thAuij2m0G4hkViBKqhTaJ5Mlm9mK4G
=MD8b
-----END PGP PUBLIC KEY BLOCK-----"#;

// gpg --encrypt -r recipient: v3 PKESK (subkey) + AED tag 20. The default happy path.
const MSG_TAG20_RECIPIENT: &str = r#"-----BEGIN PGP MESSAGE-----

hF4DMY9yhNcZMxESAQdAQ5iUMoyPlDBWv6Azhn4LHgdJsUbhMHEk7ulaBHFoD2cw
cRPdFiuBZysq/0XIhgQz2Qp2sPWkyb3xrSbt+K+w6ikN2HR8e9L0hY7goCzQAU/h
1F8BCQIQUm8jGdSzitUowSRJ43M5aLPP85E7NVVP1QolGl2bSJOG4IowV/C7g+mM
dfSAOx/2WbzUlU15oy38lYi3JsYCJKPNB/OM+5p/Oy21gg/uMxghzMYShu7CMwB3
nA==
=nteF
-----END PGP MESSAGE-----"#;

// gpg --encrypt -r sender -r recipient: two v3 PKESKs + AED tag 20.
const MSG_BOTH: &str = r#"-----BEGIN PGP MESSAGE-----

hF4D3fmq/BTEQjQSAQdAZ0txSzxdfAGvCRCkN+/WI55kcNlCAM5thMna5ovjY0Ew
bTPfViB99gYO8r2m4VyFh8mf+oJVnAQoF+3JjuX8ynnvKbOO4nA52tAf1FxWxDmr
hF4DMY9yhNcZMxESAQdABbn/LC9qcuQX3hAF5ZukZHAQ2CjE0r7M6ULWGhDuRzUw
pc8eHFVgf3lJbF2Tk69xljGfWHmN6pYpwLCWvijl2pCs/zGqTTfwmufYN44Uig6k
1F8BCQIQ4AzH2Lssf1vqCHVB/zGICXMyXXeLwZyQB6Z5+KPjEJV0sLAIwvEaOZgt
j3/XwzdQUlPpIrkCh2wTBVd97ogZe3wlrOIPd1zOLqbrv++Vm6QBXGAUo6A28te2
7w==
=KDKf
-----END PGP MESSAGE-----"#;

// gpg --encrypt -r sender only.
const MSG_SENDER_ONLY: &str = r#"-----BEGIN PGP MESSAGE-----

hF4D3fmq/BTEQjQSAQdAsFNOyce1JT0yVn0c+LzIcAqSyznWgdWAfOT5n1QyB1Iw
lFkkJZrSGrbtasP5zN8a2Yu8LVOr89ao/OZ9azpFbuCmY+4Z4/+st7P0EhZ6zRXC
1F8BCQIQ5zCq8/B8gM1sxLLWDwcg6CtCQVD1TtBQQfNxTbMcJWLnB12Zk40HX1e5
5zFQnIuhKOlA25i5P2k0bYn5LfLEYoppJA5YroO0RoeNVbQ+wJsYDpGX5lV7Wg+K
CQ==
=C6fT
-----END PGP MESSAGE-----"#;

// gpg --encrypt -r third only.
const MSG_THIRD_ONLY: &str = r#"-----BEGIN PGP MESSAGE-----

hF4Dnnoe+MY8cygSAQdA+FRwjWndiv3Pze9ZwqFi6DeVWbA8xcu+USMCRfXBIGcw
D2+u+rCOlb9c2io8IVN6wDbG4wyfOgV94Oes2xaojK5SH2slj6OHF8LRBsWgC3FJ
1F8BCQIQtm+RXR03DTE6Gdc0X3Vq4HpGWPrMaiOdS/geKEr6rSSPQGC+MCd8GM6v
MkcUeTgRgD8GY0MVdIypSHnUzcsP/G40dRTjva4G3+MAFMOuxQP8QziBlS+fxNe6
9Q==
=lvv7
-----END PGP MESSAGE-----"#;

// gpg --encrypt -r retired only: the leak-probe bytes.
const MSG_RETIRED_ONLY: &str = r#"-----BEGIN PGP MESSAGE-----

hF4DZOLJUNeW/EESAQdAuhO719WoD4QsrYmzYR6598TNUTo3ap3iMHVVd4bPFkow
U11oAZzl38LQm9+1xFxc2mtEW/d+VNBw5mkhM7wYTIWnh179ZgNZXjpHvH8MwI46
1F8BCQIQrNNMVQUpjwr2frZ7EPv3aq2UyvyJSJl6wDny9W1RZWv/BeGtNLcHUYZK
SoMgwK9lzyfN/L60Y1DvjAkyNd6VCQD1IMdkcNVaSZcU/9eJzMtpOg2SUcZhe3eA
Ag==
=Kty0
-----END PGP MESSAGE-----"#;

// gpg --encrypt -r recipient -r third.
const MSG_RECIPIENT_THIRD: &str = r#"-----BEGIN PGP MESSAGE-----

hF4DMY9yhNcZMxESAQdAIzND6edZPXLR2SvpcrKB8A7z8TVU7AOHGCKpXbFrLCIw
onqhngG+yniIdMWjwCjJYZQWIgQgDhkq4YAAl2uSJIq3O63U8wAtzOl1eMb69mCp
hF4Dnnoe+MY8cygSAQdAOGLK4Iejw3a8cOpqwtNvjttpf2FoLoM2EK+W7lx+jAow
7/tr1YJcZhmt/bIKg16YfjbMJPYjQWEMoEBNlXIuY9VBRFRS3ywc080Gxc+BPNi4
1F8BCQIQYQ0zjlbRPEVk8WS2yOzjA5MJQtMXli5gx391w5iFBTsoHizGf9b9Bpgy
yx/Ksv5eIxeEgWXBfHHDPHac4PXoUHrkFqVytl1o6NHW0SmvekMf45IJ3QQNmqgQ
eg==
=1CPO
-----END PGP MESSAGE-----"#;

// gpg --encrypt -r recipient -r retired.
const MSG_RECIPIENT_RETIRED: &str = r#"-----BEGIN PGP MESSAGE-----

hF4DMY9yhNcZMxESAQdACNpJTBTZkFjtC9pmU6ZJDESil9keQN2ClSRn6DyUnhsw
txT/8X8N2m7uZTgreicq4epi6cjh8CfSgQq/SCn2AZ9SVxFlSb4AvkVJ5ZM9Od4q
hF4DZOLJUNeW/EESAQdAtZiahX+qQomc1CFGXYf38Kc2G3JqDwJqdIFqOPJ6YWAw
6Na5JmDhl2ms99A6gcnHMo4ZCUk+Au9FBJRLFfzeNP6FA43oTBugXryFwhbME25t
1F8BCQIQkab74wpqP6Ok21f4Us8mtPwU4Eqhe4E07N4iF7r4NvjoeERG5R/sIkIp
KbUdPAGEVF1WUWh43wXiUBe7MdQ/KZPFMyOcsSNKJrn4GcI1DMkckpMm170BDWnx
/Q==
=5523
-----END PGP MESSAGE-----"#;

// gpg --encrypt -r retired -r third.
const MSG_RETIRED_THIRD: &str = r#"-----BEGIN PGP MESSAGE-----

hF4DZOLJUNeW/EESAQdAV4XYBpIACFTWS7nEuCGfQbjkYx0znXD3uv7MVUtAMD8w
xlU37fkzF030Un45c/IAc8QCdDE1acCTRqhK+L/8lb/MxhIeiCPPhtBMTWitUApP
hF4Dnnoe+MY8cygSAQdAgk4mUm+9f6H3GD8fY2mZk4wi+TKU4fcIVo9PTH/AOCcw
XLroJqXrVGheoAp+Jg1F1Z8qTtYseWCyJuDsoJsYI34+WsBKycdru5ASHCY3IVRL
1F8BCQIQEALAfnVllI46SHdkfR1IJldz7ZW4AFgkj3v8lgQqLnqyJ5XAlxaUq3HV
LMEOwIgJQXszZ4Qe/rd2spCPwzqLddItoE36gF3fSYI4Pul8v/omqLOlHda8IozW
cA==
=6zka
-----END PGP MESSAGE-----"#;

// gpg --encrypt --hidden-recipient recipient: PKESK key ID zeroed.
const MSG_HIDDEN_ONLY: &str = r#"-----BEGIN PGP MESSAGE-----

hF4DAAAAAAAAAAASAQdAeafUSVja4cufzi03v59p+i3dCZVoGVNpqV0ZKLHS7QEw
4o+wde9g87ld0dxW2Jok+Ff0h4BK5eQPqjEPYwz7McSGYpWMzPZdJi3xRAw7uK0X
1F8BCQIQikdkir9MsdPwBGOmnM+HA6Qzw+p10/lyp6vW5SREVD2BpsOiczFpgynj
Hiek5UdLhbMImv9ZRKyR8sbEiBXXUhj+ob+u/452yDXAPLTsgnRs/FQzakb/D3am
iQ==
=Vpzn
-----END PGP MESSAGE-----"#;

// gpg --encrypt -r recipient --hidden-recipient third.
const MSG_RECIPIENT_HIDDEN_THIRD: &str = r#"-----BEGIN PGP MESSAGE-----

hF4DMY9yhNcZMxESAQdAdxlcMV1oWsIq1GA6tf5tYN24RRV0HCH8ir2iftgCIScw
UC7H8fFS+2Sa2nKXZErRSIGX+30SNhyxqNAfFBHlj6CTKDKKjuR/z4Bsmgt4s32O
hF4DAAAAAAAAAAASAQdAR9wMXJKVNxUIFnmdIR1AIJfH9LEld7T5k3imOEpY3mIw
B9VOu6EwwTQ1Kx0yfTkCu8tYu5L4hAmY+K5wNMd5AnTr+BXGfmWvMkb7lPbTJmi3
1F8BCQIQX44Ejo/OFcwbuwgD42j65EqgqBMUkn8DHwrqj2KW4QEZY6pnYBT0+y2O
1eSLVW2laVcEeNLhOpJBBKsDgVjaeqMv5E+TE6PWvK52zhEp08qcpO7TZlIFLLQe
eg==
=r3nw
-----END PGP MESSAGE-----"#;

// gpg --encrypt with 9 recipients (recipient, sender, retired, third, extra1..extra5).
const MSG_NINE: &str = r#"-----BEGIN PGP MESSAGE-----

hF4DMY9yhNcZMxESAQdAlNIsK9T8RNWCHg2kZzkNe4UbVfZrilwUjWCrw7R0YAYw
KjuDKkA73hrDAGupJnNt/rr8AsMaqCW6yBjr8c0rQ5CS+8hdBgxQkx1eNVU2+wsE
hF4D3fmq/BTEQjQSAQdA77q4mFBcAbDVUi7PCHEuru7c5gIXynSxGbsGvdWhrlEw
YGh1O2CKJPrAQ0bEz653CemXwqTPVOjmPkTzsGM1FECjM31BpVPT+PfID6ZL1PFC
hF4DZOLJUNeW/EESAQdAzOo9GElQqhK3ooPaXdrn/Ut2EiO3G6ln77/QNrSZ3Hsw
79ZjYn5rSwP9IxMcLP+COIIt/jgi/CDQJb1nojm9Jcfe1+Q7UuIRH2iUWAkwztoc
hF4Dnnoe+MY8cygSAQdAgl+ZhnmguNnggYVimA+4VmSEJ7m2724XcySKNYEQPnIw
VdWxzxHYB4+tE0eH4aSEB/KhcVXWZ0on5qEN2hHnBgcZCSiqkomfdKMgNDlh7GRc
hF4Dg6V1oL+OAZkSAQdAxOcQUyACeXgZbvebwPbDa7rZZr8Oh0d4EwwC4sWWxQww
4tqrWR8C8MMrOb0gddfLSr3NTmQLuGCEks543WXQh0VzG+ts+Pi7VAyXvRzkLj4O
hF4DCuC4eezUsNwSAQdALOARIU5A/kHQnYk83+rAS7+WWJRZU0PxonzjAP3L+FMw
NmBDcANXa2W7IMZyBKFpRv0kSn1Jh0BlBJlAVBj1dnCRAddJt0VXGbBaWnG1RmJA
hF4Dx05XxQzVZx8SAQdAcHDPrTDIM7JXF5JelhYSrbBfpA0JhacqZSh8Qwk5nRUw
F5SntAfXyid3sZCoBUX3aoP27U7KPWqRMN4LrQBJBhFyQBDs7hPal5p2thHyaeUD
hF4DADxCGERV7IASAQdAMuhrs7O75crJJiqQv9mUhtNoKL+2iXIdfo+K/5rX1zgw
lBl5tealievPQyJDWK/b5bcMkQ0+DGgfJF+gxTLB80gVytyFM79oSUAKnJticoaP
hF4DByEBMzNyQpMSAQdAb0J/TBFIK3GOh7UJIclVZ1CaxbStmiRJ3ag1Tvh7Kmow
TQWPM9bYQk41OJuOoZzppCUKL30o90vaw7JRnaQgg+tbvrPk2kIwQ2JFzJqwtH2j
1F8BCQIQY4paudAatJdEeXdQWdEKg8tOJp3ganwSc2gYSbS4JZzHauymdq8/GK8f
3KWVS3aBJ41o2uuGG9Z1xzp28HpNpSCPyj7SNU9Kyw2c1yLJ7+T8ZOangY042NtR
mQ==
=daSL
-----END PGP MESSAGE-----"#;

// gpg --symmetric (AES256): SKESK packet + encrypted data, no PKESK.
const MSG_SYMMETRIC: &str = r#"-----BEGIN PGP MESSAGE-----

jA0ECQMKXXEOn/t/sg7/0lUBUwNYXVzOg7TZ5Drx7ded+qwdHhGAoCRPlh3Maa8n
eCubvYZrKt1JjcfWvhXDtf82YHPgcZ6CbCoPQAgSRf4rObjgQuOZ9i7GuN8yu2K+
87sQyf5s
=bjLu
-----END PGP MESSAGE-----"#;

// gpg --clearsign by sender: readable plaintext + signature block.
const MSG_CLEARSIGNED: &str = r#"-----BEGIN PGP SIGNED MESSAGE-----
Hash: SHA512

stage5 blind fixture plaintext
-----BEGIN PGP SIGNATURE-----

iIgEARYKADAWIQRoL7dL/BLjonfq9Y2TEV11wUd8tQUCas+oXhIcc2VuZGVyQGJs
aW5kLnRlc3QACgkQkxFddcFHfLW5qAEA7aGFxBHHdKyktPGloMwgYwtftG0V9BfU
ENZiMP8KJRUBAPkt4Om3cAGSymBhVUFa8m9B/uZlJm/TSD2yIhnqGVYH
=Biqc
-----END PGP SIGNATURE-----"#;

// ---------------------------------------------------------------------------
// Context builders
// ---------------------------------------------------------------------------

fn sender_ref() -> KeyRef {
    KeyRef::from_cert(CERT_SENDER.as_bytes()).expect("sender fixture cert must parse")
}
fn recipient_ref() -> KeyRef {
    KeyRef::from_cert(CERT_RECIPIENT.as_bytes()).expect("recipient fixture cert must parse")
}
fn retired_ref() -> KeyRef {
    KeyRef::from_cert(CERT_RETIRED.as_bytes()).expect("retired fixture cert must parse")
}
fn third_ref() -> KeyRef {
    KeyRef::from_cert(CERT_THIRD.as_bytes()).expect("third fixture cert must parse")
}

/// Standard two-party context; the sender was never shown a retired key.
fn ctx() -> EnvelopeContext {
    EnvelopeContext {
        sender: sender_ref(),
        recipient: recipient_ref(),
        recipient_retired_shown: Vec::new(),
    }
}

/// Context where the sender WAS shown the recipient's retired key in this
/// conversation.
fn ctx_retired_shown() -> EnvelopeContext {
    EnvelopeContext {
        sender: sender_ref(),
        recipient: recipient_ref(),
        recipient_retired_shown: vec![retired_ref()],
    }
}

fn expect_err(bytes: &[u8], c: &EnvelopeContext, want: EnvelopeError) {
    match validate_envelope(bytes, c) {
        Ok(_) => panic!("expected Err({want:?}), got Ok"),
        Err(e) => assert_eq!(e, want, "wrong taxonomy variant"),
    }
}

fn expect_ok_fingerprints(bytes: &[u8], c: &EnvelopeContext, want: &[&str]) {
    let info = validate_envelope(bytes, c).expect("expected envelope to validate");
    let mut got = info.recipient_fingerprints.clone();
    let mut want: Vec<String> = want.iter().map(|s| s.to_string()).collect();
    got.sort();
    want.sort();
    assert_eq!(got, want, "matched primary fingerprints");
}

// ---------------------------------------------------------------------------
// Minimal armor / packet tooling (std only) for spliced fixtures.
// ---------------------------------------------------------------------------

fn b64_val(c: u8) -> Option<u32> {
    match c {
        b'A'..=b'Z' => Some((c - b'A') as u32),
        b'a'..=b'z' => Some((c - b'a') as u32 + 26),
        b'0'..=b'9' => Some((c - b'0') as u32 + 52),
        b'+' => Some(62),
        b'/' => Some(63),
        _ => None,
    }
}

/// Extract the packet bytes from an armored PGP block (ignores the CRC).
fn dearmor(armored: &str) -> Vec<u8> {
    let mut out = Vec::new();
    let mut in_body = false;
    let mut acc: u32 = 0;
    let mut nbits: u32 = 0;
    for line in armored.lines() {
        if !in_body {
            if line.trim().is_empty() {
                in_body = true;
            }
            continue;
        }
        if line.starts_with('=') || line.starts_with("-----END") {
            break;
        }
        for &c in line.trim().as_bytes() {
            if let Some(v) = b64_val(c) {
                acc = (acc << 6) | v;
                nbits += 6;
                if nbits >= 8 {
                    nbits -= 8;
                    out.push((acc >> nbits) as u8);
                    acc &= (1 << nbits) - 1;
                }
            }
        }
    }
    out
}

const B64: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";

fn b64_encode(data: &[u8]) -> String {
    let mut s = String::new();
    for chunk in data.chunks(3) {
        let b = [
            chunk[0] as u32,
            *chunk.get(1).unwrap_or(&0) as u32,
            *chunk.get(2).unwrap_or(&0) as u32,
        ];
        let n = (b[0] << 16) | (b[1] << 8) | b[2];
        s.push(B64[(n >> 18) as usize & 63] as char);
        s.push(B64[(n >> 12) as usize & 63] as char);
        s.push(if chunk.len() > 1 {
            B64[(n >> 6) as usize & 63] as char
        } else {
            '='
        });
        s.push(if chunk.len() > 2 {
            B64[n as usize & 63] as char
        } else {
            '='
        });
    }
    s
}

fn crc24(data: &[u8]) -> u32 {
    let mut crc: u32 = 0xB704CE;
    for &b in data {
        crc ^= (b as u32) << 16;
        for _ in 0..8 {
            crc <<= 1;
            if crc & 0x1000000 != 0 {
                crc ^= 0x1864CFB;
            }
        }
    }
    crc & 0xFFFFFF
}

/// Armor-encode raw packet bytes as a PGP MESSAGE block (with CRC).
fn armor(data: &[u8]) -> String {
    let body = b64_encode(data);
    let mut s = String::from("-----BEGIN PGP MESSAGE-----\n\n");
    for chunk in body.as_bytes().chunks(64) {
        s.push_str(std::str::from_utf8(chunk).expect("base64 is ascii"));
        s.push('\n');
    }
    let crc = crc24(data);
    let crc_bytes = [(crc >> 16) as u8, (crc >> 8) as u8, crc as u8];
    s.push('=');
    s.push_str(&b64_encode(&crc_bytes));
    s.push('\n');
    s.push_str("-----END PGP MESSAGE-----\n");
    s
}

/// Build one new-format packet with a definite length.
fn pkt(tag: u8, body: &[u8]) -> Vec<u8> {
    let mut v = vec![0xC0 | tag];
    let len = body.len();
    if len < 192 {
        v.push(len as u8);
    } else if len < 16320 {
        v.push((192 + ((len - 192) >> 8)) as u8);
        v.push(((len - 192) & 0xFF) as u8);
    } else {
        v.push(255);
        v.extend_from_slice(&(len as u32).to_be_bytes());
    }
    v.extend_from_slice(body);
    v
}

/// The first (PKESK) packet of the real recipient message, as raw bytes.
///
/// Q7a CONSTRUCTION FIX (2026-10-14, applied by the implementer, assertions
/// in the tests unchanged): GnuPG emits the PKESK with an OLD-format packet
/// header (0x85), not a new-format one, so the original splitter's
/// new-format assertion rejected every genuine fixture. The splitter now
/// parses both header formats; only the tag assertion remains.
fn recipient_pkesk() -> Vec<u8> {
    let bin = dearmor(MSG_TAG20_RECIPIENT);
    let (hdr, len) = if bin[0] & 0x40 != 0 {
        // New-format header.
        assert_eq!(bin[0] & 0x3F, 1, "first fixture packet must be a PKESK");
        match bin[1] {
            l if l < 192 => (2usize, l as usize),
            l if l < 224 => (3usize, 192 + ((l as usize - 192) << 8) + bin[2] as usize),
            255 => (
                6usize,
                u32::from_be_bytes([bin[2], bin[3], bin[4], bin[5]]) as usize,
            ),
            _ => panic!("fixture splitter does not handle partial body lengths"),
        }
    } else {
        // Old-format header: tag in bits 5..2, length type in bits 1..0.
        assert_eq!((bin[0] >> 2) & 0xF, 1, "first fixture packet must be a PKESK");
        match bin[0] & 0x3 {
            0 => (2usize, bin[1] as usize),
            1 => (3usize, u16::from_be_bytes([bin[1], bin[2]]) as usize),
            2 => (
                5usize,
                u32::from_be_bytes([bin[1], bin[2], bin[3], bin[4]]) as usize,
            ),
            _ => panic!("fixture splitter does not handle indeterminate lengths"),
        }
    };
    bin[..hdr + len].to_vec()
}

/// A message made of the real recipient PKESK + a hand-built container.
fn spliced(container: Vec<u8>) -> String {
    let mut v = recipient_pkesk();
    v.extend_from_slice(&container);
    armor(&v)
}

fn junk(n: usize) -> Vec<u8> {
    vec![0xA5; n]
}

// ---------------------------------------------------------------------------
// Taxonomy basics: Empty / NotEncrypted / Malformed (rules 1, 6)
// ---------------------------------------------------------------------------

#[test]
fn empty_input_is_empty() {
    expect_err(b"", &ctx(), EnvelopeError::Empty);
}

#[test]
fn plaintext_is_not_encrypted() {
    expect_err(
        b"meet at the usual place at noon, no encryption here",
        &ctx(),
        EnvelopeError::NotEncrypted,
    );
}

#[test]
fn clearsigned_message_is_not_encrypted() {
    // A clearsigned message is readable plaintext with a signature, not an
    // encrypted envelope.
    expect_err(
        MSG_CLEARSIGNED.as_bytes(),
        &ctx(),
        EnvelopeError::NotEncrypted,
    );
}

#[test]
fn literal_only_packet_is_not_encrypted() {
    // A bare literal data packet (tag 11): 't' format, empty filename,
    // zero date, then text. Per rule 6 of the brief this is NotEncrypted
    // (see ambiguity A1 in the file header).
    let mut body = vec![b't', 0, 0, 0, 0, 0];
    body.extend_from_slice(b"just a literal packet");
    let msg = armor(&pkt(11, &body));
    expect_err(msg.as_bytes(), &ctx(), EnvelopeError::NotEncrypted);
}

#[test]
fn corrupt_armor_is_malformed() {
    let broken =
        "-----BEGIN PGP MESSAGE-----\n\n!!! this is not base64 !!!\n-----END PGP MESSAGE-----\n";
    expect_err(broken.as_bytes(), &ctx(), EnvelopeError::Malformed);
}

#[test]
fn truncated_armor_is_malformed() {
    let half = &MSG_TAG20_RECIPIENT[..MSG_TAG20_RECIPIENT.len() / 2];
    expect_err(half.as_bytes(), &ctx(), EnvelopeError::Malformed);
}

#[test]
fn trailing_bytes_after_armor_footer_are_malformed() {
    // Rule 4: no trailing bytes after the armor footer.
    let mut s = String::from(MSG_TAG20_RECIPIENT);
    s.push_str("\nTRAILING GARBAGE\n");
    expect_err(s.as_bytes(), &ctx(), EnvelopeError::Malformed);
}

// ---------------------------------------------------------------------------
// Accepted containers and happy paths (rules 2, 3, 10, 11)
// ---------------------------------------------------------------------------

#[test]
fn tag20_aed_to_recipient_validates() {
    // Genuine GnuPG 2.4.4 default output: v3 PKESK (naming the recipient's
    // encryption SUBKEY) + LibrePGP AED tag 20 (AES-256 / OCB). Success
    // here also proves certificate-level subkey matching (rule 11).
    expect_ok_fingerprints(MSG_TAG20_RECIPIENT.as_bytes(), &ctx(), &[RECIPIENT_FPR]);
}

#[test]
fn seipd_v1_to_recipient_validates() {
    // Spliced: real v3 PKESK + hand-built SEIPD v1 (tag 18, version 1).
    // Rule 3 pairing: v3 PKESK -> SEIPD v1 is an accepted combination.
    let mut body = vec![1u8];
    body.extend_from_slice(&junk(32));
    let msg = spliced(pkt(18, &body));
    expect_ok_fingerprints(msg.as_bytes(), &ctx(), &[RECIPIENT_FPR]);
}

#[test]
fn message_to_both_participants_validates_and_lists_both() {
    // Encrypted to BOTH current keys: succeeds, and EnvelopeInfo lists
    // both PRIMARY fingerprints (rule 10).
    expect_ok_fingerprints(MSG_BOTH.as_bytes(), &ctx(), &[SENDER_FPR, RECIPIENT_FPR]);
}

// ---------------------------------------------------------------------------
// Recipient matching failures (rules 7, 8, 9)
// ---------------------------------------------------------------------------

#[test]
fn message_to_sender_only_is_wrong_recipient() {
    // The recipient has no PKESK at all; only the sender's copy exists.
    expect_err(
        MSG_SENDER_ONLY.as_bytes(),
        &ctx(),
        EnvelopeError::WrongRecipient,
    );
}

#[test]
fn message_to_third_party_only_is_wrong_recipient() {
    expect_err(
        MSG_THIRD_ONLY.as_bytes(),
        &ctx(),
        EnvelopeError::WrongRecipient,
    );
}

#[test]
fn message_under_wrong_context_recipient_is_wrong_recipient() {
    // Same bytes as the happy path, but the conversation's recipient is a
    // different person: no PKESK matches THEIR current key. There is no
    // registered-vs-unknown distinction to leak here.
    let c = EnvelopeContext {
        sender: sender_ref(),
        recipient: third_ref(),
        recipient_retired_shown: Vec::new(),
    };
    expect_err(
        MSG_TAG20_RECIPIENT.as_bytes(),
        &c,
        EnvelopeError::WrongRecipient,
    );
}

#[test]
fn fingerprint_only_recipient_ref_cannot_match_subkey_pkesk() {
    // Contract: from_fingerprint knows only the primary fingerprint and
    // its key ID. GnuPG addressed the PKESK to the encryption SUBKEY, so
    // a fingerprint-only recipient ref must NOT match it.
    let c = EnvelopeContext {
        sender: sender_ref(),
        recipient: KeyRef::from_fingerprint(RECIPIENT_FPR),
        recipient_retired_shown: Vec::new(),
    };
    expect_err(
        MSG_TAG20_RECIPIENT.as_bytes(),
        &c,
        EnvelopeError::WrongRecipient,
    );
}

// ---------------------------------------------------------------------------
// Hidden recipients (rule 7 — precedence over matching)
// ---------------------------------------------------------------------------

#[test]
fn hidden_recipient_is_reported_hidden() {
    // Encrypted to the recipient with --hidden-recipient: the PKESK key
    // ID is zeroed, so even the "right" key arrives as a wildcard.
    expect_err(
        MSG_HIDDEN_ONLY.as_bytes(),
        &ctx(),
        EnvelopeError::HiddenRecipient,
    );
}

#[test]
fn hidden_recipient_takes_precedence_over_match_and_extra() {
    // Recipient matches openly AND a third party is hidden: the taxonomy
    // order puts HiddenRecipient before both success and ExtraRecipient.
    expect_err(
        MSG_RECIPIENT_HIDDEN_THIRD.as_bytes(),
        &ctx(),
        EnvelopeError::HiddenRecipient,
    );
}

// ---------------------------------------------------------------------------
// The retired-key leak fix (rule 8) — the heart of this suite
// ---------------------------------------------------------------------------

#[test]
fn retired_key_shown_in_conversation_is_retired() {
    // The PKESK matches only the recipient's retired key, and that key
    // WAS shown to the sender in this conversation -> RecipientKeyRetired.
    expect_err(
        MSG_RETIRED_ONLY.as_bytes(),
        &ctx_retired_shown(),
        EnvelopeError::RecipientKeyRetired,
    );
}

#[test]
fn retired_key_not_shown_is_wrong_recipient_leak_probe() {
    // THE probe case: identical bytes, but the retired key was never
    // shown to this sender. Answering RecipientKeyRetired here would let
    // any sender probe whether a key ever belonged to the recipient.
    // It must be indistinguishable from any other wrong key.
    expect_err(
        MSG_RETIRED_ONLY.as_bytes(),
        &ctx(),
        EnvelopeError::WrongRecipient,
    );
}

#[test]
fn retired_key_shown_by_fingerprint_only_does_not_match_subkey_pkesk() {
    // A shown-retired entry built from a bare fingerprint knows only the
    // primary fingerprint + primary key ID; the PKESK names the retired
    // cert's encryption SUBKEY, so it cannot establish "shown" either.
    let c = EnvelopeContext {
        sender: sender_ref(),
        recipient: recipient_ref(),
        recipient_retired_shown: vec![KeyRef::from_fingerprint(RETIRED_FPR)],
    };
    expect_err(
        MSG_RETIRED_ONLY.as_bytes(),
        &c,
        EnvelopeError::WrongRecipient,
    );
}

#[test]
fn current_key_match_wins_over_retired() {
    // Encrypted to current AND retired keys, retired one shown: the
    // current match means Rule 8's precondition ("none matches current")
    // fails, so this is a normal success.
    expect_ok_fingerprints(
        MSG_RECIPIENT_RETIRED.as_bytes(),
        &ctx_retired_shown(),
        &[RECIPIENT_FPR],
    );
}

#[test]
fn retired_match_reported_before_extra_recipient() {
    // Encrypted to the retired key (shown) and a third party: taxonomy
    // order puts RecipientKeyRetired before ExtraRecipient.
    expect_err(
        MSG_RETIRED_THIRD.as_bytes(),
        &ctx_retired_shown(),
        EnvelopeError::RecipientKeyRetired,
    );
}

// ---------------------------------------------------------------------------
// Extra recipients (rule 9)
// ---------------------------------------------------------------------------

#[test]
fn extra_recipient_flagged_with_key_id_only() {
    expect_err(
        MSG_RECIPIENT_THIRD.as_bytes(),
        &ctx(),
        EnvelopeError::ExtraRecipient,
    );
    // The helper names the extra key by key ID only — for this v4 PKESK
    // that is the key ID of the third party's encryption subkey (see
    // ambiguity A5). Never a fingerprint, never an owner.
    let id = extra_recipient_key_id(MSG_RECIPIENT_THIRD.as_bytes(), &ctx())
        .expect("extra recipient key ID must be reported");
    assert_eq!(id.len(), 16, "v4 key ID is 16 hex chars, got {id:?}");
    assert!(
        id.chars().all(|c| c.is_ascii_hexdigit()),
        "key ID must be hex: {id:?}"
    );
    assert_eq!(
        id.to_uppercase(),
        THIRD_SUBKEY_KEY_ID,
        "key ID of the third party's encryption subkey"
    );
    assert_ne!(
        id.to_uppercase(),
        THIRD_FPR,
        "must not leak the full fingerprint"
    );
    // And a clean two-party message has no extra recipient to report.
    assert_eq!(extra_recipient_key_id(MSG_BOTH.as_bytes(), &ctx()), None);
    assert_eq!(
        extra_recipient_key_id(MSG_TAG20_RECIPIENT.as_bytes(), &ctx()),
        None
    );
}

// ---------------------------------------------------------------------------
// Packet-structure rules (rules 2, 3, 4, 6)
// ---------------------------------------------------------------------------

#[test]
fn nine_pkesks_rejected() {
    // Rule 4 allows 1-8 PKESKs; this genuine GnuPG message has 9 (the
    // recipient IS among them, so only the count can fail it). Variant:
    // see ambiguity A3.
    expect_err(
        MSG_NINE.as_bytes(),
        &ctx(),
        EnvelopeError::UnsupportedPacket,
    );
}

#[test]
fn symmetric_skesk_is_unsupported() {
    // Genuine GnuPG --symmetric output: SKESK + encrypted data, no PKESK.
    expect_err(
        MSG_SYMMETRIC.as_bytes(),
        &ctx(),
        EnvelopeError::UnsupportedPacket,
    );
}

#[test]
fn legacy_sed_container_is_unsupported() {
    // Real PKESK + hand-built legacy SED packet (tag 9, no integrity
    // protection). See ambiguity A2 about the brief's "tag 18" wording.
    let msg = spliced(pkt(9, &junk(32)));
    expect_err(msg.as_bytes(), &ctx(), EnvelopeError::UnsupportedPacket);
}

#[test]
fn padding_packet_is_unsupported() {
    // Padding (tag 21) is rejected until a real client emits it (rule 4).
    let msg = spliced(pkt(21, &junk(16)));
    expect_err(msg.as_bytes(), &ctx(), EnvelopeError::UnsupportedPacket);
}

#[test]
fn marker_packet_is_unsupported() {
    let msg = spliced(pkt(10, b"PGP"));
    expect_err(msg.as_bytes(), &ctx(), EnvelopeError::UnsupportedPacket);
}

#[test]
fn unknown_packet_in_container_position_is_unsupported() {
    // Tag 17 (user attribute) is not an encrypted container; rule 2: no
    // unknown packet is ever accepted in the container position.
    let msg = spliced(pkt(17, &junk(8)));
    expect_err(msg.as_bytes(), &ctx(), EnvelopeError::UnsupportedPacket);
}

#[test]
fn compressed_top_level_is_unsupported() {
    // A lone compressed packet (tag 8, ZIP algo octet + filler) is not an
    // encrypted envelope and must not be descended into (rule 6).
    let mut body = vec![1u8];
    body.extend_from_slice(&junk(16));
    let msg = armor(&pkt(8, &body));
    expect_err(msg.as_bytes(), &ctx(), EnvelopeError::UnsupportedPacket);
}

// ---------------------------------------------------------------------------
// AED tag 20 header hand-check (rule 2: version 1; AES only; OCB or EAX;
// sane chunk size). All spliced behind a real recipient PKESK.
// ---------------------------------------------------------------------------

#[test]
fn aed_with_non_aes_cipher_is_unsupported() {
    // Header: version 1, cipher 3 (CAST5 — not AES 7/8/9), mode 2, chunk 16.
    let mut body = vec![1u8, 3, 2, 16];
    body.extend_from_slice(&junk(32));
    let msg = spliced(pkt(20, &body));
    expect_err(msg.as_bytes(), &ctx(), EnvelopeError::UnsupportedPacket);
}

#[test]
fn aed_with_bad_version_is_unsupported() {
    // Header: version 2 (must be 1), cipher 9, mode 2, chunk 16.
    let mut body = vec![2u8, 9, 2, 16];
    body.extend_from_slice(&junk(32));
    let msg = spliced(pkt(20, &body));
    expect_err(msg.as_bytes(), &ctx(), EnvelopeError::UnsupportedPacket);
}

#[test]
fn aed_with_bad_mode_is_unsupported() {
    // Header: version 1, cipher 9, mode 7 (neither EAX=1 nor OCB=2), chunk 16.
    let mut body = vec![1u8, 9, 7, 16];
    body.extend_from_slice(&junk(32));
    let msg = spliced(pkt(20, &body));
    expect_err(msg.as_bytes(), &ctx(), EnvelopeError::UnsupportedPacket);
}

#[test]
fn aed_with_absurd_chunk_size_is_unsupported() {
    // Header: version 1, cipher 9, mode 2, chunk-size octet 0xFF (see
    // ambiguity A6: the rules require "sane" without a numeric bound).
    let mut body = vec![1u8, 9, 2, 0xFF];
    body.extend_from_slice(&junk(32));
    let msg = spliced(pkt(20, &body));
    expect_err(msg.as_bytes(), &ctx(), EnvelopeError::UnsupportedPacket);
}

#[test]
fn seipd_v2_container_with_v3_pkesk_is_pairing_violation() {
    // Rule 3: v3 PKESKs pair ONLY with SEIPD v1 or tag 20. A spliced
    // RFC 9580 SEIPD v2 container (tag 18, version 2, cipher 9, AEAD 2,
    // chunk 16, 32-byte salt) behind a v3 PKESK must be rejected.
    // Variant: see ambiguity A4.
    let mut body = vec![2u8, 9, 2, 16];
    body.extend_from_slice(&junk(32)); // salt
    body.extend_from_slice(&junk(16)); // first chunk filler
    let msg = spliced(pkt(18, &body));
    expect_err(msg.as_bytes(), &ctx(), EnvelopeError::UnsupportedPacket);
}

// ---------------------------------------------------------------------------
// Size cap (rule 5)
// ---------------------------------------------------------------------------

#[test]
fn oversize_input_never_succeeds() {
    // A valid message padded past the 64 KiB submitted-bytes cap with a
    // huge armor Comment header. Rule 5 names no variant — only that
    // oversize input must not succeed.
    let comment = "A".repeat(70_000);
    let big = MSG_TAG20_RECIPIENT.replacen(
        "-----BEGIN PGP MESSAGE-----\n",
        &format!("-----BEGIN PGP MESSAGE-----\nComment: {comment}\n"),
        1,
    );
    assert!(big.len() > 64 * 1024, "fixture must exceed the 64 KiB cap");
    assert!(
        validate_envelope(big.as_bytes(), &ctx()).is_err(),
        "oversize input must not validate"
    );
}

// ---------------------------------------------------------------------------
// RFC 9580 v6 cases — #[ignore]d: GnuPG 2.4.4 cannot mint v6 keys or v6
// PKESKs, so these packets are hand-built per RFC 9580 section 5.1 and
// the author cannot verify that a strict packet parser accepts the
// synthetic PKESK encoding (anonymous-recipient field layout). The tests
// state the rule-3 pairings precisely; un-ignore once a v6 fixture can
// be produced with a real RFC 9580 implementation for cross-checking.
// ---------------------------------------------------------------------------

/// Invented v6 primary fingerprint (64 hex) for the ignored tests.
const V6_FPR: &str = "0123456789ABCDEF0123456789ABCDEF0123456789ABCDEF0123456789ABCDEF";

/// Hand-built v6 PKESK (RFC 9580): version 6, fingerprint length +
/// fingerprint, ECDH (18), ephemeral MPI, wrapped session key (synthetic
/// bytes — the validator never decrypts).
fn pkesk_v6(fpr_hex: &str) -> Vec<u8> {
    let fpr: Vec<u8> = (0..fpr_hex.len() / 2)
        .map(|i| u8::from_str_radix(&fpr_hex[2 * i..2 * i + 2], 16).expect("hex"))
        .collect();
    let mut body = vec![6u8, fpr.len() as u8];
    body.extend_from_slice(&fpr);
    body.push(18); // ECDH
    body.extend_from_slice(&[0x01, 0x00]); // MPI bit length: 256
    body.extend_from_slice(&[0xAA; 32]); // ephemeral key material (synthetic)
    body.push(40); // wrapped session key length
    body.extend_from_slice(&[0xBB; 40]);
    pkt(1, &body)
}

fn seipd_v2_container() -> Vec<u8> {
    let mut body = vec![2u8, 9, 2, 16];
    body.extend_from_slice(&junk(32)); // salt
    body.extend_from_slice(&junk(16));
    pkt(18, &body)
}

fn ctx_v6_recipient() -> EnvelopeContext {
    EnvelopeContext {
        sender: sender_ref(),
        recipient: KeyRef::from_fingerprint(V6_FPR),
        recipient_retired_shown: Vec::new(),
    }
}

#[test]
#[ignore = "hand-built v6 PKESK: encoding not verifiable with GnuPG 2.4.4 alone"]
fn v6_pkesk_with_seipd_v2_validates() {
    // Rule 3: v6 PKESK -> SEIPD v2 is THE accepted v6 pairing, and a v6
    // PKESK names the full fingerprint, so a fingerprint-built KeyRef
    // can match it (contrast the v4 subkey case above).
    let mut v = pkesk_v6(V6_FPR);
    v.extend_from_slice(&seipd_v2_container());
    let msg = armor(&v);
    expect_ok_fingerprints(msg.as_bytes(), &ctx_v6_recipient(), &[V6_FPR]);
}

#[test]
#[ignore = "hand-built v6 PKESK: encoding not verifiable with GnuPG 2.4.4 alone"]
fn v6_pkesk_with_seipd_v1_is_pairing_violation() {
    // Rule 3: v6 PKESKs pair with SEIPD v2 ONLY.
    let mut body = vec![1u8];
    body.extend_from_slice(&junk(32));
    let mut v = pkesk_v6(V6_FPR);
    v.extend_from_slice(&pkt(18, &body));
    let msg = armor(&v);
    expect_err(
        msg.as_bytes(),
        &ctx_v6_recipient(),
        EnvelopeError::UnsupportedPacket,
    );
}

#[test]
#[ignore = "hand-built v6 PKESK: encoding not verifiable with GnuPG 2.4.4 alone"]
fn mixed_pkesk_versions_rejected() {
    // Rule 3: mixed PKESK versions in one message are rejected. Here a
    // real v3 PKESK for the recipient is followed by a v6 PKESK; the
    // version mix alone must sink it.
    let mut v = recipient_pkesk(); // real v3 PKESK
    v.extend_from_slice(&pkesk_v6(V6_FPR));
    v.extend_from_slice(&seipd_v2_container());
    let msg = armor(&v);
    expect_err(msg.as_bytes(), &ctx(), EnvelopeError::UnsupportedPacket);
}
