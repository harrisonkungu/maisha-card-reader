# Kenyan Maisha Card/NFC enabled and e-Passport Reader

Android app that uses the NFC chip to communicate with kenyan maisha card/and e-passport.

## Contacts

Author - Harrison Kungu ([Email](mailto:harrisonkungu96@gmail.com))

## Dependencies

Third party dependencies:

📘 JMRTD
Purpose: Java library for reading electronic Machine-Readable Travel Documents (eMRTDs) like ePassports using ICAO 9303 standards.
Used For: Reading and parsing passport data (DG1, DG2, SOD, etc.) via NFC.
License: LGPL 3.0 — free to use, but changes to the library must be shared if distributed.

🧠 SCUBA (Smart Card Utils for Java)
Purpose: Low-level smart card communication utilities, often used with JMRTD.
Used For: Abstracts APDU communication with smart cards (e.g., NFC passports).
License: LGPL 3.0 — same licensing model as JMRTD, often used together.

🔐 Spongy Castle
Purpose: A repackaged version of Bouncy Castle for Android. Provides cryptography APIs.
Used For: Hashing, encryption/decryption, signature verification, needed for SOD validation in passports.
License: MIT-style Bouncy Castle License — very permissive, free for commercial use.

🖼️ JP2-Android (dev.keiji.jp2:jp2-android:1.0.4)
Purpose: A lightweight Android wrapper around the OpenJPEG library for decoding JPEG 2000 (JP2) images.
Used For: Displaying facial images extracted from DG2 files in ePassports, which are typically encoded in JPEG 2000 format.
Author: Keiji Ariyama
License: BSD 2-Clause — a permissive open-source license allowing use in both commercial and open-source projects.
Notable: Simplifies integration of JP2 decoding into Android apps without native code setup.


🧬 JNBIS
Purpose: Java library for decoding NIST biometric data formats (e.g., fingerprints).
Used For: Parsing and rendering biometric data stored in standard government formats.
License: Apache 2.0 — highly permissive, allows use in proprietary and open-source software.

📅 Material DateTimePicker
Purpose: A modern, material-themed date and time picker UI for Android apps.
Used For: User-friendly input for dates and times (e.g., DOB in passport forms).
License: Apache 2.0 — open and flexible for any type of project.

## License

    Apache License, Version 2.0

    Licensed under the Apache License, Version 2.0 (the "License");
    you may not use this file except in compliance with the License.
    You may obtain a copy of the License at

        http://www.apache.org/licenses/LICENSE-2.0

    Unless required by applicable law or agreed to in writing, software
    distributed under the License is distributed on an "AS IS" BASIS,
    WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
    See the License for the specific language governing permissions and
    limitations under the License.
