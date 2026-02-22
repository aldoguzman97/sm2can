# Legal Notice

## Trademark Disclaimer

"Scanmatik", "SM2 Pro", "Scanmatik 2 Pro", and all related names, logos,
and product names are trademarks or registered trademarks of their respective
owners. This project is **not** affiliated with, endorsed by, sponsored by,
or in any way officially connected with Scanmatik LLC, its parent companies,
subsidiaries, or affiliates.

The names "Scanmatik" and "SM2 Pro" are used in this project solely for the
purpose of identification and interoperability, as permitted under
nominative fair use doctrine.

## Clean Room Reverse Engineering

This software was developed using **clean room reverse engineering**
techniques, a practice that is well-established as lawful under:

- **United States**: *Sega Enterprises Ltd. v. Accolade, Inc.*, 977 F.2d 1510
  (9th Cir. 1992) — reverse engineering for interoperability is fair use.
  *Sony Computer Entertainment v. Connectix Corp.*, 203 F.3d 596 (9th Cir. 2000)
  — intermediate copying during reverse engineering is permissible when the
  final product is independently created.

- **European Union**: Directive 2009/24/EC, Article 6 — decompilation for
  interoperability is permitted without authorization from the rights holder.

- **Japan**: Copyright Act, Article 47-3 — reproduction for the purpose of
  achieving interoperability is permitted.

### What this means in practice

1. **No proprietary code was used.** Every line of code in this project was
   written from scratch. No code was copied, decompiled, or extracted from
   any Scanmatik software, driver, or firmware.

2. **No proprietary documentation was used.** The protocol implemented here
   was determined entirely through observation of the publicly visible USB
   interface of a legitimately purchased device, using standard USB analysis
   tools (USBPcap, Wireshark, pyusb).

3. **The techniques used are standard practice.** USB descriptor analysis,
   endpoint probing, and traffic capture between a host and a device are
   the same techniques used by every open-source device driver project
   (the Linux kernel, libusb ecosystem, OpenOCD, sigrok, etc.).

4. **The purpose is interoperability.** This project exists solely to allow
   the SM2 Pro hardware — which users have legitimately purchased and own —
   to function on operating systems not supported by the manufacturer
   (macOS and Linux).

## No Warranty

This software is provided "as is" without warranty of any kind. See the
[MIT License](LICENSE) for full terms. Use of this software with CAN bus
hardware and vehicles is at your own risk. The author is not liable for
any damage to hardware, vehicles, or other property.

## Responsible Disclosure

If the manufacturer of the SM2 Pro hardware believes any aspect of this
project infringes on their rights, the author welcomes communication
before any legal action. Contact: via GitHub Issues or the email address
listed in the repository owner's GitHub profile.
