# Signing & notarization checklist (operator)

Software in this repo builds **unsigned** release layouts via `scripts/release/build_unsigned.sh`.  
The following steps require **your** certificates and portal access. Agents cannot complete them.

---

## macOS — Developer ID + notarization

1. Enroll in [Apple Developer Program](https://developer.apple.com).
2. Create **Developer ID Application** certificate in Xcode / Certificates portal.
3. Import cert + private key into the signing Mac’s Keychain.
4. Build release binaries (or unpack unsigned tarball from `build_unsigned.sh`).
5. Sign:

```bash
codesign --force --options runtime --timestamp \
  --sign "Developer ID Application: <YOUR NAME> (<TEAMID>)" \
  dist/.../bin/ash dist/.../bin/raven-node dist/.../bin/raven-swarm
codesign --verify --verbose=2 dist/.../bin/ash
```

6. Zip/app-bundle as required by `notarytool`.
7. Store credentials once, then submit. **Never pass the app-specific password
   with `--password` on the command line**: it lands in shell history, `ps`
   output and process listings (this repo's "no secrets in argv" rule). Omit it
   so `notarytool` prompts interactively and keeps it in the Keychain:

```bash
# one time on the signing Mac (prompts for the app-specific password)
xcrun notarytool store-credentials "raven-notary" \
  --apple-id "<apple-id>" --team-id "<TEAMID>"
# every release
xcrun notarytool submit <archive.zip> --keychain-profile "raven-notary" --wait
xcrun stapler staple <artifact>
```

   Alternative: App Store Connect API-key auth (`--key <AuthKey.p8> --key-id <ID>
   --issuer <issuer-uuid>`), with the key file kept out of the repo.

8. Gatekeeper check: download on a clean Mac; open without right-click bypass.
9. Optional: Developer ID Installer + productbuild for `.pkg`.

**Blocked without:** Apple ID with paid membership, certs, and a stored `notarytool` keychain profile (app-specific password) or an API key.

---

## Windows — Authenticode / MSI

1. Obtain Authenticode code-signing certificate (EV recommended for SmartScreen reputation).
2. Import into certificate store or use USB token.
3. Sign:

```powershell
signtool sign /fd SHA256 /tr http://timestamp.digicert.com /td SHA256 /a ash.exe
signtool sign /fd SHA256 /tr http://timestamp.digicert.com /td SHA256 /a raven-node.exe
signtool verify /pa ash.exe
```

4. Build MSI/MSIX with WiX / Advanced Installer / your pipeline (not shipped here).
5. Sign the installer package similarly.
6. Optional: Microsoft Store submission (separate Partner Center account).

**Blocked without:** org signing cert, timestamp URL access, installer project.

---

## Linux packaging (optional)

1. Build with `build_unsigned.sh` on the target distro.
2. Package deb/rpm with distro tooling; sign with your GPG key for apt/yum repos.
3. Publish to your repository — **do not** claim Raven-operated mandatory relays.

---

## After signing

- Recompute SHA256 of **signed** artifacts (they differ from unsigned sums).
- Attach signed hashes to the GitHub Release (when you choose to publish).
- Keep notarization / signtool logs offline for auditors.
