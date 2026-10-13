# deZap — a whatsapp decompiler helper

**Apenas para fins acadêmicos e de pesquisa / For academic and research purposes only.** Analyze only authorized local inputs. This purpose statement does not authorize third-party decompilation, redistribution or circumvention, and does not override laws, contracts or licenses. No legal guarantee is provided.

The title identifies a research use case, not affiliation or endorsement. deZap is independent of WhatsApp and Meta, ships none of their application files, and makes no compatibility promise for any application version. The implementation accepts generic APK/XAPK inputs; users supply their own authorized packages.

Export Java and decode Android APK/XAPK packages with local JADX and Apktool. Optional reconstruction assembles smali and preserves original binary resources, with optional laboratory signing. The Python orchestrator uses the standard library. Export and reconstruction invoke no LLM and do not upload or execute the application. The separate, opt-in runtime runner installs and opens a signed set on an explicitly selected laboratory emulator through local ADB.

## What the code does

deZap supplies orchestration, validation and evidence handling around external decompilation/assembly engines. Its source is organized as follows:

- `decompile.py` and `Exporter.java`: validate/extract inputs, invoke Apktool/JADX, and record export inventories, hashes and diagnostics.
- `rebuild.py` and `Assembler.java`: assemble smali, preserve original non-DEX payloads, compare changes, align and optionally sign/verify the APK set.
- `compare.py`: compare uncompressed APK entry contents.
- `runtime.py`: install and observe a signed set on an explicitly selected laboratory emulator.
- `test_*.py` and `fixtures/`: tests and authored example apps used to validate those operations.

Fixtures are test inputs. Real user-supplied APKs and generated outputs stay in separate private directories selected with `--output`. Java export and smali reconstruction are distinct operations; this tool does not turn exported Java into a complete original source project.

## Requirements

- Python 3.10 or later.
- A JDK compatible with the supplied JADX and Apktool releases (validated with JDK 21).
- A local standalone JADX all-in-one JAR for Java export (validated with 1.5.6).
- A local Apktool JAR (validated with 3.0.3).

Supply tool paths yourself. No dependencies or binaries are bundled or downloaded. Only use inputs you are authorized to analyze.

## Usage

```shell
python decompile.py application.apk --output ../export-01 --jadx-jar /path/to/jadx-all.jar --apktool-jar /path/to/apktool.jar
```

Use `--java` and `--javac` to select a specific JDK; otherwise they are resolved from PATH. XAPK inputs may contain arbitrarily named and nested APK members. Each APK is decoded independently; this does not merge Android split packages. Non-APK XAPK members are not exported. ZIP entries are validated before extraction. Default declared expansion limit is 2 GiB, configurable with `--max-expanded-gib`.

For bytecode reconstruction without Java export, select `--smali-only`. This mode needs only Java and Apktool during export; it does not require JADX or javac and does not invoke the Java exporter. Reconstruction still requires javac to compile the assembler helper. It can avoid Java-export memory failures, but does not recover Java source or fix Java diagnostics from another run.

```shell
python decompile.py application.xapk --output ../smali-export-01 --smali-only --apktool-jar /path/to/apktool.jar
```

The summary records `export_scope: smali-and-resources`, `quality: java-not-exported` and an explicit skipped Java entry for each APK. `export-completed` still requires successful decoding and a preservation inventory for every member. Rebuild accepts either completed scope; failed Java exports remain failed and cannot be reused as completed reconstruction inputs.

`--mode AUTO` is the default; `--mode SIMPLE` selects JADX's simpler mode. `--heap-gib` controls each Java process heap. `--timeout` limits each subprocess in seconds. Every output directory must be new; existing directories are never overwritten.

Default export output contains input APK copies, generated Java, independently generated per-class inventories and hashes, decoded resources/smali, command logs, local command paths, and a run summary. **Treat output as private**: it may contain proprietary code, sensitive content or local paths. This repository is source only; never commit generated outputs.

## Validation and limits

```shell
python -m unittest -v
python build_fixture.py --output ../fixture-build --apktool-jar /path/to/apktool.jar
python decompile.py ../fixture-build/tiny.apk --output ../fixture-export --jadx-jar /path/to/jadx-all.jar --apktool-jar /path/to/apktool.jar
```

The authored fixture sources under `fixtures/tiny` use only basic Android UI calls. Building creates an unsigned APK and an XAPK outside this repository, without keys or credentials. Unit tests cover ZIP traversal, collisions, symlinks, expansion, arbitrary APK extraction, existing outputs, process failures and timeouts.

Add `--multidex --with-resource-split` to `build_fixture.py` to create an authored two-DEX base and a resource split. Fixture sources are original test examples, not extracted third-party applications.

`export-completed` means tool processes completed successfully. `quality` separately reports known Java errors and incomplete-code markers. Review Apktool warnings in local logs: no automatic claim about resource fidelity is made. JavaClass inventory covers JADX top-level export units, not every nested class or every DEX method. Obfuscation, optimization, tool versions and modes can change output. Native code is not decompiled. Successful export does not prove compilability, semantic equivalence, runtime behavior or security. Hashes record local identity, not publisher authenticity. Memory/CPU usage depends strongly on input size. Run untrusted inputs in an isolated environment.

## Comparing two APK hashes

Hash the two local files separately. For example, in Windows PowerShell:

```powershell
Get-FileHash -Algorithm SHA256 -LiteralPath '.\original.apk'
Get-FileHash -Algorithm SHA256 -LiteralPath '.\rebuilt.apk'
```

On Linux use `sha256sum original.apk rebuilt.apk`; on macOS use `shasum -a 256 original.apk rebuilt.apk`. Compare each checksum with its own known expected checksum, if available. Two exact copies should have the same SHA-256. A rebuilt APK normally has a different checksum because DEX, archive layout or signatures can change. In the preservation mode below, original resource payloads remain unchanged.

Equal hashes indicate identical bytes. Different hashes do not by themselves prove malware or different behavior. A checksum alone does not establish publisher authenticity, security or functionality.

## Experimental reconstruction: preserve binary resources

`rebuild.py` consumes a **new completed export** made by this version. It assembles the smali into new DEX, copies every original non-DEX payload, removes old signing metadata, and checks that no unexpected entry content changed. It does **not** compile the exported Java or recompile resource XML. Only edit smali; resource, manifest, asset and decode-configuration edits are rejected rather than silently ignored. Original APK copies must keep the hashes recorded during export.

Additional local dependencies: Android SDK Build-Tools `aapt2` and `zipalign`; for signing, `apksigner.jar` and a user-provided laboratory keystore. Nothing is bundled or downloaded. The assembler currently targets Apktool 3.0.3 APIs and DEX 035/037/038/039. Other DEX versions and nonstandard root DEX filenames are rejected. Opcode selection follows each original DEX header, independently of the manifest's minimum SDK.

```shell
python rebuild.py ../export-01 --output ../rebuild-01 --apktool-jar /path/to/apktool.jar --aapt2 /path/to/aapt2 --zipalign /path/to/zipalign
```

An APK/XAPK set must contain exactly one base, unique split identifiers and the same package/version. Each output records its original member name, package/split metadata and hash; resource splits inherit a missing minimum SDK from the base. Splits stay separate. The command does not merge them or guarantee that all device-required configurations were supplied.

Without signing options, the result is `unsigned-set-completed`: these APKs are **not ready to install**. To sign all APKs with one laboratory key, supply `--keystore`, `--key-alias`, `--apksigner-jar` and `--ks-pass-env` (the **name** of an existing environment variable, never the password as an argument). `--key-pass-env` optionally names a separate key-password variable. Example PowerShell password setup:

```powershell
$env:DEZAP_KS_PASSWORD = [System.Net.NetworkCredential]::new('', (Read-Host 'Laboratory keystore password' -AsSecureString)).Password
python rebuild.py ..\export-01 --output ..\rebuild-signed --apktool-jar C:\tools\apktool.jar --aapt2 C:\tools\aapt2.exe --zipalign C:\tools\zipalign.exe --apksigner-jar C:\tools\apksigner.jar --keystore C:\private\laboratory.p12 --key-alias laboratory --ks-pass-env DEZAP_KS_PASSWORD
Remove-Item Env:DEZAP_KS_PASSWORD
```

Use a test-only key, not a production key; never commit keystores or outputs. Password environment variables exist in process memory and may be inherited by children; this is not a secret-management service. Keep keystores and outputs outside this repository. Signed completion requires successful signature/alignment checks, one common certificate, preserved package metadata, unchanged input hashes and DEX-only payload differences for every APK. Partial failure leaves `incomplete` and a nonzero exit, with logs for diagnosis. File and archive layout changes are expected; preservation compares uncompressed entry bytes.

Reports identify assembly/signing results separately. They do not claim Android verifier acceptance, installation, opening or functionality. The optional runner below records controlled observations separately; they are not a security assessment.

## Optional laboratory runtime observation

Prepare a dedicated emulator and a clean snapshot with no accounts and no installed target package. Start the emulator and its local ADB server separately. The runner does not create AVDs, download SDKs, start or stop emulators, or select a device automatically. Physical-device serials are refused. Snapshot restoration changes the selected emulator's state; use only a disposable laboratory AVD.

```shell
python runtime.py ../rebuild-signed/rebuild-summary.json --output ../runtime-01 --adb /path/to/adb --server-port 5047 --serial emulator-5580 --avd laboratory --snapshot clean_offline --package example.tiny --activity example.tiny/.MainActivity --expected-text "Offline fixture"
```

The runner verifies the explicit AVD identity, restores the named snapshot, waits for boot, requires no accounts, disables Wi-Fi/data and checks supported offline connectivity state. These checkpoints are not a firewall or proof of zero traffic during boot or the observation interval. It verifies APK hashes against the signed reconstruction report, installs the whole set, and observes initial opening, Home/resume and force-stop/relaunch. Each observation requires the expected foreground activity, app process, package-owned UI text, XML/screenshot capture and absence of package-scoped crash/ANR evidence in the searched logs. Installation or `am start` success alone never passes a scenario.

Connectivity parsing currently recognizes the Android API30 `dumpsys connectivity` format; unknown formats fail rather than implying isolation. Boot queries tolerate temporary disconnects after snapshot restoration within `--boot-timeout`, then recheck AVD identity. HOME must leave the app's foreground and preserve its process; force-stop must make the process absent before relaunch.

`--activity` selects the launch entry point. If the application redirects, explicitly supply `--expected-activity` for the foreground destination; it must belong to the same package. Without this option, the launch activity is also the expected activity. An unexpected redirect remains a failure even when some expected text appears.

Signature verification is inherited from the reconstruction report and bound to artifact hashes; the runner does not independently reverify signatures. Treat the summary and artifacts as trusted local laboratory outputs, not a publisher-authentication service. All evidence goes into a new directory outside this repository. Logs, screenshots and UI XMLs may contain private content; never commit them. The runner force-stops the tested package after a successful installation, leaves the APK installed in the disposable AVD, and leaves externally managed emulator/ADB processes running.

For a specifically authorized informational dialog, optionally supply all three selectors: `--dismiss-dialog-text`, `--dismiss-button-id` and `--dismiss-button-text`. The runner taps only a unique observed, enabled, clickable matching button, preserving captures before and after. Do not use this option to accept terms, register accounts or authorize unrelated actions. No other application buttons are clicked automatically.

`runtime-observed-pass` means only the specified UI and lifecycle checks passed on the recorded Android/ABI configuration. Failed stages/scenarios return nonzero and retain their evidence. This is not an audit of security, semantic equivalence, complete functionality, telemetry, server acceptance or native-code compatibility.

Authored modern examples can be built with `build_fixture.py --modern-dex 038` or `--modern-dex 039`, plus the normal tool/output arguments. DEX038 executes `invoke-polymorphic`; DEX039 also executes `const-method-type` and displays its result. They require Android API26/28 respectively for execution, although their intentionally low manifest minimum remains23 to exercise DEX-header-based assembly selection. `--with-resource-split --split-without-sdk` builds a real resource split without explicit SDK metadata. The fixture builder stores `resources.arsc` uncompressed for API30 installation; alignment and signing still belong to the reconstruction flow.

## Compare APK payloads

```shell
python compare.py original.apk rebuilt.apk --report ../comparison.json
```

The report lists identical/changed/added/removed entry contents and ignores known signing metadata. It refuses to overwrite an existing report. The reconstruction command additionally rejects any difference outside its allowed DEX substitutions. Neither equality nor successful reconstruction proves semantic equivalence or security. This mode cannot remove or modify manifest/resource features while simultaneously promising their preservation.

## Licenses

Own scripts, exporter and fixture sources are MIT licensed; see LICENSE. External tools remain under their respective licenses and are not redistributed here:

- [JADX](https://github.com/skylot/jadx): [Apache License 2.0](https://github.com/skylot/jadx/blob/master/LICENSE).
- [Apktool](https://github.com/iBotPeaches/Apktool): [Apache License 2.0](https://github.com/iBotPeaches/Apktool/blob/main/LICENSE.md).
- A JDK distribution has its own terms; [OpenJDK licensing](https://openjdk.org/legal/gplv2+ce.html) describes GPLv2 with the Classpath Exception.

This project is independent and is not affiliated with these tool maintainers. Analyzing an input does not grant permission to redistribute its content.
