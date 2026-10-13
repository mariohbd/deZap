# deZap — a WhatsApp offline-decompiler

**Apenas para fins acadêmicos e de pesquisa / For academic and research purposes only.** Analyze only authorized local inputs. This purpose statement does not authorize third-party decompilation, redistribution or circumvention, and does not override laws, contracts or licenses. No legal guarantee is provided.

The title identifies a research use case, not affiliation or endorsement. deZap is independent of WhatsApp and Meta, ships none of their application files, and makes no compatibility promise for any application version. The implementation accepts generic APK/XAPK inputs; users supply their own authorized packages.

Export Java and decode Android APK/XAPK packages with local JADX and Apktool. The Python orchestrator uses the standard library. It makes no network requests, invokes no LLM, and does not install, execute, sign or upload the input application.

## Requirements

- Python 3.10 or later.
- A JDK compatible with the supplied JADX and Apktool releases (validated with JDK 21).
- A local standalone JADX all-in-one JAR (validated with 1.5.6).
- A local Apktool JAR (validated with 3.0.3).

Supply tool paths yourself. No dependencies or binaries are bundled or downloaded. Only use inputs you are authorized to analyze.

## Usage

```shell
python decompile.py application.apk --output ../export-01 --jadx-jar /path/to/jadx-all.jar --apktool-jar /path/to/apktool.jar
```

Use `--java` and `--javac` to select a specific JDK; otherwise they are resolved from PATH. XAPK inputs may contain arbitrarily named and nested APK members. Each APK is decoded independently; this does not merge Android split packages. Non-APK XAPK members are not exported. ZIP entries are validated before extraction. Default declared expansion limit is 2 GiB, configurable with `--max-expanded-gib`.

`--mode AUTO` is the default; `--mode SIMPLE` selects JADX's simpler mode. `--heap-gib` controls each Java process heap. `--timeout` limits each subprocess in seconds. Every output directory must be new; existing directories are never overwritten.

Output contains input APK copies, generated Java, independently generated per-class inventories and hashes, decoded resources/smali, command logs, local command paths, and a run summary. **Treat output as private**: it may contain proprietary code, sensitive content or local paths. This repository is source only; never commit generated outputs.

## Validation and limits

```shell
python -m unittest -v
python build_fixture.py --output ../fixture-build --apktool-jar /path/to/apktool.jar
python decompile.py ../fixture-build/tiny.apk --output ../fixture-export --jadx-jar /path/to/jadx-all.jar --apktool-jar /path/to/apktool.jar
```

The authored fixture sources under `fixtures/tiny` use only basic Android UI calls. Building creates an unsigned APK and an XAPK outside this repository, without keys or credentials. Unit tests cover ZIP traversal, collisions, symlinks, expansion, arbitrary APK extraction, existing outputs, process failures and timeouts.

`export-completed` means tool processes completed successfully. `quality` separately reports known Java errors and incomplete-code markers. Review Apktool warnings in local logs: no automatic claim about resource fidelity is made. JavaClass inventory covers JADX top-level export units, not every nested class or every DEX method. Obfuscation, optimization, tool versions and modes can change output. Native code is not decompiled. Successful export does not prove compilability, semantic equivalence, runtime behavior or security. Hashes record local identity, not publisher authenticity. Memory/CPU usage depends strongly on input size. Run untrusted inputs in an isolated environment.

## Comparing two APK hashes

Hash the two local files separately. For example, in Windows PowerShell:

```powershell
Get-FileHash -Algorithm SHA256 -LiteralPath '.\original.apk'
Get-FileHash -Algorithm SHA256 -LiteralPath '.\rebuilt.apk'
```

On Linux use `sha256sum original.apk rebuilt.apk`; on macOS use `shasum -a 256 original.apk rebuilt.apk`. Compare each checksum with its own known expected checksum, if available. Two exact copies should have the same SHA-256. An optional rebuilt APK created separately normally has a different checksum because DEX, resources, archive layout or signatures can change. This toolkit exports code and resources; it does not rebuild that second APK.

Equal hashes indicate identical bytes. Different hashes do not by themselves prove malware or different behavior. A checksum alone does not establish publisher authenticity, security or functionality.

## Licenses

Own scripts, exporter and fixture sources are MIT licensed; see LICENSE. External tools remain under their respective licenses and are not redistributed here:

- [JADX](https://github.com/skylot/jadx): [Apache License 2.0](https://github.com/skylot/jadx/blob/master/LICENSE).
- [Apktool](https://github.com/iBotPeaches/Apktool): [Apache License 2.0](https://github.com/iBotPeaches/Apktool/blob/main/LICENSE.md).
- A JDK distribution has its own terms; [OpenJDK licensing](https://openjdk.org/legal/gplv2+ce.html) describes GPLv2 with the Classpath Exception.

This project is independent and is not affiliated with these tool maintainers. Analyzing an input does not grant permission to redistribute its content.
