# CPU Vulnerabilities

**Expose. Explore. Explain.**

CPU Vulnerabilities is a read-only Linux inspector for the CPU vulnerability and mitigation status text reported directly by the running kernel through `/sys/devices/system/cpu/vulnerabilities`.

Current release: **0.0.5**

Repository: <https://github.com/linspectacles/cpu-vulnerabilities>

<p align="center">
  <a href="https://github.com/brunonlinespace/brunonlinespace/blob/main/linspectacles/cpu-vulnerabilities.png">
    <img
      src="https://raw.githubusercontent.com/brunonlinespace/brunonlinespace/main/linspectacles/cpu-vulnerabilities.png"
      alt="CPU Vulnerabilities screenshot"
      width="900"
    >
  </a>
</p>

## What CPU Vulnerabilities is

CPU Vulnerabilities answers a focused question: **what CPU vulnerability or mitigation state is the running Linux kernel currently reporting?**

The applet deliberately keeps this information separate from general hardware topology. Each file exposed by the kernel vulnerability interface becomes one inventory record, and the kernel's status text remains the authoritative result.

It keeps acquisition and interpretation close to the Linux interface actually used by the applet. When the interface is unavailable, restricted, or cannot be read, that condition is reported rather than replaced with an inferred answer.

## Highlights

- One inventory entry for each file exposed under `/sys/devices/system/cpu/vulnerabilities`.
- Preserves the kernel-reported status text for every readable entry.
- Compact local classification for filtering: **Vulnerable**, **Mitigated**, **Not affected**, **Unknown** or **Reported**.
- Explicit **Access denied** and **Read error** states when an individual entry cannot be read.
- Search across vulnerability name, classification, kernel status and source path.
- Metadata Details shows the raw kernel status, source path, read state and mitigation text where the kernel reports `Mitigation: ...`.
- Export of visible, already-collected records with selectable fields and optional Metadata Details.
- Persistent Metadata Details visibility and horizontal/vertical layout.

## Data sources and acquisition

- `/sys/devices/system/cpu/vulnerabilities/*`.

Each regular file in that directory is read as one vulnerability record. No external vulnerability database, userspace scanner or network service is consulted.

The classification is only a presentation aid derived from the beginning of the kernel's own text:

- `Not affected...` → **Not affected**
- `Mitigation:...` → **Mitigated**
- `Vulnerable...` → **Vulnerable**
- `Unknown...` → **Unknown**
- any other readable text → **Reported**

The applet uses those sources according to the acquisition paths implemented in this release. It does not silently substitute another source when the kernel interface is unavailable.

## Interface

CPU Vulnerabilities follows the LinSpectacles inventory + **Metadata Details** pattern: the main inventory shows **Entry**, **Classification** and **Kernel Status**, while the details pane preserves the selected record's raw reported state and provenance.

The **Classification** selector filters the already-acquired inventory. Search and filtering do not trigger additional vulnerability probing.

The applet's **Options...** dialog provides:

- Appearance controls for Metadata Details visibility and layout.
- Sources documentation.
- Export field selection and export of visible records.
- About and repository information.

Keyboard shortcuts implemented by this release include:

- `F3` — show/hide Metadata Details.
- `Ctrl+L` — toggle Horizontal/Vertical details layout.
- `Shift+F5` — refresh CPU vulnerability state.
- `Ctrl+/` — open Options.

## Read-only and scope boundaries

CPU Vulnerabilities reports **kernel-provided vulnerability and mitigation state**. It does not independently test the processor for vulnerabilities, consult an external advisory database, determine whether firmware or microcode is current, or derive an overall **secure / unsafe** verdict.

A **Mitigated** classification means the kernel status text begins with `Mitigation:`; it is not an independent LinSpectacles security certification.

Unreadable entries remain explicitly marked **Access denied** or **Read error**. The applet performs no privilege escalation.

## Running from source

The supplied source is directly runnable on Linux. The Python-side requirements are:

- Python 3.
- PyQt6 for the graphical interface.

Create a local virtual environment if you do not already have the required Python packages in the environment you want to use:

```bash
python3 -m venv .venv
source .venv/bin/activate
python -m pip install PyQt6
python3 linspectacles_cpu_vulnerabilities/standalone.py
```

The kernel vulnerability sysfs interface described under **Data sources and acquisition** is the applet's runtime data source. If the running kernel does not expose it, the applet reports that vulnerability state is unavailable.

No RPM installation instructions are included in this README.

## LinSpectacles Hub

This applet can run independently, but it can also be installed and used inside **[LinSpectacles Hub](https://github.com/linspectacles/linspectacles-hub)**.

LinSpectacles Hub is the optional workbench for the LinSpectacles applet family. It provides shared applet discovery, navigation and management while each inspector remains independently runnable.

To install a portable or user applet through the Hub, open **Configuration... → Applets** and add the applet ZIP. Once discovered, the applet can be enabled and opened from the Hub navigation.

System-installed applets are discovered by the Hub from its system applet store and remain managed by the system package manager.

## Source layout and LinSpectacles integration

The applet source is contained in:

```text
linspectacles_cpu_vulnerabilities/
├── __init__.py
├── standalone.py
├── LICENSE
├── applet.json
├── README.md
└── cpu_vulnerabilities/
    ├── __init__.py
    ├── applet.py
    ├── _support.py
    └── icon.png
```

`applet.json` defines the applet's LinSpectacles identity and integration metadata. `standalone.py` provides direct standalone launching, while the applet entrypoint allows the same inspector to run inside LinSpectacles Hub.

## Configuration

CPU Vulnerabilities persists only its implemented presentation preferences, including Metadata Details visibility and horizontal/vertical layout. Those settings do not alter kernel vulnerability or mitigation state.

## Scope

CPU Vulnerabilities owns the kernel-reported CPU vulnerability interface that was previously part of Hardware Topology.

Hardware structure and locality remain the responsibility of **[Hardware Topology](https://github.com/linspectacles/hardware-topology)**.

## License

GNU General Public License v3.0 or later. See [`LICENSE`](LICENSE).

## Links

- LinSpectacles organisation: <https://github.com/linspectacles/>
- LinSpectacles Hub: <https://github.com/linspectacles/linspectacles-hub>
- Repository: <https://github.com/linspectacles/cpu-vulnerabilities>
- Issues: <https://github.com/linspectacles/cpu-vulnerabilities/issues>

<p align="center">
  <a href="https://github.com/linspectacles/cpu-vulnerabilities">
    <img
      src="cpu_vulnerabilities/icon.png"
      alt="CPU Vulnerabilities"
      width="256"
    >
  </a>
</p>
