# Hardclone

**Hardclone** is a modular toolkit for creating and restoring disk and partition images.  
It consists of three main components:

- **Graphical User Interface (GUI)** — a user-friendly frontend built with Python.
- **Command-Line Interface (CLI)** — a powerful Bash-based tool for advanced users and SSH environments.
- **Live Linux Environment** — a bootable Linux system with both GUI and CLI preinstalled.

---

## 🔧 Components

| Name           | Description                                            | Repository |
|----------------|--------------------------------------------------------|------------|
| **GUI**        | Graphical application written in Python                | [hardclone-gui](https://github.com/dawciobiel/hardclone-gui) |
| **CLI**        | Console interface implemented in Bash                  | [hardclone-cli](https://github.com/dawciobiel/hardclone-cli) |
| **Live Linux** | Bootable Linux ISO with preinstalled Hardclone CLI     | [live-local-clonezilla](https://github.com/dawciobiel/live-local-clonezilla) |
| **Live Linux** | Bootable Linux ISO with preinstalled Hardclone         | ~~[hardclone-live](https://github.com/dawciobiel/hardclone-live)~~ |

---

## 📦 Cloning the full project (with submodules)

To clone the main repository along with all components:

```bash
git clone --recurse-submodules https://github.com/dawciobiel/hardclone.git
````

If you've already cloned the repo without `--recurse-submodules`, run:

```bash
git submodule update --init --recursive
```

---

## 💡 About this repository

This repository serves as the **meta-project** for the Hardclone suite.
It contains the three submodules and provides a unified entry point for users and contributors.

Development for each component is handled in its respective repository.

---

## 📁 Project structure

```text
hardclone/
├── cli/                        → Bash CLI tool (submodule)
├── gui/                        → Python GUI application (submodule)
├── live-local-clonezilla/      → Bootable Linux ISO with preinstalled Hardclone CLI version
└── README.md → This file
```

---

## 📜 License

This project is licensed under the **GNU General Public License v3.0**.

Each submodule may carry its license — please refer to the respective repositories.

See the [`LICENSE`](LICENSE) file for full terms.

---

## 👤 Author

Created by **Dawid Bielecki**
Feel free to contribute or open issues in any of the component repositories.
