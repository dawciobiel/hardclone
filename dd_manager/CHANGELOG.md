## [0.1.2] - 2025-07-17

### Added
- Introduced CLI interface (GLI - Graphical-less Interface) for headless usage.
- Added symbolic link `current` to always point to the latest stable version.
- Enhanced internal structure: separated `cli/`, `gui/`, and `core/` modules.

### Changed
- Improved modularity and maintainability by reorganizing project layout.
- Renamed previous GUI-only modules to reflect new architecture.

### Fixed
- Minor bugfixes in disk detection logic under some Linux distros.
