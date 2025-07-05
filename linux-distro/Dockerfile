# Dockerfile dla budowania archiso
FROM archlinux:latest

# Aktualizacja i instalacja niezbędnych pakietów
RUN pacman -Syu --noconfirm && \
    pacman -S --noconfirm archiso git base-devel && \
    pacman -Scc --noconfirm

# Utwórz katalog roboczy
WORKDIR /build

# Skopiuj profil archiso
RUN cp -r /usr/share/archiso/configs/releng ./my-imaging-distro

# Ustaw katalog roboczy na nasz profil
WORKDIR /build/my-imaging-distro

# Domyślna komenda
CMD ["bash"]
