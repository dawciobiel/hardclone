#!/usr/bin/env bash


# Sprawdź wolne miejsce w katalogu bieżącym (lub podaj ścieżkę w $DIR)
DIR="$PWD"
REQUIRED_GB=25

# Pobierz ilość wolnego miejsca (w GB, jako liczba całkowita)
AVAILABLE_GB=$(df -BG --output=avail "$DIR" | tail -1 | tr -dc '0-9')

echo "Masz dostępne: ${AVAILABLE_GB} GB wolnego miejsca w: $DIR"
echo "Wymagane: ${REQUIRED_GB} GB"

if [ "$AVAILABLE_GB" -lt "$REQUIRED_GB" ]; then
    echo -e "\033[0;31m✘ Zbyt mało miejsca! Wymagane co najmniej ${REQUIRED_GB} GB.\033[0m"
    exit 1
else
    echo -e "\033[0;32m✔ Wystarczająco miejsca, kontynuuję...\033[0m"
fi




# Parameters:
# --project-name hardclone-arch - nazwa projektu
# --version 1.x - wersja
# --list-packages - lista pakietów
# --add-package KATEGORIA PAKIET - dodaj pakiet
# --remove-package PAKIET - usuń pakiet
# --save-config plik.json - zapisz konfigurację
# --load-config plik.json - wczytaj konfigurację
# --build - zbuduj ISO (domyślnie)
#
# Cache:
# --cache-info - pokazuje informacje o cache (rozmiar, ilość paczek)
# --clean-cache - czyści cache paczek
# --clean-work - czyści katalog roboczy
# show_cache_info() - automatycznie pokazuje info o cache przed i po buildzie



# Użyj dysku z większą ilością wolnego miejsca (uważaj na spację w nazwie)
# sudo mkarchiso -v -w "/run/media/dawciobiel/home manjaro/dawciobiel/archiso_work" -o "/run/media/dawciobiel/home manjaro/dawciobiel/output" ./releng/

# Przekieruj katalog tymczasowy na dysk z miejscem
#export TMPDIR="/run/media/dawciobiel/home manjaro/dawciobiel/tmp"
#mkdir -p "$TMPDIR"
# sudo -E mkarchiso -v -o "/run/media/dawciobiel/home manjaro/dawciobiel/output" ./releng/


# Standard usage (version 1.0)
# python3 build_archiso.py

# Specific version
# python3 build_archiso.py --version 1.2

# Zapisanie konfiguracji
# python3 build_archiso.py --project-name hardclone-arch --version 1.4 --save-config config.json

# Wczytanie i budowanie
# python3 build_archiso.py --load-config config.json --build

# Custom version and custom name
python3 build_archiso.py --project-name hardclone-arch --version 1.5
