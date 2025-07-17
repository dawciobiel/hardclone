import re
import subprocess
import time

from PySide6.QtCore import QThread, Signal


class DDWorkerThread(QThread):
    """Worker thread for DD operations"""

    progress_updated = Signal(int, str)  # progress percentage, status text
    operation_finished = Signal(bool, str)  # success, message
    log_message = Signal(str)

    def __init__(self, source_device, target_file, options, sudo_password=None, encryption_password=None):
        super().__init__()
        self.source_device = source_device
        self.target_file = target_file
        self.options = options
        self.sudo_password = sudo_password
        self.encryption_password = encryption_password  # Dodaj hasło szyfrowania
        self.should_cancel = False
        self.process = None
        self.source_size = 0

    def run(self):
        """Main worker thread function"""
        try:
            # Get device size first
            self.source_size = self.get_device_size()
            if self.source_size == 0:
                self.operation_finished.emit(False, "Could not determine source device size")
                return

            self.log_message.emit(f"Source device size: {self.source_size / (1024 ** 3):.2f} GB")

            # Build and execute command
            self.execute_dd_command()

        except Exception as e:
            self.operation_finished.emit(False, f"Error: {str(e)}")

    def get_device_size(self):
        """Get device size without sudo using lsblk"""
        try:
            cmd = ["lsblk", "-b", "-dn", "-o", "SIZE", self.source_device]
            result = subprocess.run(cmd, capture_output=True, text=True)

            if result.returncode == 0:
                size_str = result.stdout.strip()
                size = int(size_str)
                if size > 0:
                    return size
                else:
                    self.log_message.emit("Error: Got zero size from lsblk command")
            else:
                self.log_message.emit(f"Error: lsblk command failed with return code {result.returncode}")
                if result.stderr:
                    self.log_message.emit(f"Error details: {result.stderr}")

        except Exception as e:
            self.log_message.emit(f"Error getting device size: {str(e)}")

        return 0

    def execute_dd_command(self):
        """Execute the DD command with optional compression and encryption"""
        try:
            # Sprawdź czy openssl jest dostępny dla szyfrowania
            if self.options.get('encrypt', False):
                try:
                    subprocess.run(['openssl', 'version'], capture_output=True, check=True)
                except (subprocess.CalledProcessError, FileNotFoundError):
                    self.operation_finished.emit(False, "OpenSSL not found. Please install OpenSSL for encryption support.")
                    return

            # Buduj komendę w zależności od opcji
            cmd_parts = []

            # Część DD
            if self.sudo_password:
                dd_cmd = f"echo '{self.sudo_password}' | sudo -S dd if={self.source_device} bs=1M status=progress"
            else:
                dd_cmd = f"dd if={self.source_device} bs=1M status=progress"

            cmd_parts.append(dd_cmd)

            # Opcjonalne szyfrowanie
            if self.options.get('encrypt', False) and self.encryption_password:
                # Używamy AES-256-CBC z PBKDF2
                encrypt_cmd = f"openssl enc -aes-256-cbc -pbkdf2 -iter 100000 -pass pass:'{self.encryption_password}'"
                cmd_parts.append(encrypt_cmd)

            # Opcjonalna kompresja
            if self.options.get('compress', False):
                cmd_parts.append("gzip -c")

            # Określ rozszerzenie pliku wyjściowego
            output_file = self.target_file
            if self.options.get('encrypt', False):
                output_file += ".enc"
            if self.options.get('compress', False):
                output_file += ".gz"

            # Przekierowanie do pliku
            cmd_parts.append(f"> {output_file}")

            # Połącz wszystkie części
            full_cmd = " 2>&1 | ".join(cmd_parts[:-1]) + f" {cmd_parts[-1]}"

            # Ukryj hasła w logach
            log_cmd = full_cmd
            if self.sudo_password:
                log_cmd = log_cmd.replace(self.sudo_password, "***")
            if self.encryption_password:
                log_cmd = log_cmd.replace(self.encryption_password, "***")

            self.log_message.emit(f"Executing: {log_cmd}")

            # Uruchom proces
            self.process = subprocess.Popen(full_cmd, shell=True, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True, bufsize=1,
                                            universal_newlines=True)

            # Monitoruj postęp
            self.monitor_progress()

        except Exception as e:
            self.operation_finished.emit(False, f"Error executing command: {str(e)}")

    def monitor_progress(self):
        """Monitor DD progress"""
        try:
            while self.process and self.process.poll() is None:
                if self.should_cancel:
                    if self.process:
                        self.process.terminate()
                        time.sleep(1)
                        if self.process.poll() is None:
                            self.process.kill()
                    self.operation_finished.emit(False, "Operation cancelled by user")
                    return

                # Try to read output
                if self.process.stdout:
                    line = self.process.stdout.readline()
                    if line:
                        self.parse_dd_output(line.strip())

                time.sleep(0.1)

            # Process finished
            if self.process:
                returncode = self.process.returncode
                if returncode == 0:
                    self.progress_updated.emit(100, "Operation completed successfully!")

                    # Dodaj informacje o szyfrowania i kompresji w komunikacie
                    features = []
                    if self.options.get('encrypt', False):
                        features.append("encrypted")
                    if self.options.get('compress', False):
                        features.append("compressed")

                    if features:
                        message = f"Image created successfully! ({', '.join(features)})"
                    else:
                        message = "Image created successfully!"

                    self.operation_finished.emit(True, message)
                else:
                    self.operation_finished.emit(False, f"Operation failed with return code: {returncode}")

        except Exception as e:
            self.operation_finished.emit(False, f"Error monitoring progress: {str(e)}")

    def parse_dd_output(self, line):
        """Parse DD output for progress information"""
        try:
            # Look for progress lines like: "1234567890 bytes (1.2 GB) copied, 10 s, 123 MB/s"
            if "bytes" in line and "copied" in line:
                # Extract bytes copied
                match = re.search(r'(\d+) bytes', line)
                if match:
                    bytes_copied = int(match.group(1))
                    if self.source_size > 0:
                        progress = min(100, int((bytes_copied / self.source_size) * 100))

                        # Extract speed if available
                        speed_match = re.search(r'(\d+(?:\.\d+)?)\s*([KMG]?B/s)', line)
                        if speed_match:
                            speed = speed_match.group(1)
                            unit = speed_match.group(2)
                            status = f"Progress: {progress}% - Speed: {speed} {unit}"
                        else:
                            status = f"Progress: {progress}%"

                        self.progress_updated.emit(progress, status)

        except Exception as e:
            self.log_message.emit(f"Error parsing output: {str(e)}")

    def cancel(self):
        """Cancel the operation"""
        self.should_cancel = True
