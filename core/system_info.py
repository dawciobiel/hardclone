import json
import subprocess
from typing import List, Dict, Any, Optional

import psutil

from core.models import Partition, DriveInfo


class SystemInfoCollector:
    """Class for collecting system information"""

    @staticmethod
    def get_block_devices() -> List[DriveInfo]:
        """Gets information about block devices"""
        drives = []

        try:
            # Try without sudo first
            cmd = ["lsblk", "-J", "-o", "NAME,SIZE,MODEL,FSTYPE,MOUNTPOINT,LABEL"]
            result = subprocess.run(cmd, capture_output=True, text=True)

            if result.returncode == 0:
                data = json.loads(result.stdout)

                for device in data.get("blockdevices", []):
                    if device.get("name", "").startswith(("sd", "nvme", "mmcblk")):
                        drives.append(SystemInfoCollector._parse_device(device))

        except Exception as e:
            print(f"Error getting drive information: {e}")

        return drives

    @staticmethod
    def get_device_size_with_sudo(device_path: str, sudo_password: str = None) -> int:
        """Gets device size using blockdev command, with sudo if needed"""
        try:
            # Try without sudo first
            cmd = ["blockdev", "--getsize64", device_path]
            result = subprocess.run(cmd, capture_output=True, text=True)

            if result.returncode == 0:
                return int(result.stdout.strip())

            # If failed, try with sudo
            if sudo_password:
                cmd = f"echo '{sudo_password}' | sudo -S blockdev --getsize64 {device_path}"
                result = subprocess.run(cmd, shell=True, capture_output=True, text=True)
                if result.returncode == 0:
                    return int(result.stdout.strip())

            raise Exception("Failed to get device size")

        except Exception as e:
            print(f"Error getting device size: {e}")
            return 0

    @staticmethod
    def _parse_device(device: Dict[str, Any]) -> DriveInfo:
        """Parse device information"""
        device_name = f"/dev/{device['name']}"
        model = device.get("model", "Unknown")
        size_str = device.get("size", "0B")

        # Size conversion
        size_bytes = SystemInfoCollector._parse_size(size_str)

        # Parse partitions
        partitions = []
        for child in device.get("children", []):
            partition = SystemInfoCollector._parse_partition(child)
            if partition:
                partitions.append(partition)

        return DriveInfo(device=device_name, model=model, size=size_bytes, partitions=partitions)

    @staticmethod
    def _parse_partition(partition_data: Dict[str, Any]) -> Optional[Partition]:
        """Parse partition information"""
        try:
            device = f"/dev/{partition_data['name']}"
            mountpoint = partition_data.get("mountpoint", "")
            fstype = partition_data.get("fstype", "")
            label = partition_data.get("label", "")

            # Get usage information
            size_str = partition_data.get("size", "0B")
            size = SystemInfoCollector._parse_size(size_str)

            used = free = 0
            if mountpoint:
                try:
                    usage = psutil.disk_usage(mountpoint)
                    used = usage.used
                    free = usage.free
                except:
                    pass

            return Partition(device=device, mountpoint=mountpoint, fstype=fstype, size=size, used=used, free=free, label=label)
        except Exception as e:
            print(f"Error parsing partition: {e}")
            return None

    @staticmethod
    def _parse_size(size_str: str) -> int:
        """Convert size string to bytes"""
        if not size_str:
            return 0

        size_str = size_str.strip().upper()
        size_str = size_str.replace(',', '.')  # Zamień przecinek na kropkę

        multipliers = {'B': 1, 'K': 1024, 'M': 1024 ** 2, 'G': 1024 ** 3, 'T': 1024 ** 4, 'P': 1024 ** 5}

        for suffix, multiplier in multipliers.items():
            if size_str.endswith(suffix):
                number_part = size_str[:-len(suffix)].strip()
                try:
                    number = float(number_part)
                    return int(number * multiplier)
                except:
                    return 0

        try:
            return int(float(size_str))
        except:
            return 0
