from dataclasses import dataclass
from typing import List


@dataclass
class Partition:
    device: str
    mountpoint: str
    fstype: str
    size: int
    used: int
    free: int
    label: str = ""

    @property
    def size_gb(self):
        return self.size / (1024 ** 3)

    @property
    def used_gb(self):
        return self.used / (1024 ** 3)

    @property
    def usage_percent(self):
        return (self.used / self.size * 100) if self.size > 0 else 0

    @property
    def pretty_size(self):
        gb = self.size / (1024 ** 3)
        if gb >= 1:
            return f"{gb:.1f} GB"
        else:
            mb = self.size / (1024 ** 2)
            return f"{mb:.0f} MB"


@dataclass
class DriveInfo:
    device: str
    model: str
    size: int
    partitions: List[Partition]

    @property
    def size_gb(self):
        return self.size / (1024 ** 3)
