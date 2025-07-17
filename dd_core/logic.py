# dd_core/logic.py

import subprocess

def clone_disk(source, target, block_size="4M", dry_run=False, show_progress=True, verify=False):
    """
    Clone a disk using the `dd` command.

    Args:
        source (str): Source device path (e.g. /dev/sdX)
        target (str): Target device path (e.g. /dev/sdY)
        block_size (str): Block size for dd (default: 4M)
        dry_run (bool): If True, don't run dd – just print it
        show_progress (bool): If True, adds 'status=progress'
        verify (bool): Placeholder for future verification step
    """
    dd_command = [
        "dd",
        f"if={source}",
        f"of={target}",
        f"bs={block_size}"
    ]

    if show_progress:
        dd_command.append("status=progress")

    if dry_run:
        print("Dry run: would execute command:")
        print(" ".join(dd_command))
        return

    print(f"Running: {' '.join(dd_command)}")

    try:
        process = subprocess.Popen(
            dd_command,
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            universal_newlines=True
        )

        for line in process.stdout:
            print(line.strip())

        process.wait()

        if process.returncode == 0:
            print("✅ Cloning completed successfully.")
        else:
            print(f"❌ Cloning failed with exit code {process.returncode}")

    except Exception as e:
        print(f"❌ Error while running dd: {e}")

    if verify:
        print("🔍 Verification not implemented yet.")
