# (C) 2026 Noverse. All Rights Reserved.
# This script is used for WinConfig
# https://github.com/nohuto
# https://discord.noverse.dev

from __future__ import annotations

import argparse
import hashlib
import os
import re
import shutil
import subprocess
import sys
import threading
import urllib.request
import zipfile
from dataclasses import dataclass
from pathlib import Path
from typing import Iterable, Sequence

RW_URL = "https://rweverything.com/downloads/RwPortableX64V1.7.zip"
RW_ARCHIVE_MEMBER = "Win64/Portable/Rw.exe"
RW_SHA256 = "5e009cdfc283d7f0d3dd777d40bcd23ecd78d8d7e93fc9cedcfb6d9dbe0b7701"
RW_RESULT = re.compile(r"=\s*(0x[0-9A-Fa-f]+)\s*$", re.MULTILINE)
XHCI_CLASS_CODE = 0x0C0330
TASK_NAME = "Noverse-IMOD"

class RwError(RuntimeError):
    pass

def get_default_rw_path() -> Path:
    base = Path(os.environ.get("LOCALAPPDATA", str(Path.home())))
    return base / "Noverse" / "IMOD" / "RwPortable" / "Win64" / "Portable" / "Rw.exe"

def prepare_rw_binary(rw_path: Path) -> None:
    if rw_path.is_file():
        return

    rw_path.parent.mkdir(parents=True, exist_ok=True)
    archive_path = rw_path.parent / "RwPortableX64V1.7.zip"
    staged_path = rw_path.with_suffix(".tmp")
    print("[~] rw.exe not found, downloading portable package")
    try:
        urllib.request.urlretrieve(RW_URL, archive_path)
        with zipfile.ZipFile(archive_path) as archive:
            with archive.open(RW_ARCHIVE_MEMBER) as source, staged_path.open("wb") as target:
                shutil.copyfileobj(source, target)
        if hashlib.sha256(staged_path.read_bytes()).hexdigest() != RW_SHA256:
            raise RwError("Failed SHA-256 verification")
        staged_path.replace(rw_path)
    except Exception:
        staged_path.unlink(missing_ok=True)
        raise
    finally:
        archive_path.unlink(missing_ok=True)

    print(f"[+] Downloaded at {rw_path}")

def startup_target(name: str) -> Path:
    base = Path(os.environ.get("LOCALAPPDATA", str(Path.home()))) / "Noverse" / "IMOD"
    base.mkdir(parents=True, exist_ok=True)
    return base / name

def install_startup_task(raw_args: Sequence[str]) -> None:
    filtered = [arg for arg in raw_args if arg not in {"--startup", "--no-exit"}]
    if getattr(sys, "frozen", False):
        source = Path(sys.executable).resolve()
        target = startup_target(source.name)
        if source != target.resolve():
            shutil.copy2(source, target)
        command = [str(target), *filtered]
    else:
        source = Path(__file__).resolve()
        target = startup_target(source.name)
        if source != target.resolve():
            shutil.copy2(source, target)
        command = [str(Path(sys.executable).resolve()), str(target), *filtered]

    result = subprocess.run(
        [
            "schtasks",
            "/Create",
            "/SC",
            "ONLOGON",
            "/RL",
            "HIGHEST",
            "/TN",
            TASK_NAME,
            "/TR",
            subprocess.list2cmdline(command),
            "/F",
        ],
        capture_output=True,
        text=True,
    )
    if result.returncode:
        raise RwError(f"Failed to create scheduled task - {result.returncode}")
    print(f"[+] Scheduled task '{TASK_NAME}' created")

def delete_startup_task() -> None:
    result = subprocess.run(
        ["schtasks", "/Delete", "/TN", TASK_NAME, "/F"],
        capture_output=True,
        text=True,
    )
    if result.returncode:
        raise RwError(f"Failed to delete scheduled task - {result.returncode}")
    print(f"[+] Scheduled task '{TASK_NAME}' deleted")

def pause_after_run(enabled: bool) -> None:
    if not enabled:
        return
    try:
        threading.Event().wait()
    except KeyboardInterrupt:
        pass

@dataclass(frozen=True, slots=True)
class Bdf:
    bus: int
    device: int
    function: int

    def __post_init__(self) -> None:
        if not 0 <= self.bus <= 0xFF or not 0 <= self.device <= 0x1F or not 0 <= self.function <= 7:
            raise ValueError("PCI address is outside valid BB:DD.F range")

    def __str__(self) -> str:
        return f"{self.bus:02x}:{self.device:02x}.{self.function:x}"

class ExecRw:
    def __init__(self, rw_path: Path, verbose: bool = False) -> None:
        self.rw_path = rw_path
        self.verbose = verbose

    def _call(self, command: str) -> str:
        if self.verbose:
            print(f"[rw] {command}")
        try:
            process = subprocess.run(
                [str(self.rw_path), "/NoLogo", f"/Command={command}", "/Stdout"],
                capture_output=True,
                text=True,
                errors="replace",
                timeout=30,
                creationflags=getattr(subprocess, "CREATE_NO_WINDOW", 0),
            )
        except subprocess.TimeoutExpired as exc:
            raise RwError("rw.exe didn't finish within 30 seconds") from exc

        output = ((process.stdout or "") + (process.stderr or "")).strip()
        if process.returncode:
            raise RwError(f"rw.exe returned {process.returncode}: {output}")
        if self.verbose and output:
            print(f"[rw] {output}")
        return output

    @staticmethod
    def _batches(commands: Iterable[str], limit: int = 24000) -> Iterable[list[str]]:
        batch: list[str] = []
        length = 0
        for command in commands:
            added = len(command) + bool(batch)
            if batch and length + added > limit:
                yield batch
                batch = []
                length = 0
            batch.append(command)
            length += len(command) + bool(length)
        if batch:
            yield batch

    def read_many(self, commands: Iterable[str]) -> list[int]:
        values: list[int] = []
        for batch in self._batches(commands):
            output = self._call(";".join(batch))
            matches = RW_RESULT.findall(output)
            if len(matches) != len(batch):
                raise RwError(f"Expected {len(batch)} values from rw.exe, received {len(matches)}: {output}")
            values.extend(int(value, 16) for value in matches)
        return values

    def write_many(self, commands: Iterable[str]) -> None:
        for batch in self._batches(commands):
            self._call(";".join(batch))

    def get_xhci_many(self, indexes: Iterable[int]) -> list[int]:
        return self.read_many(f"FPciClass 0x{XHCI_CLASS_CODE:X} 0x{index:X}" for index in indexes)

    def read_pci_dwords(self, bdf: Bdf, offsets: Iterable[int]) -> list[int]:
        return self.read_many(
            f"RPCI32 0x{bdf.bus:X} 0x{bdf.device:X} 0x{bdf.function:X} 0x{offset:X}"
            for offset in offsets
        )

    def read_mmio_dwords(self, addresses: Iterable[int]) -> list[int]:
        return self.read_many(f"R32 0x{address:X}" for address in addresses)

    def write_mmio_dwords(self, writes: Iterable[tuple[int, int]]) -> None:
        self.write_many(f"W32 0x{address:X} 0x{value:X}" for address, value in writes)

def parse_bdf(raw: str) -> Bdf:
    try:
        bus, device_function = raw.split(":", 1)
        device, function = device_function.split(".", 1)
        return Bdf(int(bus, 16), int(device, 16), int(function, 16))
    except (ValueError, AttributeError) as exc:
        raise argparse.ArgumentTypeError(f"Invalid BDF '{raw}', expected hexadecimal BB:DD.F") from exc

def bounded_integer(name: str, minimum: int, maximum: int):
    def parse(raw: str) -> int:
        try:
            value = int(raw, 0)
        except ValueError as exc:
            raise argparse.ArgumentTypeError(f"{name} must be an integer") from exc
        if not minimum <= value <= maximum:
            raise argparse.ArgumentTypeError(f"{name} must be within {minimum}-{maximum}")
        return value

    return parse

parse_index = bounded_integer("xHCI index", 0, 0xFF)
parse_interrupter = bounded_integer("Interrupter", 0, 0x3FF)
parse_interval = bounded_integer("Interval", 0, 0xFFFF)

def decode_bdf(value: int) -> Bdf:
    return Bdf((value >> 8) & 0xFF, (value >> 3) & 0x1F, value & 7)

def get_all_bdfs(rw: ExecRw) -> list[Bdf]:
    controllers: list[Bdf] = []
    for first in range(0, 0x100, 8):
        for value in rw.get_xhci_many(range(first, first + 8)):
            if value == 0xFFFF:
                return controllers
            controllers.append(decode_bdf(value))
    raise RwError("More than 256 xHCI functions were reported")

def get_bdf(rw: ExecRw, index: int) -> Bdf:
    value = rw.get_xhci_many([index])[0]
    if value == 0xFFFF:
        raise RwError(f"rw.exe didn't find xHCI controller index {index}")
    return decode_bdf(value)

def resolve_register_base(rw: ExecRw, bdf: Bdf) -> int:
    command_status, class_revision, bar0, bar1 = rw.read_pci_dwords(bdf, [0x04, 0x08, 0x10, 0x14])
    class_code = (class_revision >> 8) & 0xFFFFFF
    if class_code != XHCI_CLASS_CODE:
        raise RwError(f"PCI {bdf} has class 0x{class_code:06X}, not xHCI class 0x{XHCI_CLASS_CODE:06X}")
    if not command_status & 0x2:
        raise RwError(f"PCI {bdf} has Memory Space access disabled")
    if bar0 in {0, 0xFFFFFFFF} or bar0 & 1:
        raise RwError(f"PCI {bdf} doesn't expose a valid MMIO BAR0")

    bar_type = (bar0 >> 1) & 3
    if bar_type not in {0, 2}:
        raise RwError(f"PCI {bdf} uses unsupported BAR0 memory type {bar_type}")
    base = bar0 & 0xFFFFFFF0
    if bar_type == 2:
        if bar1 == 0xFFFFFFFF:
            raise RwError(f"PCI {bdf} reports an invalid BAR1 value")
        base |= bar1 << 32
    if not base:
        raise RwError(f"PCI {bdf} reports a zero register base")
    return base

def read_controller_layout(rw: ExecRw, register_base: int) -> tuple[int, int, int]:
    capability, hcsparams1, rtsoff = rw.read_mmio_dwords(
        [register_base, register_base + 0x04, register_base + 0x18]
    )
    capability_length = capability & 0xFF
    version = (capability >> 16) & 0xFFFF
    max_interrupters = (hcsparams1 >> 8) & 0x7FF
    runtime_offset = rtsoff & 0xFFFFFFE0
    if capability_length < 0x20:
        raise RwError(f"Invalid xHCI CAPLENGTH 0x{capability_length:X}")
    if not max_interrupters or max_interrupters > 0x400:
        raise RwError(f"Invalid HCSPARAMS1.MaxIntrs value {max_interrupters}")
    if not runtime_offset:
        raise RwError("Invalid xHCI RTSOFF value 0")
    return register_base + runtime_offset, max_interrupters, version

def register_address(runtime_base: int, interrupter: int, offset: int) -> int:
    return runtime_base + 0x20 + interrupter * 0x20 + offset

def read_interrupters(rw: ExecRw, runtime_base: int, maximum: int) -> tuple[list[int], list[int]]:
    addresses = [register_address(runtime_base, index, 0x08) for index in range(maximum)]
    addresses += [register_address(runtime_base, index, 0x04) for index in range(maximum)]
    values = rw.read_mmio_dwords(addresses)
    sizes, imod_values = values[:maximum], values[maximum:]
    active = [index for index, size in enumerate(sizes) if size & 0xFFFF]
    if not active:
        raise RwError("No initialized xHCI Event Rings were found")
    return active, imod_values

def select_interrupters(maximum: int, requested: Sequence[int] | None, active: list[int]) -> list[int]:
    if not requested:
        return active
    selected = sorted(set(requested))
    for index in selected:
        if index >= maximum:
            raise RwError(f"Interrupter {index} is outside controllers range 0-{maximum - 1}")
    inactive = sorted(set(selected) - set(active))
    if inactive:
        print(f"[~] Interrupter Register Sets {inactive} don't have initialized Event Rings")
    return selected

def program_imod(
    rw: ExecRw,
    runtime_base: int,
    interrupters: Sequence[int],
    current_values: Sequence[int],
    interval: int,
    no_write: bool,
) -> None:
    addresses = [register_address(runtime_base, index, 0x04) for index in interrupters]
    pending: list[tuple[int, int, int]] = []

    for index, address, current in zip(interrupters, addresses, current_values):
        current_interval = current & 0xFFFF
        counter = current >> 16
        if no_write or current_interval == interval:
            print(f"[-] Interrupter {index}: IMODI={current_interval}, IMODC={counter} at 0x{address:016X}")
        else:
            print(
                f"[+] Interrupter {index}: IMODI={current_interval}, IMODC={counter} at 0x{address:016X}, "
                f"setting IMODI={interval}"
            )
            pending.append((index, address, interval))

    if not pending:
        return

    rw.write_mmio_dwords((address, value) for _, address, value in pending)
    readback = rw.read_mmio_dwords(address for _, address, _ in pending)
    for (index, _, _), value in zip(pending, readback):
        if (value & 0xFFFF) != interval:
            raise RwError(f"Interrupter {index} IMOD verification failed with 0x{value:08X}")

def process_controller(bdf: Bdf, rw: ExecRw, args: argparse.Namespace) -> None:
    print(f"[~] xHCI controller at PCI {bdf}")
    register_base = resolve_register_base(rw, bdf)
    runtime_base, maximum, version = read_controller_layout(rw, register_base)
    active, imod_values = read_interrupters(rw, runtime_base, maximum)
    selected = select_interrupters(maximum, args.interrupter, active)
    print(f"    xHCI {version >> 8:X}.{version & 0xFF:02X}, register base 0x{register_base:016X}")
    print(f"    Runtime base 0x{runtime_base:016X}, {maximum} implemented, {len(active)} initialized")
    program_imod(rw, runtime_base, selected, [imod_values[index] for index in selected], args.interval, args.no_write)
    print("[+] Done")

def help_formatter(prog: str) -> argparse.HelpFormatter:
    return argparse.HelpFormatter(prog, max_help_position=34, width=240)

def parse_args(argv: Sequence[str]) -> argparse.Namespace | None:
    parser = argparse.ArgumentParser(formatter_class=help_formatter)
    parser.add_argument(
        "--rw-path",
        metavar="PATH",
        type=Path,
        default=get_default_rw_path(),
        help="Path to rw.exe, downloaded under %%LOCALAPPDATA%%\\Noverse when missing",
    )
    controller = parser.add_mutually_exclusive_group()
    controller.add_argument("--bdf", type=parse_bdf, help="Hexadecimal xHCI PCI address (BB:DD.F)")
    controller.add_argument("--xhci-index", metavar="N", type=parse_index, help="Select Nth xHCI controller")
    controller.add_argument("--all", action="store_true", help="Go through every PCI xHCI controller")
    parser.add_argument(
        "--interrupter",
        "-i",
        metavar="ID",
        type=parse_interrupter,
        action="append",
        help="Interrupter ID to process",
    )
    parser.add_argument(
        "--interval",
        metavar="VALUE",
        type=parse_interval,
        default=0,
        help="IMODI in 250 ns units, 0 disables moderation, range 0-65535",
    )
    parser.add_argument("--no-write", action="store_true", help="Read and output without MMIO writes")
    parser.add_argument("--verbose", action="store_true", help="Show rw.exe commands and output")
    parser.add_argument("--startup", action="store_true", help="Create a highest privilege logon task")
    parser.add_argument("--delete", action="store_true", help="Delete the logon task")
    parser.add_argument("--no-exit", action="store_true", help="Keep the console open after completion")
    if not argv:
        parser.print_help()
        return None
    return parser.parse_args(argv)

def main(argv: Sequence[str]) -> int:
    raw_args = list(argv)
    args = parse_args(raw_args)
    if args is None:
        return 0
    if args.startup and args.delete:
        raise SystemExit("Use either --startup or --delete")

    try:
        if args.delete:
            delete_startup_task()
            pause_after_run(args.no_exit)
            return 0

        prepare_rw_binary(args.rw_path)
        rw = ExecRw(args.rw_path, args.verbose)
        if args.all:
            controllers = get_all_bdfs(rw)
            if not controllers:
                raise RwError("No PCI xHCI controllers were found")
        elif args.bdf:
            controllers = [args.bdf]
        else:
            controllers = [get_bdf(rw, args.xhci_index or 0)]

        failed = False
        for bdf in controllers:
            try:
                process_controller(bdf, rw, args)
            except RwError as exc:
                failed = True
                print(f"[!] PCI {bdf}: {exc}", file=sys.stderr)

        if failed:
            return 1
        if args.startup:
            install_startup_task(raw_args)
        pause_after_run(args.no_exit)
        return 0
    except (OSError, RwError, zipfile.BadZipFile) as exc:
        print(f"[!] {exc}", file=sys.stderr)
        return 1

if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
