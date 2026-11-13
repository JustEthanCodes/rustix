# x86_64 drivers

## Driver boundary

Rustix keeps privileged platform access in `src/arch/x86_64/`. Device-facing routines should be small, explicit about polling/interrupt assumptions, and separated from policy such as terminal input or process I/O. The current drivers are intentionally early-boot building blocks, not a finished device model.

## Implemented drivers

| Driver | Source | Status and limits |
|---|---|---|
| 16550-compatible COM1 serial | [`src/arch/x86_64/serial.rs`](../../src/arch/x86_64/serial.rs) | Polling formatted output and early-boot input; after APIC setup, IRQ4 drains RX bytes into a bounded queue and wakes the cooperative shell. Bounded transmit waits remain in use. |
| x86 port I/O primitives | [`src/arch/x86_64/io.rs`](../../src/arch/x86_64/io.rs) | Small unsafe `in`/`out` wrappers used by platform drivers. |
| PS/2-compatible keyboard controller | [`src/arch/x86_64/keyboard.rs`](../../src/arch/x86_64/keyboard.rs) | Bounded IRQ1 drain into a raw-scancode queue, plus non-blocking polling fallback; filters auxiliary-device and controller-error bytes. |
| Local APIC, I/O APIC, and PIT | [`src/arch/x86_64/apic.rs`](../../src/arch/x86_64/apic.rs) | One-vCPU MADT-routed IRQ delivery; PIC routes remain masked. PIT supplies the approximately 100 Hz scheduler tick. |

The PS/2 driver assumes a legacy controller is present. Initialization uses bounded waits; raw scancodes are not translated, and USB HID is unsupported. UART and keyboard IRQ paths use bounded queues to wake tasks waiting for input; runnable threads are also subject to PIT preemption. Polling remains available for early boot/fallback.

## Driver development rules

- Keep port I/O, MMIO, DMA, and interrupt entry points in architecture/device modules; do not expose raw I/O ports to generic kernel services.
- Document required privilege level, device assumptions, concurrency/interrupt context, and whether a call can block.
- Bound waits in early boot, avoid allocation in low-level paths, and propagate/report device absence rather than hanging startup.
- Separate raw hardware events from key mapping, terminal semantics, and user-visible input policy.
- Add emulator/hardware tests when an integration harness exists; host tests alone cannot validate port I/O.

## Planned driver work

`src/time.rs` provides host-tested PIT divisor selection and monotonic tick arithmetic; the x86_64 APIC driver programs the PIT and delivers live ticks. This is a monotonic tick source, not wall-clock time. Single-vCPU timer preemption is implemented with IRQ-safe locking and validated context switching; SMP still requires separately designed per-CPU and synchronization rules. Framebuffer/console output, PCI discovery, storage, and networking remain future drivers; no support for those devices is implied.
