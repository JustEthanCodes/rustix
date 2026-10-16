# x86_64 drivers

## Driver boundary

Rustix keeps privileged platform access in `src/arch/x86_64/`. Device-facing routines should be small, explicit about polling/interrupt assumptions, and separated from policy such as terminal input or process I/O. The current drivers are intentionally early-boot building blocks, not a finished device model.

## Implemented drivers

| Driver | Source | Status and limits |
|---|---|---|
| 16550-compatible COM1 serial | [`src/arch/x86_64/serial.rs`](../../src/arch/x86_64/serial.rs) | Initialized during `_start`; polling formatted output and non-blocking input for Crabshell; bounded transmit waits. |
| x86 port I/O primitives | [`src/arch/x86_64/io.rs`](../../src/arch/x86_64/io.rs) | Small unsafe `in`/`out` wrappers used by platform drivers. |
| PS/2-compatible keyboard controller | [`src/arch/x86_64/keyboard.rs`](../../src/arch/x86_64/keyboard.rs) | Non-blocking raw-byte polling API; filters auxiliary-device and controller-error bytes. Not yet connected to a kernel input queue. |

The keyboard routine assumes a legacy controller is present and enabled. It does not initialize the controller, decode scancode sets, support USB HID, or use interrupts. Callers must not spin waiting for input; use `try_read_scancode()` when the kernel has a suitable polling opportunity.

## Driver development rules

- Keep port I/O, MMIO, DMA, and interrupt entry points in architecture/device modules; do not expose raw I/O ports to generic kernel services.
- Document required privilege level, device assumptions, concurrency/interrupt context, and whether a call can block.
- Bound waits in early boot, avoid allocation in low-level paths, and propagate/report device absence rather than hanging startup.
- Separate raw hardware events from key mapping, terminal semantics, and user-visible input policy.
- Add emulator/hardware tests when an integration harness exists; host tests alone cannot validate port I/O.

## Planned driver work

Add a timer and interrupt-controller path before interrupt-driven keyboard input; establish locking and per-CPU rules before enabling concurrency. Then consider framebuffer/console output, PCI discovery, storage, and networking as independently reviewed drivers. No support for those devices is implied by this plan.
