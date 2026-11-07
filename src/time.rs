//! Host-testable PIT rate selection and monotonic tick accounting.
//!
//! The platform timer owns interrupt delivery. `AtomicTickCounter` is the
//! allocation-free IRQ-facing counter; it does not access hardware or enable
//! interrupts.

/// The fixed input frequency of the legacy 8254 PIT.
pub const PIT_INPUT_HZ: u32 = 1_193_182;
const NANOS_PER_SECOND: u128 = 1_000_000_000;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum TimeError {
    ZeroFrequency,
    FrequencyTooHigh,
    FrequencyTooLow,
    TickCounterOverflow,
    ElapsedTimeOverflow,
}

/// A rounded PIT reload value and its exact input-clock period.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct PitRate {
    divisor: u16,
}

impl PitRate {
    /// Select the closest representable PIT frequency for a requested rate.
    ///
    /// The PIT divisor is limited to 1..=65535. Rounding is performed using
    /// integer arithmetic; users should use `divisor()` rather than assuming
    /// the requested rate is exact.
    pub fn for_frequency(requested_hz: u32) -> Result<Self, TimeError> {
        if requested_hz == 0 {
            return Err(TimeError::ZeroFrequency);
        }
        if requested_hz > PIT_INPUT_HZ {
            return Err(TimeError::FrequencyTooHigh);
        }
        let rounded_divisor = PIT_INPUT_HZ
            .checked_add(requested_hz / 2)
            .ok_or(TimeError::FrequencyTooHigh)?
            / requested_hz;
        if rounded_divisor == 0 {
            return Err(TimeError::FrequencyTooHigh);
        }
        if rounded_divisor > u32::from(u16::MAX) {
            return Err(TimeError::FrequencyTooLow);
        }
        Ok(Self {
            divisor: rounded_divisor as u16,
        })
    }

    pub const fn divisor(self) -> u16 {
        self.divisor
    }

    /// Return the realized rate as an exact rational number of interrupts/sec.
    pub const fn frequency_numerator_hz(self) -> u32 {
        PIT_INPUT_HZ
    }

    pub const fn frequency_denominator(self) -> u16 {
        self.divisor
    }
}

/// A lock-free tick counter suitable for a bounded single-instruction timer ISR.
///
/// It saturates rather than wrapping, so elapsed time never moves backwards.
pub struct AtomicTickCounter {
    ticks: core::sync::atomic::AtomicU64,
}

impl AtomicTickCounter {
    pub const fn new() -> Self {
        Self {
            ticks: core::sync::atomic::AtomicU64::new(0),
        }
    }

    /// Record one timer tick without taking a lock or allocating.
    pub fn tick(&self) {
        let _ = self.ticks.try_update(
            core::sync::atomic::Ordering::Relaxed,
            core::sync::atomic::Ordering::Relaxed,
            |ticks| Some(ticks.saturating_add(1)),
        );
    }

    pub fn ticks(&self) -> u64 {
        self.ticks.load(core::sync::atomic::Ordering::Acquire)
    }

    /// Convert a stable tick snapshot to nanoseconds without per-tick drift.
    pub fn elapsed_nanos(&self, rate: PitRate) -> u64 {
        elapsed_nanos_for_ticks(rate, self.ticks()).unwrap_or(u64::MAX)
    }
}

impl Default for AtomicTickCounter {
    fn default() -> Self {
        Self::new()
    }
}

/// Convert a tick snapshot using the exact PIT input-clock divisor.
pub fn elapsed_nanos_for_ticks(rate: PitRate, ticks: u64) -> Result<u64, TimeError> {
    let numerator = u128::from(ticks)
        .checked_mul(u128::from(rate.divisor))
        .and_then(|value| value.checked_mul(NANOS_PER_SECOND))
        .ok_or(TimeError::ElapsedTimeOverflow)?;
    u64::try_from(numerator / u128::from(PIT_INPUT_HZ)).map_err(|_| TimeError::ElapsedTimeOverflow)
}

/// Allocation-free monotonic time accumulated from periodic PIT interrupts.
///
/// The fractional numerator is retained across ticks, preventing per-tick
/// integer truncation from accumulating as clock drift. A caller must serialize
/// writes (normally by invoking this only from one timer handler); readers of a
/// shared clock need a separate synchronization strategy.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct MonotonicClock {
    ticks: u64,
    elapsed_nanos: u64,
    fractional_numerator: u32,
}

impl MonotonicClock {
    pub const fn new() -> Self {
        Self {
            ticks: 0,
            elapsed_nanos: 0,
            fractional_numerator: 0,
        }
    }

    pub const fn ticks(self) -> u64 {
        self.ticks
    }

    pub const fn elapsed_nanos(self) -> u64 {
        self.elapsed_nanos
    }

    /// Account for exactly one periodic PIT interrupt.
    ///
    /// On overflow the clock is left unchanged. The configured divisor is also
    /// used as the input-cycle count for one interrupt period.
    pub fn advance_pit_tick(&mut self, rate: PitRate) -> Result<(), TimeError> {
        let next_ticks = self
            .ticks
            .checked_add(1)
            .ok_or(TimeError::TickCounterOverflow)?;
        let numerator = u128::from(rate.divisor)
            .checked_mul(NANOS_PER_SECOND)
            .and_then(|value| value.checked_add(u128::from(self.fractional_numerator)))
            .ok_or(TimeError::ElapsedTimeOverflow)?;
        let whole_nanos = numerator / u128::from(PIT_INPUT_HZ);
        let fractional_numerator = (numerator % u128::from(PIT_INPUT_HZ)) as u32;
        let elapsed_nanos = self
            .elapsed_nanos
            .checked_add(u64::try_from(whole_nanos).map_err(|_| TimeError::ElapsedTimeOverflow)?)
            .ok_or(TimeError::ElapsedTimeOverflow)?;

        self.ticks = next_ticks;
        self.elapsed_nanos = elapsed_nanos;
        self.fractional_numerator = fractional_numerator;
        Ok(())
    }
}

/// A monotonic deadline represented in nanoseconds since the clock origin.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub struct Deadline(u64);

impl Deadline {
    pub const fn at_nanos(timestamp: u64) -> Self {
        Self(timestamp)
    }

    pub const fn timestamp_nanos(self) -> u64 {
        self.0
    }

    pub const fn is_reached(self, now_nanos: u64) -> bool {
        now_nanos >= self.0
    }

    pub fn after(now_nanos: u64, delay_nanos: u64) -> Result<Self, TimeError> {
        now_nanos
            .checked_add(delay_nanos)
            .map(Self)
            .ok_or(TimeError::ElapsedTimeOverflow)
    }
}

#[cfg(test)]
mod tests {
    use super::{
        elapsed_nanos_for_ticks, AtomicTickCounter, Deadline, MonotonicClock, PitRate, TimeError,
        PIT_INPUT_HZ,
    };
    use core::assert_eq;

    #[test]
    fn selects_rounded_pit_rates_and_rejects_unrepresentable_requests() {
        let rate = PitRate::for_frequency(100).unwrap();
        assert_eq!(rate.divisor(), 11_932);
        assert_eq!(rate.frequency_numerator_hz(), PIT_INPUT_HZ);
        assert_eq!(rate.frequency_denominator(), 11_932);
        assert_eq!(PitRate::for_frequency(0), Err(TimeError::ZeroFrequency));
        assert_eq!(
            PitRate::for_frequency(PIT_INPUT_HZ + 1),
            Err(TimeError::FrequencyTooHigh)
        );
        assert_eq!(PitRate::for_frequency(18), Err(TimeError::FrequencyTooLow));
    }

    #[test]
    fn fractional_tick_time_does_not_accumulate_per_tick_rounding_drift() {
        let rate = PitRate::for_frequency(100).unwrap();
        let mut clock = MonotonicClock::new();
        for _ in 0..100_000 {
            clock.advance_pit_tick(rate).unwrap();
        }

        let expected_numerator = u128::from(rate.divisor()) * 100_000 * 1_000_000_000u128;
        let expected_nanos = expected_numerator / u128::from(PIT_INPUT_HZ);
        assert_eq!(clock.ticks(), 100_000);
        assert_eq!(u128::from(clock.elapsed_nanos()), expected_nanos);
    }

    #[test]
    fn monotonic_clock_handles_deadlines_and_rejects_overflow() {
        assert_eq!(Deadline::after(100, 50), Ok(Deadline::at_nanos(150)));
        assert!(!Deadline::at_nanos(150).is_reached(149));
        assert!(Deadline::at_nanos(150).is_reached(150));
        assert_eq!(
            Deadline::after(u64::MAX, 1),
            Err(TimeError::ElapsedTimeOverflow)
        );
    }

    #[test]
    fn atomic_tick_counter_saturates_and_elapsed_time_uses_exact_divisor() {
        let rate = PitRate::for_frequency(100).unwrap();
        let ticks = AtomicTickCounter::new();
        ticks.tick();
        ticks.tick();
        assert_eq!(ticks.ticks(), 2);
        assert_eq!(
            ticks.elapsed_nanos(rate),
            elapsed_nanos_for_ticks(rate, 2).unwrap()
        );
        assert_eq!(
            elapsed_nanos_for_ticks(rate, 100),
            Ok(
                (u128::from(rate.divisor()) * 100 * 1_000_000_000u128 / u128::from(PIT_INPUT_HZ))
                    as u64
            )
        );
        let saturated = AtomicTickCounter {
            ticks: core::sync::atomic::AtomicU64::new(u64::MAX),
        };
        saturated.tick();
        assert_eq!(saturated.ticks(), u64::MAX);
        assert_eq!(saturated.elapsed_nanos(rate), u64::MAX);
    }

    #[test]
    fn failed_tick_updates_leave_the_monotonic_clock_unchanged() {
        let rate = PitRate::for_frequency(100).unwrap();
        let mut tick_overflow = MonotonicClock {
            ticks: u64::MAX,
            ..MonotonicClock::new()
        };
        let before_tick_overflow = tick_overflow;
        assert_eq!(
            tick_overflow.advance_pit_tick(rate),
            Err(TimeError::TickCounterOverflow)
        );
        assert_eq!(tick_overflow, before_tick_overflow);

        let mut time_overflow = MonotonicClock {
            elapsed_nanos: u64::MAX,
            ..MonotonicClock::new()
        };
        let before_time_overflow = time_overflow;
        assert_eq!(
            time_overflow.advance_pit_tick(rate),
            Err(TimeError::ElapsedTimeOverflow)
        );
        assert_eq!(time_overflow, before_time_overflow);
    }
}
