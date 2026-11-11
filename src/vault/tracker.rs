//! Bounded failure tracking for the lockout thresholds.
//!
//! [`KeyVault::report_failure`](crate::KeyVault::report_failure) takes a
//! key name from the caller, and callers often take that name from a
//! request (a token's key id, say). Before 1.2 every reported name got an
//! entry that was never freed, and each report walked every timestamp in
//! the window under one global lock. This tracker is bounded on every
//! axis:
//!
//! - **Nothing is recorded when no threshold is on.** The vault does not
//!   call the tracker at all then.
//! - **Per name, at most [`MAX_SLOTS`] slots.** Each slot is a timestamp and
//!   a count. Up to the threshold, every failure has its own slot, so the
//!   count is exact for thresholds up to `MAX_SLOTS`. Past that, new
//!   failures are added to the newest slot, which moves to the current
//!   time; that can only make the count higher, never lower, so a lockout
//!   is never missed.
//! - **Names of unregistered keys share a fixed capacity.** When it is
//!   full, the name whose last failure is oldest is forgotten. Names of
//!   registered keys (and the master credential) are pinned: flooding
//!   the tracker with other names cannot evict them, so it cannot reset
//!   the count of a key under attack.
//! - **Names are not stored.** An entry is keyed by a 64-bit keyed hash of
//!   the name, so a long name costs nothing extra.
//! - **Sharded.** Sixteen independently locked shards, chosen by the hash.
//!   Every report costs a hash, two `O(log n)` map operations on one
//!   shard, and at most `MAX_SLOTS` slot reads.

use alloc::collections::{BTreeMap, VecDeque};
use core::time::Duration;

use crate::sync::Mutex;

/// Slots kept per name.
pub(crate) const MAX_SLOTS: usize = 64;

/// Number of shards. A power of two.
const SHARDS: usize = 16;

/// Default capacity for names that are not pinned.
pub(crate) const DEFAULT_CAPACITY: usize = 4096;

/// Failure counts for one report.
#[derive(Debug, Clone, Copy)]
pub(crate) struct FailureCounts {
    /// Failures inside the vault-wide window.
    pub(crate) in_window: u32,
    /// Failures inside the per-key window (0 when not asked for).
    pub(crate) in_key_window: u32,
    /// Age of the oldest failure inside the vault-wide window.
    pub(crate) window_elapsed: Duration,
}

/// What a report should be counted against.
#[derive(Debug, Clone, Copy)]
pub(crate) struct Windows {
    /// Vault-wide window, if that threshold is on.
    pub(crate) vault: Option<Duration>,
    /// Per-key window, if that threshold is on and applies to this name.
    pub(crate) key: Option<Duration>,
}

/// One name's failures.
struct Entry {
    /// `(time, count)`, oldest first. Times never decrease.
    slots: VecDeque<(Duration, u32)>,
    /// Position in the eviction order, or `None` if the entry is pinned.
    seq: Option<u64>,
}

#[derive(Default)]
struct Shard {
    entries: BTreeMap<u64, Entry>,
    /// Unpinned entries by the sequence number of their last failure:
    /// the first one is evicted first.
    order: BTreeMap<u64, u64>,
    next_seq: u64,
}

/// The tracker. See the module docs.
pub(crate) struct FailureTracker {
    shards: [Mutex<Shard>; SHARDS],
    /// Unpinned entries allowed per shard.
    per_shard: usize,
    /// Slots kept per name: the larger threshold, capped at `MAX_SLOTS`.
    slots: usize,
}

impl FailureTracker {
    /// A tracker for thresholds up to `max_threshold`, holding at most
    /// `capacity` unpinned names (at least one per shard).
    pub(crate) fn new(max_threshold: u32, capacity: usize) -> Self {
        let slots = usize::try_from(max_threshold)
            .unwrap_or(MAX_SLOTS)
            .clamp(1, MAX_SLOTS);
        Self {
            shards: core::array::from_fn(|_| Mutex::new(Shard::default())),
            per_shard: capacity.div_ceil(SHARDS).max(1),
            slots,
        }
    }

    fn shard(&self, hash: u64) -> &Mutex<Shard> {
        // The top bits pick the shard; the low bits order the map.
        #[allow(clippy::cast_possible_truncation)] // < SHARDS.
        let index = (hash >> 60) as usize % SHARDS;
        &self.shards[index]
    }

    /// Record a failure for the name with hash `hash` at `now` and count
    /// the failures inside each requested window.
    pub(crate) fn record(
        &self,
        hash: u64,
        pinned: bool,
        now: Duration,
        windows: Windows,
    ) -> FailureCounts {
        let keep = match (windows.vault, windows.key) {
            (Some(a), Some(b)) => a.max(b),
            (Some(a), None) | (None, Some(a)) => a,
            (None, None) => Duration::ZERO,
        };
        let mut guard = self.shard(hash).lock();
        let shard = &mut *guard;
        if !shard.entries.contains_key(&hash) {
            if !pinned {
                while shard.order.len() >= self.per_shard {
                    let Some((_, victim)) = shard.order.pop_first() else {
                        break;
                    };
                    let _ = shard.entries.remove(&victim);
                }
            }
            let _ = shard.entries.insert(
                hash,
                Entry {
                    slots: VecDeque::new(),
                    seq: None,
                },
            );
        }
        let seq = shard.next_seq;
        shard.next_seq += 1;
        let Some(entry) = shard.entries.get_mut(&hash) else {
            return FailureCounts {
                in_window: 1,
                in_key_window: u32::from(windows.key.is_some()),
                window_elapsed: Duration::ZERO,
            };
        };
        // Keep the eviction order in step: pinned entries are not in it,
        // unpinned ones move to the back on every failure.
        if let Some(old) = entry.seq.take() {
            let _ = shard.order.remove(&old);
        }
        if !pinned {
            entry.seq = Some(seq);
            let _ = shard.order.insert(seq, hash);
        }

        let slots = &mut entry.slots;
        while let Some(&(t, _)) = slots.front() {
            if now.saturating_sub(t) > keep {
                let _ = slots.pop_front();
            } else {
                break;
            }
        }
        let full = slots.len() >= self.slots;
        match slots.back_mut() {
            Some(back) if back.0 >= now || full => {
                // Same instant, or no slot left: count it in the newest
                // slot and move that slot to now. Moving it later can only
                // keep failures in the window longer.
                back.0 = back.0.max(now);
                back.1 = back.1.saturating_add(1);
            }
            _ => slots.push_back((now, 1)),
        }

        let count = |window: Duration| -> u32 {
            slots
                .iter()
                .rev()
                .take_while(|&&(t, _)| now.saturating_sub(t) <= window)
                .fold(0u32, |acc, &(_, n)| acc.saturating_add(n))
        };
        let (in_window, window_elapsed) = match windows.vault {
            Some(w) => {
                let oldest = slots
                    .iter()
                    .find(|&&(t, _)| now.saturating_sub(t) <= w)
                    .map_or(now, |&(t, _)| t);
                (count(w), now.saturating_sub(oldest))
            }
            None => (count(keep), Duration::ZERO),
        };
        FailureCounts {
            in_window,
            in_key_window: windows.key.map_or(0, count),
            window_elapsed,
        }
    }

    /// Forget the failures recorded for `hash`.
    pub(crate) fn remove(&self, hash: u64) {
        let mut guard = self.shard(hash).lock();
        let shard = &mut *guard;
        if let Some(entry) = shard.entries.remove(&hash) {
            if let Some(seq) = entry.seq {
                let _ = shard.order.remove(&seq);
            }
        }
    }

    /// Forget everything.
    pub(crate) fn clear(&self) {
        for shard in &self.shards {
            let mut shard = shard.lock();
            shard.entries.clear();
            shard.order.clear();
        }
    }

    /// Number of names tracked (tests).
    #[cfg(test)]
    pub(crate) fn len(&self) -> usize {
        self.shards.iter().map(|s| s.lock().entries.len()).sum()
    }

    /// Slots held for `hash` (tests).
    #[cfg(test)]
    pub(crate) fn slots_of(&self, hash: u64) -> usize {
        self.shard(hash)
            .lock()
            .entries
            .get(&hash)
            .map_or(0, |e| e.slots.len())
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
    use super::*;

    const MIN: Duration = Duration::from_secs(60);

    fn vault_only() -> Windows {
        Windows {
            vault: Some(MIN),
            key: None,
        }
    }

    #[test]
    fn counts_are_exact_up_to_the_threshold() {
        let t = FailureTracker::new(5, 100);
        for i in 1..=5u32 {
            let c = t.record(7, true, Duration::from_secs(u64::from(i)), vault_only());
            assert_eq!(c.in_window, i);
        }
        // Failures age out one by one.
        let c = t.record(7, true, Duration::from_secs(62), vault_only());
        assert_eq!(c.in_window, 5); // t=1 is out, t=2..5 and 62 are in
        assert_eq!(c.window_elapsed, Duration::from_secs(60));
    }

    #[test]
    fn many_failures_for_one_name_use_bounded_slots() {
        let t = FailureTracker::new(3, 100);
        for i in 0..100_000u64 {
            let c = t.record(1, true, Duration::from_micros(i), vault_only());
            assert_eq!(u64::from(c.in_window), i + 1);
        }
        assert!(t.slots_of(1) <= 3);
    }

    #[test]
    fn unpinned_names_are_capped_and_evicted_oldest_first() {
        let t = FailureTracker::new(3, 32);
        let pinned = 0x5555;
        let _ = t.record(pinned, true, Duration::ZERO, vault_only());
        for i in 0..10_000u64 {
            let h = i.wrapping_mul(0x9e37_79b9_7f4a_7c15);
            let _ = t.record(h, false, Duration::from_millis(i), vault_only());
        }
        // 32 unpinned (2 per shard) plus the pinned one.
        assert!(t.len() <= 33, "{} names tracked", t.len());
        // The pinned name kept its count.
        let c = t.record(pinned, true, Duration::from_secs(1), vault_only());
        assert_eq!(c.in_window, 2);
    }

    #[test]
    fn separate_windows_are_counted_separately() {
        let t = FailureTracker::new(10, 100);
        let w = Windows {
            vault: Some(Duration::from_secs(10)),
            key: Some(Duration::from_secs(100)),
        };
        let _ = t.record(9, true, Duration::from_secs(0), w);
        let c = t.record(9, true, Duration::from_secs(50), w);
        assert_eq!(c.in_window, 1);
        assert_eq!(c.in_key_window, 2);
    }

    #[test]
    fn remove_and_clear_forget() {
        let t = FailureTracker::new(3, 100);
        let _ = t.record(1, false, Duration::ZERO, vault_only());
        let _ = t.record(2, true, Duration::ZERO, vault_only());
        t.remove(1);
        assert_eq!(t.len(), 1);
        t.clear();
        assert_eq!(t.len(), 0);
        let c = t.record(2, true, Duration::ZERO, vault_only());
        assert_eq!(c.in_window, 1);
    }
}
