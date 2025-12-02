//! Bounded collections and queues with overflow protection

use parking_lot::{Mutex, RwLock};
use serde::Serialize;
use std::collections::VecDeque;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Arc;

/// Statistics for bounded collection operations
#[derive(Debug, Clone, Default, Serialize)]
pub struct BoundedStats {
    pub current_size: usize,
    pub capacity: usize,
    pub total_pushed: u64,
    pub total_popped: u64,
    pub total_dropped: u64,
    pub high_water_mark: usize,
}

/// A bounded queue that drops oldest items when full
#[derive(Debug)]
pub struct BoundedQueue<T> {
    inner: Mutex<VecDeque<T>>,
    capacity: usize,
    stats: Arc<BoundedQueueStats>,
}

#[derive(Debug, Default)]
struct BoundedQueueStats {
    total_pushed: AtomicUsize,
    total_popped: AtomicUsize,
    total_dropped: AtomicUsize,
    high_water_mark: AtomicUsize,
}

impl<T> BoundedQueue<T> {
    pub fn new(capacity: usize) -> Self {
        Self {
            inner: Mutex::new(VecDeque::with_capacity(capacity)),
            capacity,
            stats: Arc::new(BoundedQueueStats::default()),
        }
    }

    /// Push an item, dropping the oldest if at capacity
    pub fn push(&self, item: T) -> Option<T> {
        let mut queue = self.inner.lock();
        self.stats.total_pushed.fetch_add(1, Ordering::Relaxed);

        let dropped = if queue.len() >= self.capacity {
            self.stats.total_dropped.fetch_add(1, Ordering::Relaxed);
            queue.pop_front()
        } else {
            None
        };

        queue.push_back(item);
        let current_len = queue.len();
        let mut hwm = self.stats.high_water_mark.load(Ordering::Relaxed);
        while current_len > hwm {
            match self.stats.high_water_mark.compare_exchange_weak(
                hwm,
                current_len,
                Ordering::Relaxed,
                Ordering::Relaxed,
            ) {
                Ok(_) => break,
                Err(x) => hwm = x,
            }
        }

        dropped
    }

    /// Push only if there's room
    pub fn try_push(&self, item: T) -> Result<(), T> {
        let mut queue = self.inner.lock();
        if queue.len() >= self.capacity {
            return Err(item);
        }

        self.stats.total_pushed.fetch_add(1, Ordering::Relaxed);
        queue.push_back(item);
        Ok(())
    }

    /// Pop the oldest item
    pub fn pop(&self) -> Option<T> {
        let mut queue = self.inner.lock();
        let item = queue.pop_front();
        if item.is_some() {
            self.stats.total_popped.fetch_add(1, Ordering::Relaxed);
        }
        item
    }

    pub fn len(&self) -> usize {
        self.inner.lock().len()
    }

    pub fn is_empty(&self) -> bool {
        self.inner.lock().is_empty()
    }

    pub fn capacity(&self) -> usize {
        self.capacity
    }

    pub fn clear(&self) {
        let mut queue = self.inner.lock();
        let dropped = queue.len();
        queue.clear();
        self.stats
            .total_dropped
            .fetch_add(dropped, Ordering::Relaxed);
    }

    pub fn stats(&self) -> BoundedStats {
        let queue = self.inner.lock();
        BoundedStats {
            current_size: queue.len(),
            capacity: self.capacity,
            total_pushed: self.stats.total_pushed.load(Ordering::Relaxed) as u64,
            total_popped: self.stats.total_popped.load(Ordering::Relaxed) as u64,
            total_dropped: self.stats.total_dropped.load(Ordering::Relaxed) as u64,
            high_water_mark: self.stats.high_water_mark.load(Ordering::Relaxed),
        }
    }

    pub fn drain(&self) -> Vec<T> {
        let mut queue = self.inner.lock();
        let items: Vec<T> = queue.drain(..).collect();
        self.stats
            .total_popped
            .fetch_add(items.len(), Ordering::Relaxed);
        items
    }
}

/// A bounded map that evicts oldest entries when full
#[derive(Debug)]
pub struct BoundedMap<K, V> {
    inner: RwLock<BoundedMapInner<K, V>>,
    capacity: usize,
    stats: Arc<BoundedMapStats>,
}

#[derive(Debug)]
struct BoundedMapInner<K, V> {
    map: std::collections::HashMap<K, V>,
    insertion_order: VecDeque<K>,
}

#[derive(Debug, Default)]
struct BoundedMapStats {
    total_inserted: AtomicUsize,
    total_evicted: AtomicUsize,
    total_hits: AtomicUsize,
    total_misses: AtomicUsize,
}

impl<K: Clone + Eq + std::hash::Hash, V> BoundedMap<K, V> {
    pub fn new(capacity: usize) -> Self {
        Self {
            inner: RwLock::new(BoundedMapInner {
                map: std::collections::HashMap::with_capacity(capacity),
                insertion_order: VecDeque::with_capacity(capacity),
            }),
            capacity,
            stats: Arc::new(BoundedMapStats::default()),
        }
    }

    /// Insert a key-value pair, evicting oldest if at capacity
    pub fn insert(&self, key: K, value: V) -> Option<V> {
        let mut inner = self.inner.write();
        self.stats.total_inserted.fetch_add(1, Ordering::Relaxed);

        if inner.map.contains_key(&key) {
            return inner.map.insert(key, value);
        }

        if inner.map.len() >= self.capacity {
            if let Some(oldest_key) = inner.insertion_order.pop_front() {
                inner.map.remove(&oldest_key);
                self.stats.total_evicted.fetch_add(1, Ordering::Relaxed);
            }
        }

        inner.insertion_order.push_back(key.clone());
        inner.map.insert(key, value)
    }

    /// Get a value by key
    pub fn get(&self, key: &K) -> Option<V>
    where
        V: Clone,
    {
        let inner = self.inner.read();
        match inner.map.get(key) {
            Some(v) => {
                self.stats.total_hits.fetch_add(1, Ordering::Relaxed);
                Some(v.clone())
            }
            None => {
                self.stats.total_misses.fetch_add(1, Ordering::Relaxed);
                None
            }
        }
    }

    pub fn contains_key(&self, key: &K) -> bool {
        self.inner.read().map.contains_key(key)
    }

    pub fn remove(&self, key: &K) -> Option<V> {
        let mut inner = self.inner.write();
        if let Some(value) = inner.map.remove(key) {
            inner.insertion_order.retain(|k| k != key);
            Some(value)
        } else {
            None
        }
    }

    pub fn len(&self) -> usize {
        self.inner.read().map.len()
    }

    pub fn is_empty(&self) -> bool {
        self.inner.read().map.is_empty()
    }

    pub fn clear(&self) {
        let mut inner = self.inner.write();
        let evicted = inner.map.len();
        inner.map.clear();
        inner.insertion_order.clear();
        self.stats
            .total_evicted
            .fetch_add(evicted, Ordering::Relaxed);
    }

    pub fn stats(&self) -> BoundedMapStatsSnapshot {
        let inner = self.inner.read();
        BoundedMapStatsSnapshot {
            current_size: inner.map.len(),
            capacity: self.capacity,
            total_inserted: self.stats.total_inserted.load(Ordering::Relaxed) as u64,
            total_evicted: self.stats.total_evicted.load(Ordering::Relaxed) as u64,
            total_hits: self.stats.total_hits.load(Ordering::Relaxed) as u64,
            total_misses: self.stats.total_misses.load(Ordering::Relaxed) as u64,
        }
    }
}

#[derive(Debug, Clone, Serialize)]
pub struct BoundedMapStatsSnapshot {
    pub current_size: usize,
    pub capacity: usize,
    pub total_inserted: u64,
    pub total_evicted: u64,
    pub total_hits: u64,
    pub total_misses: u64,
}

/// A rate-limited counter for tracking operations per time window
#[derive(Debug)]
pub struct RateLimitedCounter {
    count: AtomicUsize,
    limit: usize,
    window_start: Mutex<std::time::Instant>,
    window_duration: std::time::Duration,
    total_allowed: AtomicUsize,
    total_rejected: AtomicUsize,
}

impl RateLimitedCounter {
    pub fn new(limit: usize, window: std::time::Duration) -> Self {
        Self {
            count: AtomicUsize::new(0),
            limit,
            window_start: Mutex::new(std::time::Instant::now()),
            window_duration: window,
            total_allowed: AtomicUsize::new(0),
            total_rejected: AtomicUsize::new(0),
        }
    }

    /// Try to increment the counter. Returns true if under limit.
    pub fn try_acquire(&self) -> bool {
        {
            let mut start = self.window_start.lock();
            if start.elapsed() >= self.window_duration {
                *start = std::time::Instant::now();
                self.count.store(0, Ordering::Relaxed);
            }
        }

        let current = self.count.fetch_add(1, Ordering::Relaxed);
        if current < self.limit {
            self.total_allowed.fetch_add(1, Ordering::Relaxed);
            true
        } else {
            self.count.fetch_sub(1, Ordering::Relaxed);
            self.total_rejected.fetch_add(1, Ordering::Relaxed);
            false
        }
    }

    pub fn remaining(&self) -> usize {
        let current = self.count.load(Ordering::Relaxed);
        self.limit.saturating_sub(current)
    }

    pub fn stats(&self) -> RateLimitStats {
        RateLimitStats {
            current_count: self.count.load(Ordering::Relaxed),
            limit: self.limit,
            total_allowed: self.total_allowed.load(Ordering::Relaxed) as u64,
            total_rejected: self.total_rejected.load(Ordering::Relaxed) as u64,
        }
    }
}

#[derive(Debug, Clone, Serialize)]
pub struct RateLimitStats {
    pub current_count: usize,
    pub limit: usize,
    pub total_allowed: u64,
    pub total_rejected: u64,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_bounded_queue_overflow() {
        let queue: BoundedQueue<i32> = BoundedQueue::new(3);

        queue.push(1);
        queue.push(2);
        queue.push(3);

        assert_eq!(queue.len(), 3);

        let dropped = queue.push(4);
        assert_eq!(dropped, Some(1));
        assert_eq!(queue.len(), 3);

        assert_eq!(queue.pop(), Some(2));
        assert_eq!(queue.pop(), Some(3));
        assert_eq!(queue.pop(), Some(4));
    }

    #[test]
    fn test_bounded_queue_try_push() {
        let queue: BoundedQueue<i32> = BoundedQueue::new(2);

        assert!(queue.try_push(1).is_ok());
        assert!(queue.try_push(2).is_ok());
        assert!(queue.try_push(3).is_err());
    }

    #[test]
    fn test_bounded_map_eviction() {
        let map: BoundedMap<String, i32> = BoundedMap::new(3);

        map.insert("a".to_string(), 1);
        map.insert("b".to_string(), 2);
        map.insert("c".to_string(), 3);

        assert_eq!(map.len(), 3);

        map.insert("d".to_string(), 4);

        assert_eq!(map.len(), 3);
        assert!(!map.contains_key(&"a".to_string()));
        assert!(map.contains_key(&"d".to_string()));
    }

    #[test]
    fn test_rate_limited_counter() {
        let counter = RateLimitedCounter::new(3, std::time::Duration::from_secs(1));

        assert!(counter.try_acquire());
        assert!(counter.try_acquire());
        assert!(counter.try_acquire());
        assert!(!counter.try_acquire());

        let stats = counter.stats();
        assert_eq!(stats.total_allowed, 3);
        assert_eq!(stats.total_rejected, 1);
    }
}
