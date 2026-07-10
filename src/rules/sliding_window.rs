use std::time::Instant;

const BUCKET_COUNT: usize = 4;

#[derive(Debug, Clone)]
pub struct SlidingWindow {
    buckets: [u32; BUCKET_COUNT],
    bucket_time: u64,
    total: u32,
    last_update: Instant,
}

impl SlidingWindow {
    pub fn new(window_secs: u32) -> Self {
        Self {
            buckets: [0; BUCKET_COUNT],
            bucket_time: (window_secs as u64 * 1_000_000_000) / BUCKET_COUNT as u64,
            total: 0,
            last_update: Instant::now(),
        }
    }

    pub fn record(&mut self) -> u32 {
        self.rotate();
        self.buckets[BUCKET_COUNT - 1] += 1;
        self.total += 1;
        self.total
    }

    pub fn count(&self) -> u32 {
        let mut window = self.clone();
        window.rotate();
        window.total
    }

    pub fn reset(&mut self) {
        self.buckets = [0; BUCKET_COUNT];
        self.total = 0;
        self.last_update = Instant::now();
    }

    pub fn last_update(&self) -> Instant {
        self.last_update
    }

    fn rotate(&mut self) {
        let now = Instant::now();
        let elapsed = now.duration_since(self.last_update).as_nanos() as u64;

        if elapsed < self.bucket_time {
            return;
        }

        let buckets_to_rotate = (elapsed / self.bucket_time) as usize;

        for _ in 0..buckets_to_rotate.min(BUCKET_COUNT) {
            let mut sum = 0;
            for i in 1..BUCKET_COUNT {
                self.buckets[i - 1] = self.buckets[i];
                sum += self.buckets[i];
            }
            self.buckets[BUCKET_COUNT - 1] = 0;
            self.total = sum;
        }

        self.last_update = now;
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::thread;
    use std::time::Duration;

    #[test]
    fn test_sliding_window_basic() {
        let mut window = SlidingWindow::new(20);

        for _ in 0..10 {
            window.record();
        }

        assert_eq!(window.count(), 10);
    }

    #[test]
    fn test_sliding_window_rotation() {
        let mut window = SlidingWindow::new(4);

        for _ in 0..10 {
            window.record();
            thread::sleep(Duration::from_millis(300));
        }

        thread::sleep(Duration::from_secs(2));
        let count_after_2s = window.count();
        assert!(count_after_2s < 10);

        thread::sleep(Duration::from_secs(3));
        assert_eq!(window.count(), 0);
    }

    #[test]
    fn test_sliding_window_reset() {
        let mut window = SlidingWindow::new(20);

        for _ in 0..10 {
            window.record();
        }

        assert_eq!(window.count(), 10);
        window.reset();
        assert_eq!(window.count(), 0);
    }
}
