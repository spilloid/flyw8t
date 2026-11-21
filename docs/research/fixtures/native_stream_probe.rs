//! Offline scheduling model for issue #53. Compile with rustc --test.
//! All pixels and times are synthetic. There is no OS capture or transport.
#![cfg(test)]

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct Frame {
    captured_ms: u32,
    pixels: [u8; 4],
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct Grant(u64);

#[derive(Default)]
struct Pipeline {
    generation: u64,
    active: Option<Grant>,
    pending: Option<Frame>,
}

impl Pipeline {
    fn grant(&mut self) -> Grant {
        assert!(self.active.is_none());
        self.generation = self.generation.checked_add(1).unwrap();
        let grant = Grant(self.generation);
        self.active = Some(grant);
        grant
    }

    fn offer(&mut self, grant: Grant, frame: Frame) -> bool {
        if self.active != Some(grant) {
            return false;
        }
        self.pending = Some(frame);
        true
    }

    fn take(&mut self, grant: Grant) -> Option<Frame> {
        if self.active != Some(grant) {
            return None;
        }
        self.pending.take()
    }

    fn stop(&mut self) {
        self.active = None;
        self.pending = None;
    }
}

fn tile(id: u8, captured_ms: u32) -> Frame {
    Frame {
        captured_ms,
        pixels: [id, 0, 0, 255],
    }
}

#[test]
fn slow_consumer_gets_latest_pixels_and_original_capture_time() {
    let mut pipe = Pipeline::default();
    let grant = pipe.grant();
    for (id, ms) in [(1, 0), (2, 16), (3, 33)] {
        assert!(pipe.offer(grant, tile(id, ms)));
    }
    let frame = pipe.take(grant).unwrap();
    assert_eq!(frame.pixels, [3, 0, 0, 255]);
    assert_eq!(40 - frame.captured_ms, 7);
    assert_eq!(pipe.take(grant), None);
}

#[test]
fn revoke_before_first_frame_rejects_late_completion() {
    let mut pipe = Pipeline::default();
    let old = pipe.grant();
    pipe.stop();
    assert!(!pipe.offer(old, tile(1, 0)));
    assert_eq!(pipe.take(old), None);
}

#[test]
fn stop_flushes_buffer_and_old_callbacks_cannot_touch_new_session() {
    let mut pipe = Pipeline::default();
    let old = pipe.grant();
    assert!(pipe.offer(old, tile(1, 0)));
    pipe.stop();
    pipe.stop();
    let new = pipe.grant();
    assert_eq!(pipe.take(new), None);
    assert!(pipe.offer(new, tile(2, 16)));
    assert!(!pipe.offer(old, tile(3, 17)));
    assert_eq!(pipe.take(old), None);
    assert_eq!(pipe.take(new), Some(tile(2, 16)));
}
