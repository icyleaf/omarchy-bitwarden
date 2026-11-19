use std::io;
use std::sync::{Arc, Mutex};

use super::provider::ClipboardProvider;

#[derive(Debug, Default, Clone)]
struct MockState {
    last_copied: Option<String>,
    sensitive: bool,
    cleared: bool,
    available: bool,
    monitors: bool,
    copy_count: usize,
    clear_count: usize,
}

/// An in-memory clipboard provider for deterministic unit and integration tests.
#[derive(Debug, Clone)]
pub struct MockClipboardProvider {
    state: Arc<Mutex<MockState>>,
}

impl Default for MockClipboardProvider {
    fn default() -> Self {
        Self::new()
    }
}

impl MockClipboardProvider {
    pub fn new() -> Self {
        Self {
            state: Arc::new(Mutex::new(MockState {
                last_copied: None,
                sensitive: false,
                cleared: false,
                available: true,
                monitors: false,
                copy_count: 0,
                clear_count: 0,
            })),
        }
    }

    pub fn last_copied(&self) -> Option<String> {
        self.state.lock().unwrap().last_copied.clone()
    }

    pub fn is_sensitive(&self) -> bool {
        self.state.lock().unwrap().sensitive
    }

    pub fn was_cleared(&self) -> bool {
        self.state.lock().unwrap().cleared
    }

    pub fn copy_count(&self) -> usize {
        self.state.lock().unwrap().copy_count
    }

    pub fn clear_count(&self) -> usize {
        self.state.lock().unwrap().clear_count
    }

    pub fn set_available(&self, available: bool) {
        self.state.lock().unwrap().available = available;
    }

    pub fn set_monitors(&self, monitors: bool) {
        self.state.lock().unwrap().monitors = monitors;
    }
}

impl ClipboardProvider for MockClipboardProvider {
    fn name(&self) -> &'static str {
        "mock"
    }

    fn is_available(&self) -> bool {
        self.state.lock().unwrap().available
    }

    fn monitors_selection(&self) -> bool {
        self.state.lock().unwrap().monitors
    }

    fn copy(&self, text: &str, sensitive: bool) -> io::Result<()> {
        let mut st = self.state.lock().unwrap();
        if !st.available {
            return Err(io::Error::other("Mock clipboard is unavailable"));
        }
        st.last_copied = Some(text.to_string());
        st.sensitive = sensitive;
        st.cleared = false;
        st.copy_count += 1;
        Ok(())
    }

    fn clear(&self) -> io::Result<()> {
        let mut st = self.state.lock().unwrap();
        if !st.available {
            return Err(io::Error::other("Mock clipboard is unavailable"));
        }
        st.last_copied = None;
        st.cleared = true;
        st.clear_count += 1;
        Ok(())
    }
}
