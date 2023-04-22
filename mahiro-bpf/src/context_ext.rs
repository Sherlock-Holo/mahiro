use core::mem::size_of;

use aya_bpf::programs::TcContext;

pub trait ContextExt {
    fn load_ptr<T>(&self, offset: usize) -> Option<&mut T>;
}

impl ContextExt for TcContext {
    fn load_ptr<T>(&self, offset: usize) -> Option<&mut T> {
        let start = self.data() + offset;
        if start + size_of::<T>() > self.data_end() {
            return None;
        }

        let ptr = start as *mut T;

        Some(unsafe { &mut *ptr })
    }
}
