use libc::c_void;

fn data_to_void_ptr(data: &[u8]) -> *const c_void {
    data as *const _ as *const c_void
}
