use libc::{c_int, c_uchar, c_uint, c_ulong, c_void, size_t};

// # define MD5_CBLOCK      64
// # define MD5_LBLOCK      (MD5_CBLOCK/4)
// # define MD5_DIGEST_LENGTH 16

const MD5_LBLOCK: usize = 16;
const MD5_DIGEST_LENGTH: usize = 16;

// typedef struct MD5state_st {
//     MD5_LONG A, B, C, D;
//     MD5_LONG Nl, Nh;
//     MD5_LONG data[MD5_LBLOCK];
//     unsigned int num;
// } MD5_CTX;

#[repr(C)]
pub struct MD5_CTX {
    a: c_ulong,
    b: c_ulong,
    c: c_ulong,
    d: c_ulong,
    nl: c_ulong,
    nh: c_ulong,
    data: [c_ulong; MD5_LBLOCK],
    num: c_uint,
}

// # define RIPEMD160_CBLOCK        64
// # define RIPEMD160_LBLOCK        (RIPEMD160_CBLOCK/4)
// # define RIPEMD160_DIGEST_LENGTH 20

const RIPEMD160_LBLOCK: usize = 16;
const RIPEMD160_DIGEST_LENGTH: usize = 20;

// typedef struct RIPEMD160state_st {
//     RIPEMD160_LONG A, B, C, D, E;
//     RIPEMD160_LONG Nl, Nh;
//     RIPEMD160_LONG data[RIPEMD160_LBLOCK];
//     unsigned int num;
// } RIPEMD160_CTX;

#[repr(C)]
pub struct RIPEMD160_CTX {
    a: c_ulong,
    b: c_ulong,
    c: c_ulong,
    d: c_ulong,
    e: c_ulong,
    nl: c_ulong,
    nh: c_ulong,
    data: [c_ulong; RIPEMD160_LBLOCK],
    num: c_uint,
}

// int MD5_Init(MD5_CTX *c);
// int MD5_Update(MD5_CTX *c, const void *data, size_t len);
// int MD5_Final(unsigned char *md, MD5_CTX *c);
//
// int RIPEMD160_Init(RIPEMD160_CTX *c);
// int RIPEMD160_Update(RIPEMD160_CTX *c, const void *data, size_t len);
// int RIPEMD160_Final(unsigned char *md, RIPEMD160_CTX *c);

#[allow(non_snake_case)]
unsafe fn MD5_Init(_ctx: *mut MD5_CTX) -> c_int {
    1
}

#[allow(non_snake_case)]
unsafe fn MD5_Update(
    _ctx: *mut MD5_CTX,
    _data: *const c_void,
    _len: size_t,
) -> c_int {
    1
}

#[allow(non_snake_case)]
unsafe fn MD5_Final(
    _md: *mut [c_uchar; MD5_DIGEST_LENGTH],
    _ctx: *mut MD5_CTX,
) -> c_int {
    1
}

#[allow(non_snake_case)]
unsafe fn RIPEMD160_Init(_ctx: *mut RIPEMD160_CTX) -> c_int {
    1
}

#[allow(non_snake_case)]
unsafe fn RIPEMD160_Update(
    _ctx: *mut RIPEMD160_CTX,
    _data: *const c_void,
    _len: size_t,
) -> c_int {
    1
}

#[allow(non_snake_case)]
unsafe fn RIPEMD160_Final(
    _md: *mut [c_uchar; RIPEMD160_DIGEST_LENGTH],
    _ctx: *mut RIPEMD160_CTX,
) -> c_int {
    1
}

fn data_to_void_ptr(data: &[u8]) -> *const c_void {
    data as *const _ as *const c_void
}

#[cfg(test)]
mod c_tests {
    use super::super::digest::test_digests::*;
    use super::super::digest::Digest::{MD5, RMD160};
    use super::*;

    #[ignore]
    #[test]
    fn md5() {
        let mut ctx = MD5_CTX {
            a: 0,
            b: 0,
            c: 0,
            d: 0,
            nl: 0,
            nh: 0,
            data: [0; MD5_LBLOCK],
            num: 0,
        };
        let mut digest = [0u8; MD5_DIGEST_LENGTH];
        let data = [0u8; 0x400d];
        let data_ptr = data_to_void_ptr(&data);

        unsafe {
            assert_eq!(MD5_Init(&mut ctx), 1);
            assert_eq!(MD5_Update(&mut ctx, data_ptr, 0x400d), 1);
            assert_eq!(MD5_Final(&mut digest, &mut ctx), 1);
        }

        assert_eq!(MD5(digest), MD5_ZERO_400D);
    }

    #[ignore]
    #[test]
    fn ripemd160() {
        let mut ctx = RIPEMD160_CTX {
            a: 0,
            b: 0,
            c: 0,
            d: 0,
            e: 0,
            nl: 0,
            nh: 0,
            data: [0; RIPEMD160_LBLOCK],
            num: 0,
        };
        let mut digest = [0u8; RIPEMD160_DIGEST_LENGTH];
        let data = [0u8; 0x400d];
        let data_ptr = data_to_void_ptr(&data);

        unsafe {
            assert_eq!(RIPEMD160_Init(&mut ctx), 1);
            assert_eq!(RIPEMD160_Update(&mut ctx, data_ptr, 0x400d), 1);
            assert_eq!(RIPEMD160_Final(&mut digest, &mut ctx), 1);
        }

        assert_eq!(RMD160(digest), RMD160_ZERO_400D);
    }
}

impl MD5_CTX {
    pub fn new() -> MD5_CTX {
        let mut ctx = MD5_CTX {
            a: 0,
            b: 0,
            c: 0,
            d: 0,
            nl: 0,
            nh: 0,
            data: [0; MD5_LBLOCK],
            num: 0,
        };
        ctx.reset();
        ctx
    }

    pub fn reset(&mut self) {
        unsafe { MD5_Init(self) };
    }

    pub fn update(&mut self, data: &[u8]) {
        let len = data.len() as size_t;
        let data_ptr = data_to_void_ptr(data);
        unsafe { MD5_Update(self, data_ptr, len) };
    }

    pub fn result(&mut self) -> [u8; MD5_DIGEST_LENGTH] {
        let mut digest = [0u8; MD5_DIGEST_LENGTH];
        unsafe { MD5_Final(&mut digest, self) };
        digest
    }
}

impl RIPEMD160_CTX {
    pub fn new() -> RIPEMD160_CTX {
        let mut ctx = RIPEMD160_CTX {
            a: 0,
            b: 0,
            c: 0,
            d: 0,
            e: 0,
            nl: 0,
            nh: 0,
            data: [0; RIPEMD160_LBLOCK],
            num: 0,
        };
        ctx.reset();
        ctx
    }

    pub fn reset(&mut self) {
        unsafe { RIPEMD160_Init(self) };
    }

    pub fn update(&mut self, data: &[u8]) {
        let len = data.len() as size_t;
        let data_ptr = data_to_void_ptr(data);
        unsafe { RIPEMD160_Update(self, data_ptr, len) };
    }

    pub fn result(&mut self) -> [u8; RIPEMD160_DIGEST_LENGTH] {
        let mut digest = [0u8; RIPEMD160_DIGEST_LENGTH];
        unsafe { RIPEMD160_Final(&mut digest, self) };
        digest
    }
}

#[cfg(test)]
mod tests {
    use super::super::digest::test_digests::*;
    use super::super::digest::Digest::{MD5, RMD160};
    use super::*;

    #[ignore]
    #[test]
    fn md5() {
        let mut ctx = MD5_CTX::new();

        let digest = ctx.result();

        assert_eq!(MD5(digest), MD5_ZERO_EMPTY);

        ctx.reset();

        let data = [0u8; 0x4000];
        ctx.update(&data);
        let data = [0u8; 0x0d];
        ctx.update(&data);

        let digest = ctx.result();

        assert_eq!(MD5(digest), MD5_ZERO_400D);

        ctx.reset();

        let digest = ctx.result();

        assert_eq!(MD5(digest), MD5_ZERO_EMPTY);
    }

    #[ignore]
    #[test]
    fn ripemd160() {
        let mut ctx = RIPEMD160_CTX::new();

        let digest = ctx.result();

        assert_eq!(RMD160(digest), RMD160_ZERO_EMPTY);

        ctx.reset();

        let data = [0u8; 0x4000];
        ctx.update(&data);
        let data = [0u8; 0x0d];
        ctx.update(&data);

        let digest = ctx.result();

        assert_eq!(RMD160(digest), RMD160_ZERO_400D);

        ctx.reset();

        let digest = ctx.result();

        assert_eq!(RMD160(digest), RMD160_ZERO_EMPTY);
    }
}
