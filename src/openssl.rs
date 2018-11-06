use libc::{c_void, c_uchar, c_int, c_uint, c_long, c_longlong, size_t};

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
    a: c_long, b: c_long, c: c_long, d: c_long,
    nl: c_long, nh: c_long,
    data: [c_long; MD5_LBLOCK],
    num: c_uint,
}

// int MD5_Init(MD5_CTX *c);
// int MD5_Update(MD5_CTX *c, const void *data, size_t len);
// int MD5_Final(unsigned char *md, MD5_CTX *c);

#[link(kind = "static", name = "crypto")]
extern {
    fn MD5_Init(ctx: *mut MD5_CTX) -> c_int;
    fn MD5_Update(ctx: *mut MD5_CTX,
                  data: *const c_void, len: size_t) -> c_int;
    fn MD5_Final(md: *mut [c_uchar; MD5_DIGEST_LENGTH],
                 ctx: *mut MD5_CTX) -> c_int;
}

// # define SHA_LBLOCK      16
// # define SHA256_DIGEST_LENGTH    32

const SHA_LBLOCK: usize = 16;
const SHA256_DIGEST_LENGTH: usize = 32;

// typedef struct SHA256state_st {
//     SHA_LONG h[8];
//     SHA_LONG Nl, Nh;
//     SHA_LONG data[SHA_LBLOCK];
//     unsigned int num, md_len;
// } SHA256_CTX;

#[repr(C)]
pub struct SHA256_CTX {
    h: [c_long; 8],
    nl: c_long, nh: c_long,
    data: [c_long; SHA_LBLOCK],
    num: c_uint, md_len: c_uint,
}

// int SHA256_Init(SHA256_CTX *c);
// int SHA256_Update(SHA256_CTX *c, const void *data, size_t len);
// int SHA256_Final(unsigned char *md, SHA256_CTX *c);

#[link(kind = "static", name = "crypto")]
extern {
    fn SHA256_Init(ctx: *mut SHA256_CTX) -> c_int;
    fn SHA256_Update(ctx: *mut SHA256_CTX,
                     data: *const c_void, len: size_t) -> c_int;
    fn SHA256_Final(md: *mut [c_uchar; SHA256_DIGEST_LENGTH],
                    ctx: *mut SHA256_CTX) -> c_int;
}

// # define SHA512_DIGEST_LENGTH    64
// #  define SHA512_CBLOCK   (SHA_LBLOCK*8)

const SHA512_DIGEST_LENGTH: usize = 64;
const SHA512_CBLOCK: usize = SHA_LBLOCK * 8;

// typedef struct SHA512state_st {
//     SHA_LONG64 h[8];
//     SHA_LONG64 Nl, Nh;
//     union {
//         SHA_LONG64 d[SHA_LBLOCK];
//         unsigned char p[SHA512_CBLOCK];
//     } u;
//     unsigned int num, md_len;
// } SHA512_CTX;

#[repr(C)]
union SHA512_CTX_U {
    d: [c_longlong; SHA_LBLOCK],
    p: [c_uchar; SHA512_CBLOCK],
}
#[repr(C)]
pub struct SHA512_CTX {
    h: [c_longlong; 8],
    nl: c_longlong, nh: c_longlong,
    u: SHA512_CTX_U,
    num: c_uint, md_len: c_uint,
}

// int SHA512_Init(SHA512_CTX *c);
// int SHA512_Update(SHA512_CTX *c, const void *data, size_t len);
// int SHA512_Final(unsigned char *md, SHA512_CTX *c);

#[link(kind = "static", name = "crypto")]
extern {
    fn SHA512_Init(ctx: *mut SHA512_CTX) -> c_int;
    fn SHA512_Update(ctx: *mut SHA512_CTX,
                     data: *const c_void, len: size_t) -> c_int;
    fn SHA512_Final(md: *mut [c_uchar; SHA512_DIGEST_LENGTH],
                    ctx: *mut SHA512_CTX) -> c_int;
}

fn data_to_void_ptr(data: &[u8]) -> *const c_void {
    data as *const _ as *const c_void
}

#[cfg(test)]
mod c_tests {
    use super::*;
    use super::super::digest::Digest::{MD5, SHA256, SHA512};
    use super::super::digest::test_digests::*;

    #[test]
    fn md5() {
        let mut ctx = MD5_CTX {
            a: 0, b: 0, c: 0, d: 0,
            nl: 0, nh: 0,
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

    #[test]
    fn sha256() {
        let mut ctx = SHA256_CTX {
            h: [0; 8],
            nl: 0, nh: 0,
            data: [0; SHA_LBLOCK],
            num: 0, md_len: 0,
        };
        let mut digest = [0u8; SHA256_DIGEST_LENGTH];
        let data = [0u8; 0x400d];
        let data_ptr = data_to_void_ptr(&data);

        unsafe {
            assert_eq!(SHA256_Init(&mut ctx), 1);
            assert_eq!(SHA256_Update(&mut ctx, data_ptr, 0x400d), 1);
            assert_eq!(SHA256_Final(&mut digest, &mut ctx), 1);
        }

        assert_eq!(SHA256(digest), SHA256_ZERO_400D);
    }

    #[test]
    fn sha512() {
        let mut ctx = SHA512_CTX {
            h: [0; 8],
            nl: 0, nh: 0,
            u: SHA512_CTX_U { d: [0; SHA_LBLOCK] },
            num: 0, md_len: 0,
        };
        let mut digest = [0u8; SHA512_DIGEST_LENGTH];
        let data = [0u8; 0x400d];
        let data_ptr = data_to_void_ptr(&data);

        unsafe {
            assert_eq!(SHA512_Init(&mut ctx), 1);
            assert_eq!(SHA512_Update(&mut ctx, data_ptr, 0x400d), 1);
            assert_eq!(SHA512_Final(&mut digest, &mut ctx), 1);
        }

        assert_eq!(SHA512(digest), SHA512_ZERO_400D);
    }
}

impl MD5_CTX {
    pub fn new() -> MD5_CTX {
        let mut ctx = MD5_CTX {
            a: 0, b: 0, c: 0, d: 0,
            nl: 0, nh: 0,
            data: [0; MD5_LBLOCK],
            num: 0
        };
        ctx.reset();
        ctx
    }

    pub fn reset(&mut self) {
        unsafe { MD5_Init(self) };
    }

    pub fn update(&mut self, data: &[u8]) {
        let len = data.len() as size_t;
        let data_ptr = data_to_void_ptr(&data);
        unsafe { MD5_Update(self, data_ptr, len) };
    }

    pub fn result(&mut self) -> [u8; MD5_DIGEST_LENGTH] {
        let mut digest = [0u8; MD5_DIGEST_LENGTH];
        unsafe { MD5_Final(&mut digest, self) };
        digest
    }
}

impl SHA256_CTX {
    pub fn new() -> SHA256_CTX {
        let mut ctx = SHA256_CTX {
            h: [0; 8],
            nl: 0, nh: 0,
            data: [0; SHA_LBLOCK],
            num: 0, md_len: 0
        };
        ctx.reset();
        ctx
    }

    pub fn reset(&mut self) {
        unsafe { SHA256_Init(self) };
    }

    pub fn update(&mut self, data: &[u8]) {
        let len = data.len() as size_t;
        let data_ptr = data_to_void_ptr(&data);
        unsafe { SHA256_Update(self, data_ptr, len) };
    }

    pub fn result(&mut self) -> [u8; SHA256_DIGEST_LENGTH] {
        let mut digest = [0u8; SHA256_DIGEST_LENGTH];
        unsafe { SHA256_Final(&mut digest, self) };
        digest
    }
}

impl SHA512_CTX {
    pub fn new() -> SHA512_CTX {
        let mut ctx = SHA512_CTX {
            h: [0; 8],
            nl: 0, nh: 0,
            u: SHA512_CTX_U { d: [0; SHA_LBLOCK] },
            num: 0, md_len: 0,
        };
        ctx.reset();
        ctx
    }

    pub fn reset(&mut self) {
        unsafe { SHA512_Init(self) };
    }

    pub fn update(&mut self, data: &[u8]) {
        let len = data.len() as size_t;
        let data_ptr = data_to_void_ptr(&data);
        unsafe { SHA512_Update(self, data_ptr, len) };
    }

    pub fn result(&mut self) -> [u8; SHA512_DIGEST_LENGTH] {
        let mut digest = [0u8; SHA512_DIGEST_LENGTH];
        unsafe { SHA512_Final(&mut digest, self) };
        digest
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use super::super::digest::Digest::{MD5, SHA256, SHA512};
    use super::super::digest::test_digests::*;

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

    #[test]
    fn sha256() {
        let mut ctx = SHA256_CTX::new();

        let digest = ctx.result();

        assert_eq!(SHA256(digest), SHA256_ZERO_EMPTY);

        ctx.reset();

        let data = [0u8; 0x4000];
        ctx.update(&data);
        let data = [0u8; 0x0d];
        ctx.update(&data);

        let digest = ctx.result();

        assert_eq!(SHA256(digest), SHA256_ZERO_400D);

        ctx.reset();

        let digest = ctx.result();

        assert_eq!(SHA256(digest), SHA256_ZERO_EMPTY);
    }

    #[test]
    fn sha512() {
        let mut ctx = SHA512_CTX::new();

        let digest = ctx.result();

        assert_eq!(SHA512(digest), SHA512_ZERO_EMPTY);

        ctx.reset();

        let data = [0u8; 0x4000];
        ctx.update(&data);
        let data = [0u8; 0x0d];
        ctx.update(&data);

        let digest = ctx.result();

        assert_eq!(SHA512(digest), SHA512_ZERO_400D);

        ctx.reset();

        let digest = ctx.result();

        assert_eq!(SHA512(digest), SHA512_ZERO_EMPTY);
    }
}

