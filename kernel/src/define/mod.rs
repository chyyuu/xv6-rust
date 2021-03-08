use core::convert::From;

use crate::memory::address::Addr;

pub mod memlayout;
pub mod param;
pub mod virtio;


#[repr(C)]
#[derive(Copy, Clone, Eq, PartialEq)]
pub struct Address(usize);

impl Addr for Address{
    fn as_usize(&self) -> usize{
        self.0
    }
}

impl Address {
    pub const fn add_addr(&self, x:usize) -> Self {
        Self(self.0 + x)
    }

}

impl From<Address> for usize {
    fn from(addr: Address) -> Self{
        addr.0
    }
}