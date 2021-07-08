use crate::define::fs::NDIRECT;
use alloc::boxed::Box;
use alloc::string::String;

/// In-memory copy of an inode
#[repr(C)]
#[derive(Clone, Copy)]
pub struct Inode {
    dev: usize, // device id
    inum: usize, // Inode number
    file_ref: usize, // Reference count
    vaild: usize, // inode has been read from disk

    file_type: u16, // copy of disk inode
    major: u16,
    minor: u16,
    nlink: u16,
    size: usize,
    addrs: [usize;NDIRECT+1]
}

impl Inode {
    /// Allocate an inode on device dev. 
    /// Mark it as allocated by giving it type type. 
    /// Returns an unlocked but allocated and referenced inode. 
    pub(crate) fn alloc(dev: u32, file_type: u16) -> Option<&'static mut Inode> {
        None
    }


    /// Copy a modified in-memory inode to disk
    /// Must be called after every change to an ip->xxx field
    /// that lives on disk. 
    /// Caller must hold ip->lock
    pub(crate) fn update(&self) {

    }

    /// Find the inode with number inum on device dev
    /// and return th in-memory copy. Does not lock
    /// the inode and does not read it from disk. 
    pub(crate) fn get(dev: u32, inum: u32) -> Option<&'static mut Inode> {
        None
    }


    /// Increment reference count for ip. 
    /// Returns ip to enable ip = idup(ip1) idinum
    pub(crate) fn dup(&mut self) {

    } 

    /// Lock the given inode. 
    /// Reads the inode from disk if necessary. 
    pub(crate) fn lock(&self) {

    }

    /// Unlock the given inode. 
    pub(crate) fn unlock(&self) {

    }

    /// Drop a reference to an im-memory inode. 
    /// If that was the last reference, the inode table entry can
    /// be recycled. 
    /// If that was the last reference and the inode has no links
    /// to it, free the inode (and its content) on disk. 
    /// All calls to put() must be inside a transaction in
    /// case it has to free the inode. 
    pub(crate) fn put(&self) {

    }

    /// Inode content
    /// 
    /// The content (data) associated with each inode is stored
    /// in blocks on the disk. The first NDIRECT block numbers
    /// are listed in ip->address. The next NINDIRECT blocks are
    /// listed in block ip.addr[NDIRECT]. 
    /// 
    /// Return the disk block address of the nth block in inode ip. 
    /// If there is no such block, bmap allocates one. 
    pub(crate) fn map(&mut self, bn: usize) -> usize {
        panic!("inode map: out of range.")
    }

    /// Truncate inode (discard contents)
    /// Caller must hold ip.lock 
    pub(crate) fn trunc(&mut self) {

    }

    /// Copy stat information from inode. 
    /// Caller must hold ip->lock. 
    pub(crate) fn stat(&mut self, st: &super::stat::Stat) {

    }


    /// Read data from inode.
    /// Caller must hold ip->lock.
    /// If user_dst==1, then dst is a user virtual address;
    /// otherwise, dst is a kernel address.
    pub(crate) fn read(
        &self, 
        user_dst: usize, 
        dst: usize, 
        off: u32, 
        len: usize
    ) -> Result<usize, &'static str>{
        Ok(0)
    }

    /// Write data to inode. 
    /// Caller must hold ip->lock. 
    /// If user_dst == 1, then src is a user virtual address;
    /// otherwise, src is a kernel address. 
    /// Returns the number of bytes successfully written. 
    /// If the return value is less than the requested n, 
    /// there was an error of some kind.
    pub(crate) fn write(
        &mut self,
        user_dst: usize,
        dst: usize,
        off: u32,
        buf: &[u8]
    ) {

    }

    /// Look up and return the inode for a path name.
    /// If parent != 0, return the inode for the parent and copy the final
    /// path element into name, which must have room for DIRSIZ bytes.
    /// Must be called inside a transaction since it calls iput().
    pub(crate) fn namex(path: &str, nameiparent: isize, name: String) -> Option<Box<Self>> {
        None
    }

    pub fn namei(path: &str) -> Option<Box<Self>> {
        let name:String = String::new();
        Self::namex(path, 0, name)
    }

    pub fn nameiparent(path: &str, name: &str) -> Option<Box<Self>> {
        Self::namex(path, 1, String::from(name))
    }



    
}