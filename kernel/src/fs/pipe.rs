// use super::File;
pub struct Pipe {

}

impl Pipe {
    pub fn read(&self, addr: usize, buf: &mut [u8]) -> Result<usize, &'static str> {
        Err("No implement")
    }

    pub fn write(&self, addr: usize, buf: &[u8]) -> Result<usize, &'static str> {
        Err("No implement")
    }

    pub fn readable(&self) -> bool {
        false
    }

    pub fn writeable(&self) -> bool {
        false
    }
}