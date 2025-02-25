pub trait ToMessageBytes {
    fn to_message_bytes(&self) -> Vec<u8>;
}

impl<T: AsRef<[u8]>> ToMessageBytes for T {
    fn to_message_bytes(&self) -> Vec<u8> {
        self.as_ref().to_vec()
    }
}

impl ToMessageBytes for str {
    fn to_message_bytes(&self) -> Vec<u8> {
        self.as_bytes().to_vec()
    }
}
