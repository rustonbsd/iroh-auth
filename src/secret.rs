use secrecy::SecretSlice;


pub trait IntoSecret {
    fn into_secret(self) -> SecretSlice<u8>;
}

impl IntoSecret for SecretSlice<u8> {
    fn into_secret(self) -> SecretSlice<u8> {
        self
    }
}

impl IntoSecret for String {
    fn into_secret(self) -> SecretSlice<u8> {
        SecretSlice::new(self.into_bytes().into_boxed_slice())
    }
}

impl IntoSecret for &str {
    fn into_secret(self) -> SecretSlice<u8> {
        SecretSlice::new(self.as_bytes().to_vec().into_boxed_slice())
    }
}

impl IntoSecret for Vec<u8> {
    fn into_secret(self) -> SecretSlice<u8> {
        SecretSlice::new(self.into_boxed_slice())
    }
}

impl IntoSecret for &[u8] {
    fn into_secret(self) -> SecretSlice<u8> {
        SecretSlice::new(self.to_vec().into_boxed_slice())
    }
}

impl<const N: usize> IntoSecret for &[u8; N] {
    fn into_secret(self) -> SecretSlice<u8> {
        SecretSlice::new(self.as_slice().to_vec().into_boxed_slice())
    }
}

impl IntoSecret for Box<[u8]> {
    fn into_secret(self) -> SecretSlice<u8> {
        SecretSlice::new(self)
    }
}

