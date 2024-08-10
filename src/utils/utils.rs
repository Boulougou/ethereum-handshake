pub fn to_array<const N: usize>(slice: &[u8]) -> [u8; N] {
    let mut array = [0u8; N];
    if slice.len() != N {
        panic!("passed slice should be {N} bytes instead of {}", slice.len())
    }
    slice.iter().enumerate().for_each(|(i, x)| array[i] = *x);
    array
}

pub fn xor_slices<const N: usize>(left : [u8; N], right : [u8; N]) -> [u8; N] {
    let mut result = [0u8; N];
    for i in 0..N {
        result[i] = left[i] ^ right[i];
    }
    result
}
