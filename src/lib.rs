/// inspirational sources:
/// https://docs.zama.ai/tfhe-rs/fhe-computation/advanced-features/public_key
/// https://docs.zama.ai/tfhe-rs/fhe-computation/data-handling/serialization
/// https://napi.rs/docs/concepts/values
/// https://www.youtube.com/watch?v=LLxfmrrl4cE

use napi_derive::napi;
use tfhe::prelude::*;
use tfhe::safe_serialization::{safe_serialize, safe_deserialize};
use tfhe::{set_server_key, ClientKey, ConfigBuilder, FheInt64, FheBool, CompressedPublicKey, CompressedServerKey};

#[napi]
fn get_keys() -> Vec<Vec<u8>> {
    let config = ConfigBuilder::default().build();
    let client_key= ClientKey::generate(config);
    let compressed_server_key = CompressedServerKey::new(&client_key);
    let compressed_public_key = CompressedPublicKey::new(&client_key);

    let mut client_key_ser = vec![];
    safe_serialize(&client_key, &mut client_key_ser, 1 << 30).unwrap();
    let mut compressed_server_key_ser = vec![];
    safe_serialize(&compressed_server_key, &mut compressed_server_key_ser, 1 << 30).unwrap();
    let mut compressed_public_key_ser = vec![];
    safe_serialize(&compressed_public_key, &mut compressed_public_key_ser, 1 << 30).unwrap();

    return vec![client_key_ser, compressed_server_key_ser, compressed_public_key_ser];
}

#[napi]
fn encrypt(plain: i64, client_key_ser:Vec<u8>) -> Vec<u8> {
    let client_key: ClientKey = safe_deserialize(client_key_ser.as_slice(), 1 << 30).unwrap();
    let cipher = FheInt64::encrypt(plain, &client_key);
    let mut cipher_ser = vec![];
    safe_serialize(&cipher, &mut cipher_ser, 1 << 20).unwrap();

    return cipher_ser;
}

#[napi]
fn encrypt_public_key(plain: i64, compressed_public_key_ser:Vec<u8>) -> Vec<u8> {
    let compressed_public_key: CompressedPublicKey = safe_deserialize(compressed_public_key_ser.as_slice(), 1 << 30).unwrap();
    let public_key = compressed_public_key.decompress();
   
    let cipher = FheInt64::encrypt(plain, &public_key);
    let mut cipher_ser = vec![];
    safe_serialize(&cipher, &mut cipher_ser, 1 << 20).unwrap();
    return cipher_ser;
}

#[napi]
fn encrypt_bool_public_key(plain: bool, compressed_public_key_ser:Vec<u8>) -> Vec<u8> {
    let compressed_public_key_ser: Vec<u8> = compressed_public_key_ser;
    let compressed_public_key: CompressedPublicKey = safe_deserialize(compressed_public_key_ser.as_slice(), 1 << 30).unwrap();
    let public_key = compressed_public_key.decompress();
   
    let cipher = FheBool::encrypt(plain, &public_key);
    let mut cipher_ser = vec![];
    safe_serialize(&cipher, &mut cipher_ser, 1 << 20).unwrap();
    return cipher_ser;
}

#[napi]
fn greater_than(cipher_a_ser: Vec<u8>, cipher_b_ser: Vec<u8>, compressed_server_key_ser:Vec<u8>) -> Vec<u8> {
    let compressed_server_key: CompressedServerKey = safe_deserialize(compressed_server_key_ser.as_slice(), 1 << 30).unwrap();
    let cipher_a: FheInt64 = safe_deserialize(cipher_a_ser.as_slice(), 1 << 20).unwrap();
    let cipher_b: FheInt64 = safe_deserialize(cipher_b_ser.as_slice(), 1 << 20).unwrap();

    //let gpu_key = compressed_server_key.decompress_to_gpu();
    let server_key = compressed_server_key.decompress();
    //set_server_key(gpu_key);
    set_server_key(server_key);

    let gtresult = cipher_a.gt(cipher_b.clone());
    let mut gtresult_ser = vec![];
    safe_serialize(&gtresult, &mut gtresult_ser, 1 << 20).unwrap();

    return gtresult_ser;
}

#[napi]
fn flip_bit(cipher_a_ser: Vec<u8>, compressed_server_key_ser:Vec<u8>) -> Vec<u8> {
    let compressed_server_key: CompressedServerKey = safe_deserialize(compressed_server_key_ser.as_slice(), 1 << 30).unwrap();
    let cipher_a: FheBool = safe_deserialize(cipher_a_ser.as_slice(), 1 << 20).unwrap();

    //let gpu_key = compressed_server_key.decompress_to_gpu();
    let server_key = compressed_server_key.decompress();
    //set_server_key(gpu_key);
    set_server_key(server_key);

    let flipresult = !cipher_a;
    let mut flipresult_ser = vec![];
    safe_serialize(&flipresult, &mut flipresult_ser, 1 << 20).unwrap();

    return flipresult_ser;
}

#[napi]
fn decrypt(cipher_ser: Vec<u8>, client_key_ser:Vec<u8>) -> bool {
    let client_key: ClientKey = safe_deserialize(client_key_ser.as_slice(), 1 << 30).unwrap();
    let cipher: FheBool = safe_deserialize(cipher_ser.as_slice(), 1 << 20).unwrap();
    let plain: bool = cipher.decrypt(&client_key);
    return plain;
}