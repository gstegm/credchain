/// inspirational sources:
/// https://docs.zama.ai/tfhe-rs/fhe-computation/advanced-features/public_key
/// https://docs.zama.ai/tfhe-rs/fhe-computation/data-handling/serialization
/// https://napi.rs/docs/concepts/values
/// https://www.youtube.com/watch?v=LLxfmrrl4cE

/// import the preludes
use napi::bindgen_prelude::*;
use napi_derive::napi;
use tfhe::{generate_keys, set_server_key, ClientKey, ConfigBuilder, FheInt64, FheBool, ServerKey, CompressedServerKey};
use tfhe::prelude::*;
use tfhe::safe_serialization::{safe_serialize, safe_deserialize};
use tfhe::PublicKey;
use std::time::Instant;

/// module registration is done by the runtime, no need to explicitly do it now.
/// run $napi build
#[napi]
fn getkeys() -> Vec<Buffer> {
    let config = ConfigBuilder::default().build();

    let (client_key, server_key) = generate_keys(config);
    //let client_key= ClientKey::generate(config);
    //let server_key = CompressedServerKey::new(&client_key);
    let public_key = PublicKey::new(&client_key);

    let mut client_key_ser = vec![];
    safe_serialize(&client_key, &mut client_key_ser, 1 << 30).unwrap();
    let mut server_key_ser = vec![];
    safe_serialize(&server_key, &mut server_key_ser, 1 << 30).unwrap();
    let mut public_key_ser = vec![];
    safe_serialize(&public_key, &mut public_key_ser, 1 << 40).unwrap();

    return vec![client_key_ser.into(), server_key_ser.into(), public_key_ser.into()];
}

#[napi]
fn enc(plain: i64, client_key_ser:Buffer) -> Buffer {
    println!("starting deserialization");
    let client_key_ser: Vec<u8> = client_key_ser.into();
    let client_key: ClientKey = safe_deserialize(client_key_ser.as_slice(), 1 << 30).unwrap();
    println!("ending deserialization");
   
    let cipher = FheInt64::encrypt(plain, &client_key);
    let mut cipher_ser = vec![];
    safe_serialize(&cipher, &mut cipher_ser, 1 << 20).unwrap();

    return cipher_ser.into();
}

#[napi]
fn encpub(plain: i64, public_key_ser:Buffer) -> Buffer {
    let public_key_ser: Vec<u8> = public_key_ser.into();
    let public_key: PublicKey = safe_deserialize(public_key_ser.as_slice(), 1 << 40).unwrap();
   
    let cipher = FheInt64::encrypt(plain, &public_key);
    let mut cipher_ser = vec![];
    safe_serialize(&cipher, &mut cipher_ser, 1 << 20).unwrap();

    return cipher_ser.into();
}

#[napi]
fn gt(cipher_a_ser: Buffer, cipher_b_ser: Buffer, server_key_ser:Buffer) -> Buffer {
    let server_key_ser: Vec<u8> = server_key_ser.into();
    let cipher_a_ser: Vec<u8> = cipher_a_ser.into();
    let cipher_b_ser: Vec<u8> = cipher_b_ser.into();
    //let server_key: CompressedServerKey = safe_deserialize(server_key_ser.as_slice(), 1 << 30).unwrap();
    let server_key: ServerKey = safe_deserialize(server_key_ser.as_slice(), 1 << 30).unwrap();
    let cipher_a: FheInt64 = safe_deserialize(cipher_a_ser.as_slice(), 1 << 20).unwrap();
    let cipher_b: FheInt64 = safe_deserialize(cipher_b_ser.as_slice(), 1 << 20).unwrap();

    //let gpu_key = server_key.decompress_to_gpu();
    //set_server_key(gpu_key);
    set_server_key(server_key);

    let now = Instant::now();
    let gtresult = cipher_a.gt(cipher_b.clone());
    let elapsed = now.elapsed();
    println!("Elapsed: {:.2?}", elapsed);
    let mut gtresult_ser = vec![];
    safe_serialize(&gtresult, &mut gtresult_ser, 1 << 20).unwrap();

    return gtresult_ser.into();
}

#[napi]
fn dec(cipher_ser: Buffer, client_key_ser:Buffer) -> bool {
    let client_key_ser: Vec<u8> = client_key_ser.into();
    let cipher_ser: Vec<u8> = cipher_ser.into();

    let client_key: ClientKey = safe_deserialize(client_key_ser.as_slice(), 1 << 30).unwrap();
    let cipher: FheBool = safe_deserialize(cipher_ser.as_slice(), 1 << 20).unwrap();
       
    let plain: bool = cipher.decrypt(&client_key);
    return plain;
}