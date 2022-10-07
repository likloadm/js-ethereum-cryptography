import * as secp256k1 from "secp256k1";
var arldilithium = require('./module');


if (!arldilithium.cwrap)
  arldilithium = arldilithium.Module

var generate_key_pair = arldilithium.cwrap('PQCLEAN_DILITHIUM3_CLEAN_crypto_sign_keypair', 'number', ['number', 'number', 'number']) ;
var crypto_priv_to_pub = arldilithium.cwrap('crypto_priv_to_pub', 'number', ['number', 'number', 'number']) ;
var sign_signature = arldilithium.cwrap('PQCLEAN_DILITHIUM3_CLEAN_crypto_sign_signature',
      'number', // return type
      ['number', 'number', 'number','number','number','number']);

var verify_signature = arldilithium.cwrap('PQCLEAN_DILITHIUM3_CLEAN_crypto_sign_verify',
      'number', // return type
      ['number', 'number', 'number','number','number']);

function generateKeypair(derivedKey: Buffer)
{
	    var dataPtr1 = arldilithium._malloc(1952);
	    var dataPtr2 = arldilithium._malloc(4000);
	    var dataPtr3 = arldilithium._malloc(32);

	    var dataHeap1 = new Uint8Array(arldilithium.HEAPU8.buffer, dataPtr1, 1952);
	    var dataHeap2 = new Uint8Array(arldilithium.HEAPU8.buffer, dataPtr2, 4000);
	    var dataHeap3 = new Uint8Array(arldilithium.HEAPU8.buffer, dataPtr3, 32);

	    dataHeap3.set(derivedKey);
	    generate_key_pair(dataHeap1.byteOffset,dataHeap2.byteOffset,dataHeap3.byteOffset);

	    var pubkey = new Uint8Array(dataHeap1.buffer, dataHeap1.byteOffset, 1952);
	    var privkey = new Uint8Array(dataHeap2.buffer, dataHeap2.byteOffset, 4000);

	    var priv = new Uint8Array(privkey);
	    var pub = new Uint8Array(pubkey);

	    arldilithium._free(dataHeap1.byteOffset);
	    arldilithium._free(dataHeap2.byteOffset);
	    arldilithium._free(dataHeap3.byteOffset);

	    return [Buffer.from(priv), Buffer.from(pub)];
}

function privToPub(privateKey: Buffer)
{
	    var dataPtr1 = arldilithium._malloc(1952);
	    var dataPtr2 = arldilithium._malloc(4000);

	    var dataHeap1 = new Uint8Array(arldilithium.HEAPU8.buffer, dataPtr1, 1952);
	    var dataHeap2 = new Uint8Array(arldilithium.HEAPU8.buffer, dataPtr2, 4000);

	    dataHeap2.set(privateKey);
	    crypto_priv_to_pub(dataHeap2.byteOffset,dataHeap1.byteOffset);

	    var pubkey = new Uint8Array(dataHeap1.buffer, dataHeap1.byteOffset, 1952);

	    var pub = new Uint8Array(pubkey);

	    arldilithium._free(dataHeap1.byteOffset);
	    arldilithium._free(dataHeap2.byteOffset);

	    return Buffer.from(pub);
}

function signDilithium(privk: Buffer, mess: Buffer) {
	    var message = mess

	    var dataPtr1 = arldilithium._malloc(3293);
	    var dataPtr2 = arldilithium._malloc(4000);
	    var dataPtr3 = arldilithium._malloc(message.length);
	    var dataPtr4 = arldilithium._malloc(4);

	    var dataHeap1 = new Uint8Array(arldilithium.HEAPU8.buffer, dataPtr1, 3293);
	    var dataHeap2 = new Uint8Array(arldilithium.HEAPU8.buffer, dataPtr2, 4000);
	    var dataHeap3 = new Uint8Array(arldilithium.HEAPU8.buffer, dataPtr3, message.length);
	    var dataHeap4 = new Uint32Array(arldilithium.HEAPU8.buffer, dataPtr4, 1);

	    dataHeap2.set(privk);
	    dataHeap3.set(message);

	    sign_signature(dataHeap1.byteOffset,dataHeap4.byteOffset, dataHeap3.byteOffset, message.length, dataHeap2.byteOffset);


      var sig = new Uint8Array(dataHeap1.buffer, dataHeap1.byteOffset, dataHeap4[0]);

	    var signature = new Uint8Array(sig);

	    arldilithium._free(dataHeap1.byteOffset);
	    arldilithium._free(dataHeap2.byteOffset);
	    arldilithium._free(dataHeap3.byteOffset);
	    arldilithium._free(dataHeap4.byteOffset);
	    return Buffer.from(sig);
}

export function privateKeyVerify(privateKey: Buffer): boolean {
  return secp256k1.privateKeyVerify(privateKey);
}

export function publicKeyCreate(privateKey: Buffer, compressed = true): Buffer {
  return Buffer.from(privToPub(privateKey));
}

export function publicKeyVerify(publicKey: Buffer): boolean {
  return secp256k1.publicKeyVerify(publicKey);
}

export function publicKeyConvert(publicKey: Buffer, compressed = true): Buffer {
  return Buffer.from(secp256k1.publicKeyConvert(publicKey, compressed));
}

export function privateKeyTweakAdd(publicKey: Buffer, tweak: Buffer): Buffer {
  return Buffer.from(
    secp256k1.privateKeyTweakAdd(Buffer.from(publicKey), tweak)
  );
}

export function publicKeyTweakAdd(
  publicKey: Buffer,
  tweak: Buffer,
  compressed = true
): Buffer {
  return Buffer.from(
    secp256k1.publicKeyTweakAdd(Buffer.from(publicKey), tweak, compressed)
  );
}

export function sign(
  message: Buffer,
  privateKey: Buffer
): { signature: Buffer} {
  const ret = signDilithium(privateKey, message);
  return { signature: Buffer.from(ret)};
}

export function verify(
  message: Buffer,
  signature: Buffer,
  publicKey: Buffer
): boolean {
  return secp256k1.ecdsaVerify(signature, message, publicKey);
}
