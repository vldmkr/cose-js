const cose = require('../');
const { secp256k1 } = require('@noble/curves/secp256k1');

async function run () {
  let COSEMessage;
  const priv = secp256k1.utils.randomPrivateKey();
  const pubkey = secp256k1.getPublicKey(priv);
  try {
    const plaintext = 'Important message!';
    const headers = {
      p: { alg: 'ES256K' }
    };
    const signer = {
      key: {
        d: priv
      }
    };
    COSEMessage = await cose.sign.create(headers, Buffer.from(plaintext), signer);
    console.log('Public key: ' + Buffer.from(pubkey).toString('hex'));
    console.log('Signed message: ' + COSEMessage.toString('hex'));
  } catch (error) {
    console.log(error);
  }

  try {
    const verifier = {
      key: {
        raw: pubkey
      }
    };
    const buf = await cose.sign.verify(COSEMessage, verifier);
    console.log('Verified message: ' + buf.toString('utf8'));
  } catch (error) {
    console.log(error);
  }
}
run();
