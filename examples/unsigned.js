const cose = require('../');
const cbor = require('cbor');

async function run () {
  const COSEMessage = Buffer.from('d28440a05820a36474797065636c6f676974696d657374616d701a669fdeb2636d736762313940', 'hex');
  console.log('Signed message: ' + COSEMessage.toString('hex'));
  const pubkey = Buffer.from('39B029B5B6A1AE80CD9EBC38646BC0DA4243FF68512A306480E9816829BC04C3', 'hex');

  try {
    const verifier = {
      key: {
        raw: pubkey
      }
    };
    const buf = await cose.sign.verify(COSEMessage, verifier);
    console.log('Verified message: ' + buf.toString('utf8'));
  } catch (error) {
    if (error instanceof cose.common.ErrorWithValue) {
      console.log(error.message);
      const obj = await cbor.decodeFirst(error.value);
      console.log(obj);
    } else {
      console.log(error);
    }
  }
}
run();
