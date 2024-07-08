const cose = require('../src');
const cbor = require('cbor');

async function run () {
  const msg = {
    timestamp: 1234567890,
    temperature: 23,
    humidity: 45
  };
  const COSEMessage = await cose.sign.createUnsigned({}, cbor.encodeCanonical(msg));
  console.log('Message: ' + COSEMessage.toString('hex'));
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
