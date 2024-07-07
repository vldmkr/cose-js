/* jshint esversion: 6 */
/* jslint node: true */
'use strict';

const cbor = require('cbor');
// const EC = require('elliptic').ec;
const crypto = require('crypto');
const NodeRSA = require('node-rsa');
const common = require('./common');
const { p256 } = require('@noble/curves/p256');
const { p384 } = require('@noble/curves/p384');
const { p521 } = require('@noble/curves/p521');
const { ed25519 } = require('@noble/curves/ed25519');
const { secp256k1 } = require('@noble/curves/secp256k1');
const { ed448 } = require('@noble/curves/ed448');
const { bytesToHex } = require('@noble/curves/abstract/utils');
const EMPTY_BUFFER = common.EMPTY_BUFFER;
const Tagged = cbor.Tagged;

const SignTag = exports.SignTag = 98;
const Sign1Tag = exports.Sign1Tag = 18;

const ECset = { secp256k1: secp256k1, p256: p256, p384: p384, p521: p521 };
const Edset = { ed25519: ed25519, ed448: ed448 };

const AlgFromTags = {};
AlgFromTags[-7] = { sign: 'ES256', digest: 'SHA-256' };
AlgFromTags[-47] = { sign: 'ES256K', digest: 'SHA-256' };
AlgFromTags[-8] = { sign: 'EdDSA', digest: 'SHA-256' };
AlgFromTags[-35] = { sign: 'ES384', digest: 'SHA-384' };
AlgFromTags[-36] = { sign: 'ES512', digest: 'SHA-512' };
AlgFromTags[-37] = { sign: 'PS256', digest: 'SHA-256' };
AlgFromTags[-38] = { sign: 'PS384', digest: 'SHA-384' };
AlgFromTags[-39] = { sign: 'PS512', digest: 'SHA-512' };
AlgFromTags[-257] = { sign: 'RS256', digest: 'SHA-256' };
AlgFromTags[-258] = { sign: 'RS384', digest: 'SHA-384' };
AlgFromTags[-259] = { sign: 'RS512', digest: 'SHA-512' };

const COSEAlgToNodeAlg = {
  ES256: { sign: 'p256', digest: 'sha256' },
  ES256K: { sign: 'secp256k1', digest: 'sha256' },
  ES384: { sign: 'p384', digest: 'sha384' },
  ES512: { sign: 'p521', digest: 'sha512' },
  EdDSA: { sign: 'ed25519', digest: 'sha256' },
  RS256: { sign: 'RSA-SHA256' },
  RS384: { sign: 'RSA-SHA384' },
  RS512: { sign: 'RSA-SHA512' },
  PS256: { alg: 'pss-sha256', saltLen: 32 },
  PS384: { alg: 'pss-sha384', saltLen: 48 },
  PS512: { alg: 'pss-sha512', saltLen: 64 }
};

function i2osp(x, xlen) { // RFC 8017 Section 4.1
  if (x < 0 || x >= (256 ** xlen)) {
    throw new Error(`bad I2OSP call: value=${x} length=${xlen}`);
  }
  const res = new Uint8Array(xlen);

  for (let i = xlen - 1; i >= 0; i--) {
    const elem = x / BigInt(256 ** i);
    res[i] = Number(elem);
    x = x % BigInt(256 ** i);
  }

  res.reverse();//
  return Buffer.from(res);
}

async function doSign(SigStructure, signer, alg) {
  if (!AlgFromTags[alg]) {
    throw new Error('Unknown algorithm, ' + alg);
  }
  if (!COSEAlgToNodeAlg[AlgFromTags[alg].sign]) {
    throw new Error('Unsupported algorithm, ' + AlgFromTags[alg].sign);
  }

  let ToBeSigned = cbor.encode(SigStructure);
  // console.log('ToBeSigned: ' + ToBeSigned.toString('hex'));
  let sig;
  if (AlgFromTags[alg].sign.startsWith('ES')) {
    const hash = crypto.createHash(COSEAlgToNodeAlg[AlgFromTags[alg].sign].digest);
    hash.update(ToBeSigned);
    ToBeSigned = hash.digest();
    const ec = ECset[COSEAlgToNodeAlg[AlgFromTags[alg].sign].sign];

    const signature = await ec.sign(ToBeSigned, signer.key.d);

    sig = Buffer.concat([i2osp(signature.r, ec.CURVE.nByteLength), i2osp(signature.s, ec.CURVE.nByteLength)]);
  } else if (AlgFromTags[alg].sign.startsWith('PS')) {
    signer.key.dmp1 = signer.key.dp;
    signer.key.dmq1 = signer.key.dq;
    signer.key.coeff = signer.key.qi;
    const key = new NodeRSA().importKey(signer.key, 'components-private');
    key.setOptions({
      signingScheme: {
        scheme: COSEAlgToNodeAlg[AlgFromTags[alg].sign].alg.split('-')[0],
        hash: COSEAlgToNodeAlg[AlgFromTags[alg].sign].alg.split('-')[1],
        saltLength: COSEAlgToNodeAlg[AlgFromTags[alg].sign].saltLen
      }
    });
    sig = key.sign(ToBeSigned);
  } else if (AlgFromTags[alg].sign.startsWith('Ed')) {
    // TODO:choosing curve by verification key
    const ed = Edset.ed25519;
    const signature = await ed.sign(ToBeSigned, signer.key.d);
    sig = Buffer.from(signature);
  } else {
    const sign = crypto.createSign(COSEAlgToNodeAlg[AlgFromTags[alg].sign].sign);
    sign.update(ToBeSigned);
    sign.end();
    sig = sign.sign(signer.key);
  }
  return sig;
}

exports.create = async function (headers, payload, signers, options) {
  options = options || {};
  let u = headers.u || {};
  let p = headers.p || {};

  p = common.TranslateHeaders(p);
  u = common.TranslateHeaders(u);
  let bodyP = p || {};
  bodyP = (bodyP.size === 0) ? EMPTY_BUFFER : cbor.encode(bodyP);
  if (Array.isArray(signers)) {
    if (signers.length === 0) {
      throw new Error('There has to be at least one signer');
    }
    if (signers.length > 1) {
      // throw new Error('Only one signer is supported');
      const sigs = Array(signers.length);
      for (let i = 0; i < signers.length; i++) {
        const signer = signers[i];
        const externalAAD = signer.externalAAD || EMPTY_BUFFER;
        let signerP = signer.p || {};
        let signerU = signer.u || {};

        signerP = common.TranslateHeaders(signerP);
        signerU = common.TranslateHeaders(signerU);
        const alg = signerP.get(common.HeaderParameters.alg);
        signerP = (signerP.size === 0) ? EMPTY_BUFFER : cbor.encode(signerP);

        const SigStructure = [
          'Signature',
          bodyP,
          signerP,
          externalAAD,
          payload
        ];

        const sig = await doSign(SigStructure, signer, alg);
        if (signerP.size === 0 && options.encodep === 'empty') {
          signerP = EMPTY_BUFFER;
        } else {
          // signerP = cbor.encode(signerP);
        }
        sigs[i] = [signerP, signerU, sig];
      }
      const signed = [bodyP, u, payload, sigs];
      return cbor.encodeAsync(options.excludetag ? signed : new Tagged(SignTag, signed));
    } else {
      // TODO handle multiple signers

      const signer = signers[0];
      const externalAAD = signer.externalAAD || EMPTY_BUFFER;
      let signerP = signer.p || {};
      let signerU = signer.u || {};

      signerP = common.TranslateHeaders(signerP);
      signerU = common.TranslateHeaders(signerU);
      const alg = signerP.get(common.HeaderParameters.alg);
      signerP = (signerP.size === 0) ? EMPTY_BUFFER : cbor.encode(signerP);

      const SigStructure = [
        'Signature',
        bodyP,
        signerP,
        externalAAD,
        payload
      ];

      const sig = await doSign(SigStructure, signer, alg);
      if (p.size === 0 && options.encodep === 'empty') {
        p = EMPTY_BUFFER;
      } else {
        p = cbor.encode(p);
      }
      const signed = [p, u, payload, [[signerP, signerU, sig]]];
      return cbor.encodeAsync(options.excludetag ? signed : new Tagged(SignTag, signed));
    }
  } else {
    const signer = signers;
    const externalAAD = signer.externalAAD || EMPTY_BUFFER;
    const alg = p.get(common.HeaderParameters.alg) || u.get(common.HeaderParameters.alg);
    const SigStructure = [
      'Signature1',
      bodyP,
      externalAAD,
      payload
    ];
    const sig = await doSign(SigStructure, signer, alg);
    if (p.size === 0 && options.encodep === 'empty') {
      p = EMPTY_BUFFER;
    } else {
      p = cbor.encode(p);
    }
    const signed = [p, u, payload, sig];
    return cbor.encodeAsync(options.excludetag ? signed : new Tagged(Sign1Tag, signed), { canonical: true });
  }
};

function doVerify(SigStructure, verifier, alg, sig) {
  if (!AlgFromTags[alg]) {
    throw new Error('Unknown algorithm, ' + alg);
  }
  const nodeAlg = COSEAlgToNodeAlg[AlgFromTags[alg].sign];
  if (!nodeAlg) {
    throw new Error('Unsupported algorithm, ' + AlgFromTags[alg].sign);
  }
  const ToBeSigned = cbor.encode(SigStructure);

  if (AlgFromTags[alg].sign.startsWith('ES')) {
    const hash = crypto.createHash(nodeAlg.digest);
    hash.update(ToBeSigned);
    const msgHash = hash.digest();

    const ec = ECset[COSEAlgToNodeAlg[AlgFromTags[alg].sign].sign];

    // make 33b hex format
    // const yBigInt = hexToNumber(verifier.key.y.toString('hex'));
    // const isYOdd = (yBigInt % BigInt(2)) === 1n;
    // const compressBuf = Buffer.concat([isYOdd ? Buffer.from('03', 'hex') : Buffer.from('02', 'hex'), verifier.key.x]);
    // const pub = bytesToHex(compressBuf);

    let pub = verifier.key?.raw;
    if (!pub) {
      if (!verifier.key?.x || !verifier.key?.y) {
        throw new Error('Verifier key is missing');
      }
      // make 64b hex format
      const compressBuf = Buffer.concat([Buffer.from('04', 'hex'), verifier.key.x, verifier.key.y]);
      pub = bytesToHex(compressBuf);
    }
    const isValid = ec.verify(sig, msgHash, pub) === true;
    if (!isValid) {
      throw new Error('Signature missmatch');
    }
  } else if (AlgFromTags[alg].sign.startsWith('PS')) {
    const key = new NodeRSA().importKey(verifier.key, 'components-public');
    key.setOptions({
      signingScheme: {
        scheme: COSEAlgToNodeAlg[AlgFromTags[alg].sign].alg.split('-')[0],
        hash: COSEAlgToNodeAlg[AlgFromTags[alg].sign].alg.split('-')[1],
        saltLength: COSEAlgToNodeAlg[AlgFromTags[alg].sign].saltLen
      }
    });
    if (!key.verify(ToBeSigned, sig, 'buffer', 'buffer')) {
      throw new Error('Signature missmatch');
    }
  } else if (AlgFromTags[alg].sign.startsWith('Ed')) {
    // EdDSA
    // TODO:choosing curve by verification key
    const ed = Edset.ed25519;
    const pub = verifier.key.raw || verifier.key.x;
    const isValid = ed.verify(sig, ToBeSigned, pub) === true;
    if (!isValid) {
      throw new Error('Signature missmatch');
    }
  } else {
    const verify = crypto.createVerify(nodeAlg.sign);
    verify.update(ToBeSigned);
    if (!verify.verify(verifier.key, sig)) {
      throw new Error('Signature missmatch');
    }
  }
}

function getSigner(signers, verifier) {
  for (let i = 0; i < signers.length; i++) {
    const kid = signers[i][1].get(common.HeaderParameters.kid); // TODO create constant for header locations
    if (kid.equals(Buffer.from(verifier.key.kid, 'utf8'))) {
      return signers[i];
    }
  }
}

function getCommonParameter(first, second, parameter) {
  let result;
  if (first.get) {
    result = first.get(parameter);
  }
  if (!result && second.get) {
    result = second.get(parameter);
  }
  return result;
}

exports.verify = async function (payload, verifier, options) {
  options = options || {};
  const obj = await cbor.decodeFirst(payload);
  return verifyInternal(verifier, options, obj);
};

exports.verifySync = function (payload, verifier, options) {
  options = options || {};
  const obj = cbor.decodeFirstSync(payload);
  return verifyInternal(verifier, options, obj);
};

function verifyInternal(verifier, options, obj) {
  options = options || {};
  let type = options.defaultType ? options.defaultType : SignTag;
  if (obj instanceof Tagged) {
    if (obj.tag !== SignTag && obj.tag !== Sign1Tag) {
      throw new Error('Unexpected cbor tag, \'' + obj.tag + '\'');
    }
    type = obj.tag;
    obj = obj.value;
  }

  if (!Array.isArray(obj)) {
    throw new Error('Expecting Array');
  }

  if (obj.length !== 4) {
    throw new Error('Expecting Array of lenght 4');
  }

  let [p, u, plaintext, signers] = obj;

  if (type === SignTag && !Array.isArray(signers)) {
    throw new Error('Expecting signature Array');
  }

  p = (!p.length) ? EMPTY_BUFFER : cbor.decodeFirstSync(p);
  u = (!u.size) ? EMPTY_BUFFER : u;

  const signer = (type === SignTag ? getSigner(signers, verifier) : signers);

  if (!signer) {
    throw new Error('Failed to find signer with kid' + verifier.key.kid);
  }

  if (type === SignTag) {
    const externalAAD = verifier.externalAAD || EMPTY_BUFFER;
    let [signerP, , sig] = signer;
    signerP = (!signerP.length) ? EMPTY_BUFFER : signerP;
    p = (!p.size) ? EMPTY_BUFFER : cbor.encode(p);
    const signerPMap = cbor.decode(signerP);
    const alg = signerPMap.get(common.HeaderParameters.alg);
    const SigStructure = [
      'Signature',
      p,
      signerP,
      externalAAD,
      plaintext
    ];
    doVerify(SigStructure, verifier, alg, sig);
    return plaintext;
  } else {
    const externalAAD = verifier.externalAAD || EMPTY_BUFFER;

    const alg = getCommonParameter(p, u, common.HeaderParameters.alg);
    if (!alg && !signer.length) {
      throw new common.ErrorWithValue('Unsigned COSE Message', plaintext);
    }
    p = (!p.size) ? EMPTY_BUFFER : cbor.encode(p);
    const SigStructure = [
      'Signature1',
      p,
      externalAAD,
      plaintext
    ];
    try {
      doVerify(SigStructure, verifier, alg, signer);
    } catch (error) {
      throw new common.ErrorWithValue(error.message, plaintext);
    }
    return plaintext;
  }
}
