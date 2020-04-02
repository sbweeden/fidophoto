//
// Collection of utility functions built on crypto APIs
//
const KJUR = require('jsrsasign');
const CryptoJS = require('crypto-js');
const cbor = require('cbor');
const logger = require('./logging.js');

/**
 * Extracts the bytes from an array beginning at index start, and continuing until 
 * index end-1 or the end of the array is reached. Pass -1 for end if you want to 
 * parse till the end of the array.
 */
function bytesFromArray(o, start, end) {
	// o may be a normal array of bytes, or it could be a JSON encoded Uint8Array
	let len = o.length;
	if (len == null) {
		len = Object.keys(o).length;
	}
	
	let result = [];
	for (let i = start; (end == -1 || i < end) && (i < len); i++) {
		result.push(o[i]);
	}
	return result;
}

/**
 * Returns the bytes of a sha256 message digest of either a string or byte array
 * This is used when building the signature base string to verify registration
 * data.
 */
function sha256(data) {
	let md = new KJUR.crypto.MessageDigest({
		alg : "sha256",
		prov : "cryptojs"
	});
	if (Array.isArray(data)) {
		md.updateHex(KJUR.BAtohex(data));
	} else {
		md.updateString(data);
	}
	return KJUR.b64toBA(KJUR.hex2b64(md.digest()));
}


function coseKeyToPublicKey(k) {
	let result = null;

	if (k != null) {
		// see https://tools.ietf.org/html/rfc8152
		// and https://www.iana.org/assignments/cose/cose.xhtml
		let kty = k["1"];
		let alg = k["3"];

		if (kty == 1) {
			// EdDSA key type
			validEDAlgs = [ -8 ];
			if (validEDAlgs.indexOf(alg) >= 0) {
				let crvMap = {
						"6" : "Ed25519",
						"7" : "Ed448"
					};
					let crv = crvMap['' + k["-1"]];
					if (crv != null) {
						logger.logWithTS("No support for EdDSA keys");
					} else {
						logger.logWithTS("Invalid crv: " + k["-1"] + " for ED key type");
					}

			} else {
				logger.logWithTS("Invalid alg: " + alg + " for ED key type");
			}
		} else if (kty == 2) {
			// EC key type
			validECAlgs = [ -7, -35, -36 ];

			if (validECAlgs.indexOf(alg) >= 0) {
				let crvMap = {
					"1" : "P-256",
					"2" : "P-384",
					"3" : "P-521" // this is not a typo. It is 521
				};
				let crv = crvMap['' + k["-1"]];
				if (crv != null) {
					// ECDSA
					let xCoordinate = bytesFromArray(k["-2"], 0, -1);
					let yCoordinate = bytesFromArray(k["-3"], 0, -1);

					if (xCoordinate != null && xCoordinate.length > 0
							&& yCoordinate != null && yCoordinate.length > 0) {
						result = KJUR.KEYUTIL.getKey({
							"kty" : "EC",
							"crv" : crv,
							"x" : KJUR.hextob64(KJUR.BAtohex(xCoordinate)),
							"y" : KJUR.hextob64(KJUR.BAtohex(yCoordinate))
						});
					} else {
						logger.logWithTS("Invalid x or y co-ordinates for EC key type");
					}
				} else {
					logger.logWithTS("Invalid crv: " + k["-1"] + " for EC key type");
				}
			} else {
				logger.logWithTS("Invalid alg: " + alg + " for EC key type");
			}
		} else if (kty == 3) {
			// RSA key type
			validRSAAlgs = [ -37, -38, -39, -257, -258, -259, -65535 ];
			if (validRSAAlgs.indexOf(alg) >= 0) {
				let n = bytesFromArray(k["-1"], 0, -1);
				let e = bytesFromArray(k["-2"], 0, -1);
				if (n != null && n.length > 0 && e != null && e.length > 0) {
					result = KJUR.KEYUTIL.getKey({
						"kty" : "RSA",
						"n" : KJUR.hextob64(KJUR.BAtohex(n)),
						"e" : KJUR.hextob64(KJUR.BAtohex(e))
					});
				} else {
					logger.logWithTS("Invalid n or e values for RSA key type");
				}
			} else {
				logger.logWithTS("Invalid alg: " + alg + " for RSA key type");
			}
		} else {
			logger.logWithTS("Unsupported key type: " + kty);
		}
	}
	return result;
}

function verifyFIDOSignature(sigBaseHex, coseKey, sigHex, alg) {
	let result = false;
	
	// default to ECDSA
	if (alg == null) {
		alg = -7;
	}

	let algMap = {
			"-7" : "SHA256withRSA",
			"-35" : "SHA384withECDSA",
			"-36" : "SHA512withECDSA",
			"-37" : "SHA256withRSAandMGF1",
			"-38" : "SHA384withRSAandMGF1",
			"-39" : "SHA512withRSAandMGF1",
			"-257" : "SHA256withRSA",
			"-258" : "SHA384withRSA",
			"-259" : "SHA512withRSA",
			"-65535" : "SHA1withRSA"
		};

	let algStr = algMap['' + alg];
	if (algStr != null) {
		let verifier = new KJUR.crypto.Signature({
			"alg" : algStr
		});

		// initialize with the public key
		verifier.init(coseKeyToPublicKey(coseKey));

		verifier.updateHex(sigBaseHex);
		result = verifier.verify(sigHex);
	} else {
		logger.logWithTS("Unsupported algorithm in verifyFIDOSignature: " + alg);
	}

	if (!result) {
		// some extra debugging in case debug is needed later
		logger.logWithTS("verifyFIDOSignature failed: sigBaseHex="
				+ sigBaseHex + "; coseKey="
				+ JSON.stringify(coseKey) + "; sigHex=" + sigHex
				+ "; alg=" + alg + ";");
	}

	return result;
}

/**
* Deals with an odd JSON representation of array buffers from the CBOR decoder, converting top-level objects like
* { "key": {"type":"Buffer","data":[46,214]} }
* to
* { "key": [46,214] }
*/
function normalizeBuffersToArray(x) {
	if (x != null && typeof x == "object") {
		Object.keys(x).forEach((k) => {
			if (typeof x[k] == "object" && x[k]["type"] != null && x[k]["type"] == "Buffer" && x[k]["data"] != null) {
				x[k] = x[k]["data"];
			}
		});
	}
}

/**
* Takes the b64 text of the CBOR-encoded coseKey, and returns as a JSON
* COSE Key.
*/
function cpkB64toCoseKey(cpkStr) {
	let coseKey = cbor.decodeFirstSync(KJUR.b64tohex(cpkStr));
	normalizeBuffersToArray(coseKey);
	return coseKey;
}

/**
 * Calculates the base64url of the left-most half of the sha256 hash of the octets
 * of the ASCII string str. This is how access token hashes are calculated.
 */
function atHash(str) {
	let hashBytes = sha256(KJUR.b64toBA(KJUR.utf8tob64(str)));
	let halfLength = Math.ceil(hashBytes.length / 2);    
	let leftSide = hashBytes.splice(0,halfLength);
	return KJUR.hextob64u(KJUR.BAtohex(leftSide));
}

var ENCRYPTION_keySize = 256;
var ENCRYPTION_ivSize = 128;
var ENCRYPTION_iterations = 100;

/*
 * Simple AES encryption of a payload using a passphrase
 */
function hashedEncryptAESToBA(msg, pass) {
  let salt = CryptoJS.lib.WordArray.random(ENCRYPTION_ivSize/8);

  let key = CryptoJS.PBKDF2(pass, salt, {
      keySize: ENCRYPTION_keySize/32,
      iterations: ENCRYPTION_iterations
    });

  let iv = CryptoJS.lib.WordArray.random(ENCRYPTION_ivSize/8);
  
  // sha the original text and include the b64u of the left-most bytes 
  // in what gets encrypted. This allows us to verify that decryption is correct.
  // shaStr will always be 22 chars long
  let shaStr = atHash(msg);

  
  let encrypted = CryptoJS.AES.encrypt(shaStr + msg, key, { 
    iv: iv, 
    padding: CryptoJS.pad.Pkcs7,
    mode: CryptoJS.mode.CBC    
  });
  
  //console.log("salt: " + salt.toString());
  //console.log("iv: " + iv.toString());
  //console.log("encrypted: " + encrypted.toString());
  
  // salt, iv will be 16 bytes (ENCRYPTION_ivSize / 8) in length
  // encrypted bytes is the rest
  let saltByteArray = KJUR.b64toBA(KJUR.hextob64(salt.toString()));
  let ivByteArray = KJUR.b64toBA(KJUR.hextob64(iv.toString()));
    
  // encryption string is B64
  let encryptedByteArray = KJUR.b64toBA(encrypted.toString());
  let result = [];
  result.push(...saltByteArray);
  result.push(...ivByteArray);
  result.push(...encryptedByteArray);
  return result;
}

function hashedDecryptAESFromBA(ciphertextBytes, pass) {
	let result = null;
	
  // salt, iv will be 16 bytes (ENCRYPTION_ivSize / 8) in length
  // encrypted bytes is the rest
  let saltBytes = bytesFromArray(ciphertextBytes, 0, (ENCRYPTION_ivSize / 8));
  let ivBytes = bytesFromArray(ciphertextBytes, (ENCRYPTION_ivSize / 8), 2*(ENCRYPTION_ivSize / 8));
  let encryptedBytes = bytesFromArray(ciphertextBytes, 2*(ENCRYPTION_ivSize / 8), -1);
	
  let salt = CryptoJS.enc.Hex.parse(KJUR.BAtohex(saltBytes));
  let iv = CryptoJS.enc.Hex.parse(KJUR.BAtohex(ivBytes));
  let encrypted = KJUR.hextob64(KJUR.BAtohex(encryptedBytes));
  
  //console.log("salt: " + salt.toString());
  //console.log("iv: " + iv.toString());
  //console.log("encrypted: " + encrypted);
  
  let key = CryptoJS.PBKDF2(pass, salt, {
      keySize: ENCRYPTION_keySize/32,
      iterations: ENCRYPTION_iterations
    });

  let decryptedText = CryptoJS.AES.decrypt(encrypted, key, { 
    iv: iv, 
    padding: CryptoJS.pad.Pkcs7,
    mode: CryptoJS.mode.CBC    
  }).toString(CryptoJS.enc.Utf8);
  
  if (decryptedText != null && decryptedText.length > 22) {
	  // first 22 bytes is the left-most half of the sha256 of the rest of the msg
	  let hexShaTxt = decryptedText.substr(0,22);
	  let msg = decryptedText.substr(22);
	  
	  // validate the sha of msg
	  let computedShaStr = atHash(msg);
	  if (computedShaStr == hexShaTxt) {
		  result = msg;
	  } else {
		  logger.logWithTS("decrypted sha text did not match - not encrypted by this passphrase");
	  }
  }
  
  return result;
}

module.exports = { 
	cpkB64toCoseKey: cpkB64toCoseKey,
	verifyFIDOSignature: verifyFIDOSignature,
	hashedEncryptAESToBA: hashedEncryptAESToBA,
	hashedDecryptAESFromBA: hashedDecryptAESFromBA
};
