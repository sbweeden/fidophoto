//
// A Node.js command-line app to sign a jpeg file with a FIDO2-like signature and
// include the signature information as JSON in the MakerNote Exif data.
//
const fs = require('fs');
const jsrsasign = require('jsrsasign');
const piexif = require('piexifjs');

// this credentialId and private key was extracted from using POSTMAN after registering and authenticating with a credential
// there are temporary POSTMAN variables these can be extracted from (last_CredentialId and last_privKeyHex)
var credentialId = "oKgQqFpvK9mP24UqPTYinSzXXw-6JYTKtRzW78U182RcYAYTGrymQ_WFgMAn2RHN8NGnJ9PBleJCYSQD-5tIm2udTCmNNeMF-DQPh_11lBI9V-fYUqhqlcsJj3ypCjqqFSk-whRL8CvGcQmTjB8oig";
var privateKeyHex = "2f42aa624ccda8d6550b8ebd206c7bdbda3fda6189f88b9bf816b721f76d7ba6";

//the input and output files
var filename = "/Users/sweeden/Downloads/test.jpg";
var fileout = "/Users/sweeden/Downloads/test-signed.jpg";

const rpId = "www.fidophoto.com";

const IMG_PREFIX = "data:image/jpeg;base64,";

function flattenImage(img) {
    var exif = piexif.load(img);
    exif.Exif[piexif.ExifIFD.MakerNote] = "";
    var exifStr = piexif.dump(exif);
    var newImg = piexif.insert(exifStr, img);
    if (newImg.startsWith(IMG_PREFIX)) {
    	newImg = newImg.substring(IMG_PREFIX.length);
    }
    return newImg;
}


/**
 * Returns the bytes of a sha256 message digest of either a string or byte array
 * This is used when building the signature base string to verify registration
 * data.
 */
function sha256(data) {
	var md = new jsrsasign.crypto.MessageDigest({
		alg : "sha256",
		prov : "cryptojs"
	});
	if (Array.isArray(data)) {
		md.updateHex(jsrsasign.BAtohex(data));
	} else {
		md.updateString(data);
	}
	return jsrsasign.b64toBA(jsrsasign.hex2b64(md.digest()));
}

function sha256hex(data) {
    var md = new jsrsasign.crypto.MessageDigest({
            alg : "sha256",
            prov : "cryptojs"
    });
    md.updateHex(data);
    return md.digest();
}

// Build the authenticatorData
var authData = [];

// first rpIdHashBytes
authData.push(...sha256(rpId));

// flags - UP, UV
var up = false;
var uv = false;
var flags = (up ? 0x01 : 0x00) | (uv ? 0x04 : 0x00);
authData.push(flags);

// add 4 bytes of signature counter - we use the current time in epoch seconds as the monotonic counter
var now = (new Date()).getTime() / 1000;
authData.push(
		((now & 0xFF000000) >> 24) & 0xFF,
		((now & 0x00FF0000) >> 16) & 0xFF,
		((now & 0x0000FF00) >> 8) & 0xFF,
		(now & 0x000000FF));


// read the starting file
var jpeg = fs.readFileSync(filename);
var dataURI = IMG_PREFIX + jsrsasign.hextob64(jsrsasign.BAtohex(jpeg));

// build the signature base string
var flatImage = flattenImage(dataURI);
var hashImgHex = sha256hex(jsrsasign.b64tohex(flatImage));
//console.log("hashImgHex: " + hashImgHex);
var sigbaseHex = jsrsasign.BAtohex(authData) + hashImgHex;
//console.log("sigbaseHex: " + sigbaseHex);

// compute signature
var ecdsa = new jsrsasign.crypto.ECDSA({'curve': 'prime256v1'});
ecdsa.setPrivateKeyHex(privateKeyHex);
var sig = new jsrsasign.crypto.Signature({"alg": "SHA256withRSA"});
sig.init(ecdsa);
sig.updateHex(sigbaseHex);
var sigValueHex = sig.sign();

// construct new MakerNote content
var mn = {
	credentialId: jsrsasign.b64utohex(credentialId),
	authenticatorData: jsrsasign.BAtohex(authData),
	signature: sigValueHex
};

// create and write out the updated file
var exif = piexif.load(dataURI);
exif.Exif[piexif.ExifIFD.MakerNote] = JSON.stringify(mn);
var exifbytes = piexif.dump(exif);
var newDataURI = piexif.insert(exifbytes, dataURI);
fs.writeFileSync(fileout, new Uint8Array(jsrsasign.b64toBA(newDataURI.substring(IMG_PREFIX.length))));
