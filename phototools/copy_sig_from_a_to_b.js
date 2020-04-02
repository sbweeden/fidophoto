//
// A Node.js command-line app to copy the signature information from one
// good image into another. This is so that you can create a second image that
// has a bad signature (demonstrate forgery attempt).
//
const fs = require('fs');
const jsrsasign = require('jsrsasign');
const piexif = require('piexifjs');

//the input and output files
var filename1 = "/Users/sweeden/Downloads/SecureImage-1.jpg";
var filename2 = "/Users/sweeden/Downloads/SecureImage-1-modified.jpg";
var fileout = "/Users/sweeden/Downloads/SecureImage-1-modified-with-sig.jpg";

const IMG_PREFIX = "data:image/jpeg;base64,";



// read the starting files
var jpeg1 = fs.readFileSync(filename1);
var dataURI1 = IMG_PREFIX + jsrsasign.hextob64(jsrsasign.BAtohex(jpeg1));

var jpeg2 = fs.readFileSync(filename2);
var dataURI2 = IMG_PREFIX + jsrsasign.hextob64(jsrsasign.BAtohex(jpeg2));

// get MakerNote from first file
var exif1 = piexif.load(dataURI1);
var mn = exif1.Exif[piexif.ExifIFD.MakerNote];

if (mn != null) {
	var exif2 = piexif.load(dataURI2);
	exif2.Exif[piexif.ExifIFD.MakerNote] = JSON.stringify(mn);
	var exifbytes = piexif.dump(exif2);
	var newDataURI = piexif.insert(exifbytes, dataURI2);
	fs.writeFileSync(fileout, new Uint8Array(jsrsasign.b64toBA(newDataURI.substring(IMG_PREFIX.length))));

} else {
	console.log("No MakerNote in file: " + filename1);
}
