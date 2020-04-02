//
// A Node.js command-line app to show the JSON contents of the MakerNote Exif data.
//
const fs = require('fs');
const jsrsasign = require('jsrsasign');
const piexif = require('piexifjs');

//the input file
var filename = "/Users/sweeden/Downloads/SecureImage-1-modified-with-sig.jpg";
const IMG_PREFIX = "data:image/jpeg;base64,";

// read the starting file
var jpeg = fs.readFileSync(filename);
var dataURI = IMG_PREFIX + jsrsasign.hextob64(jsrsasign.BAtohex(jpeg));

// get and display the MakerNote data out the updated file
var exif = piexif.load(dataURI);
console.log(JSON.parse(exif.Exif[piexif.ExifIFD.MakerNote]));
