//
// OAuthTokenManager - looks after APIs needed to get or refresh access tokens
//
const KJUR = require('jsrsasign');
const requestp = require('request-promise-native');
const logger = require('./logging.js');
const fido2error = require('./fido2error.js');
const cryptoutils = require('./cryptoutils.js');


// this is used for a shared admin access token
var adminTokenResponse = null;

/**
* Obtain a promise for a new access token. The reason that requestp is wrapped in a new promise
* is to allow normalisation of the error to a fido2error.fido2Error.
*/
function getAccessToken(req) {
	return new Promise((resolve, reject) => {
		// if the current access token has more than two minutes to live, use it, otherwise get a new one
		let now = new Date();

		let tokenResponse = adminTokenResponse;

		if (tokenResponse != null && tokenResponse.expires_at_ms > (now.getTime() + (2*60*1000))) {
			resolve(tokenResponse.access_token);
		} else {
			let formData = {
				"grant_type": "client_credentials",
				"client_id": process.env.OAUTH_CLIENT_ID,
				"client_secret": process.env.OAUTH_CLIENT_SECRET
			};
			console.log("oauthtokenmanager about to get new token with formData: " + JSON.stringify(formData));

			let options = {
				url: process.env.CI_TENANT_ENDPOINT + "/v1.0/endpoint/default/token",
				method: "POST",
				headers: {
					"Accept": "application/json",
				},
				form: formData,
				json: true
			};

			requestp(options).then((tr) => {
				if (tr && tr.access_token) {
					// compute this
					let now = new Date();
					tr.expires_at_ms = now.getTime() + (tr.expires_in * 1000);

					// store the new token response back in global cache
					adminTokenResponse = tr;

					resolve(tr.access_token);
				} else {
					console.log("oauthtokenmanager requestp(options) unexpected token response: " + (tr != null) ? JSON.stringify(tr) : "null");
					let err = new fido2error.fido2Error("Did not get access token in token response");
					reject(err);
				}
			}).catch((e) => {
				console.log("oauthtokenmanager.getAccessToken inside catch block with e: " + (e != null ? JSON.stringify(e) : "null"));
				let err = null;
				if (e != null && e.error != null && e.error.error_description != null) {
					err = new fido2error.fido2Error(e.error.error_description);
				} else {
					err = new fido2error.fido2Error("Unable to get access_token - check server logs for details");
				}
				reject(err);
			});
		}
	});
}

/**
* Rest of this file provides utilities for a light-weight symmetric-key based access token implementation 
* for user access tokens. This is somewhat temporary and should eventually be replaced by a Cloud Identity 
* OAuth-as-a-service implementation pending some finer grained control and search capabilities over access 
* tokens from CI. For now though this is perfectly adequate because these secrets are also stored in the
* user registry, and even knowning the encryption key you cannot forge one that can be used on another users
* account.
*/

function generateAccessTokenForUser(userId) {
	return KJUR.hextob64u(KJUR.BAtohex(cryptoutils.hashedEncryptAESToBA(KJUR.utf8tob64u(userId), process.env.SECRET)));
}

/**
* Returns userId if access token can be decrypted, otherwise returns null.
*/
function validateUserAccessToken(access_token) {
	let result = null;
	try {
		result = KJUR.b64utoutf8(cryptoutils.hashedDecryptAESFromBA(KJUR.b64toBA(KJUR.b64utob64(access_token)), process.env.SECRET));
	} catch (e) {
		logger.logWithTS("Unable to decrypt user access token: " + e);
		result = null;
	}
	return result;
}

module.exports = { 
	getAccessToken: getAccessToken,
	generateAccessTokenForUser: generateAccessTokenForUser,
	validateUserAccessToken: validateUserAccessToken
};
