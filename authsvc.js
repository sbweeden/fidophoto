//
// Utility functions for validating a user access token as an optional alternative
// authentication mechanism in the express middleware. If authenticated via OAuth,
// session is cleared and req.user is populated. This will only look for and 
// evaluate an access token if the request is not already authenticated via a 
// session (e.g. not already an OIDC logged in session).
//
// This is not particularly efficient because no caching is done of access token
// validation results, however we do not expect high volumes of OAuth-authenticated
// traffic to this application. OAuth authentication will only be used by a mobile
// application during credential registration time. As such, no caching logic has
// been implemented.
//
const requestp = require('request-promise-native');
const tm = require('./oauthtokenmanager.js');

/**
* Use the "formatted" display name from SCIM record if available, otherwise fallback
* to username.
*/
function getDisplayNameFromSCIMResponse(scimResponse) {
	let result = scimResponse.userName;
	if (scimResponse.name != null && scimResponse.name.formatted != null) {
		result = scimResponse.name.formatted;
	}
	return result;
}

/**
* This is a middleware function designed to optionally look for and authenticate
* a request (by populating req.user) if the request is not already an authenticated
* session, and a valid access token is present.
*
* In this scheme, access tokens are like API keys - they are long-lived. Their
* representation is a symmetric encryption of a Cloud Identity user id. If the 
* decryption is successful, a lookup of the user record in Cloud Identity is then
* completed to ensure that the access token (there can only be one valid active
* access token for a user) is still "current", and to retrieve other user details.
* 
* Note that we don't "fail" the request on validation errors - we just silently 
* ignore errors and the request will proceed as unauthenticated. This is a 
* concious and required implementation decision of this function.
*/
function validateAccessToken() {

	return async (req, rsp, next) => {

		if (req.session.username == null) {
			let token = null;
			let authz = req.get("Authorization");
			if (authz !== undefined) {
				let parts = authz.split(' ');
				    if (parts.length == 2) {
						let scheme = parts[0]
						let credentials = parts[1];

						if (/^Bearer$/i.test(scheme)) {
							token = credentials;
						} else {
							console.log("Authorization scheme was not Bearer");
						}
					} else {
						console.log("Invalid Authorization header");
					}

				if (token != null) {
					let isError = false;
					let access_token = null;
					let userSCIMResponse = null;

					let userSCIMId = tm.validateUserAccessToken(token);

					if (userSCIMId != null) {
						// look up user record to validate AT is current, and get username, etc
						try {
							access_token = await tm.getAccessToken(req);
						} catch (e) {
							console.log(e);
							isError = true;
						}

						if (!isError) {
							try {
								userSCIMResponse = await requestp({
									url: process.env.CI_TENANT_ENDPOINT + "/v2.0/Users",
									method: "GET",
									qs: { "filter" : 'id eq "' + userSCIMId + '"' },
									headers: {
										"Accept": "application/scim+json",
										"Authorization": "Bearer " + access_token
									},
									json: true
								});
							} catch (e) {
								console.log(e);
								isError = true;								
							}
						}

						if (!isError) {
							//console.log("Validating access token received userSCIMResponse: " + JSON.stringify(userSCIMResponse));

							if (userSCIMResponse != null && userSCIMResponse.totalResults == 1) {
								let userRecord = userSCIMResponse.Resources[0];

								let uat = null;
								if (userRecord != null && userRecord["urn:ietf:params:scim:schemas:extension:ibm:2.0:User"] != null
									&& userRecord["urn:ietf:params:scim:schemas:extension:ibm:2.0:User"]["customAttributes"] != null) {
									for (let i = 0; i < userRecord["urn:ietf:params:scim:schemas:extension:ibm:2.0:User"]["customAttributes"].length && uat == null; i++) {
										let ca = userRecord["urn:ietf:params:scim:schemas:extension:ibm:2.0:User"]["customAttributes"][i];
										if (ca.name == "userAccessToken") {
											uat = ca.values[0];
										}										
									}							

								}
								if (token == uat) {
									// all ok - authenticate the request, without a session
									req.session = null;
									req.user = {
										"username": userRecord.userName,
										"userDisplayName": getDisplayNameFromSCIMResponse(userRecord),
										"userSCIMId": userRecord.id,
										"userAccessToken": uat
									};
								} else {
									console.log("Provided access token: " + token + " does not match token in user record: " + uat);
								}
							}
						}
					}
				}
			} else {
				// console.log("No Authorization header");
			}
		} else {
			//console.log("User already authenticated, skipping OAuth authentication");
		}
		return next();
	}
}


module.exports = { 
	validateAccessToken: validateAccessToken
};
