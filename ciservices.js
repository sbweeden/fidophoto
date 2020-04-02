//
// ciservices - performs user and FIDO2 operations against IBM Cloud Identity
//
const KJUR = require('jsrsasign');
const requestp = require('request-promise-native');
const logger = require('./logging.js');
const tm = require('./oauthtokenmanager.js');
const fido2error = require('./fido2error.js');
const cryptoutils = require('./cryptoutils.js');
const userutils = require('./userutils.js');

//
// Caching logic to reduce number of calls to CI
//

// cache to map rpUuid to rpId
var rpUuidMap = {};
// cache to map rpId to rpUuid
var rpIdMap = {};

//
// All users of this app will end up in this group
// This is useful for when the Cloud Identity tenant
// is used for multiple purposes and we want to see/filter
// users in the context of this application only.
// The applicationGroupSCIMId will be dynamically populated
// first time the group is created/accessed after startup.
//
var applicationGroupName = "FIDOPhotoUsers";
var applicationGroupSCIMId = null;

function getUserDetails(req) {
	return userutils.getUserDetails(req);
}

function handleErrorResponse(methodName, rsp, e, genericError) {
	// log what we can about this error case
	logger.logWithTS("ciservices." + methodName + " e: " + 
		e + " stringify(e): " + (e != null ? JSON.stringify(e): "null"));

	let fidoError = null;

	// if e is already a fido2Error, return it, otherwise try to perform discovery of
	// the error message, otherwise return a generic error message
	if (e != null && e.status == "failed") {
		// seems to already be a fido2Error
		fidoError = e;
	} else if (e != null && e.error != null && e.error.messageId != null && e.error.messageDescription != null) {
		// this looks like one of the typical CI error messages
		fidoError = new fido2error.fido2Error(e.error.messageId + ": " + e.error.messageDescription);

	} else {
		// fallback to the generic error
		fidoError = new fido2error.fido2Error(genericError);
	}

	logger.logWithTS("handleErrorResponse sending error response: " + JSON.stringify(fidoError));	
	rsp.json(fidoError);
}

/**
* Ensure the request contains a "username" attribute, and make sure it's either the
* empty string (if allowed), or is the username of the currently authenticated user. 
*/
function validateSelf(fidoRequest, username, allowEmptyUsername) {

	if (username != null) {
		if (!((fidoRequest.username == username) || (allowEmptyUsername && fidoRequest.username == ""))) {
			throw new fido2error.fido2Error("Invalid username in request");
		}
	} else {
		// no currently authenticated user
		// only permitted if fidoRequest.username is the empty string and allowEmptyUsername
		if (!(fidoRequest.username == "" && allowEmptyUsername)) {
			throw new fido2error.fido2Error("Not authenticated");
		}
	}

	return fidoRequest;
}


//
// Takes a CI attestation result payload and converts it to a format
// expected by the client.
//
function coerceAttestationResultToClientFormat(req, attestationResult) {
	let result = {
		"attributes": {
			"responseData": {},
			"credentialData": {}
		}
	};
	return result;
}

//
// Takes a CI assertion result payload and converts it to a format
// expected by the client.
//
function coerceAssertionResultToClientFormat(req, reqBody, assertionResult) {

	let result = {
		"user": {
			"id": assertionResult.userId,
			"name": null
		},
		"attributes": {
			"responseData": {},
			"credentialData": {
				"fidoLoginDetails": JSON.stringify({
					"request": reqBody,
					"response": assertionResult
				}),
				"AUTHENTICATOR_FRIENDLY_NAME": assertionResult.attributes.nickname,
				"AUTHENTICATION_LEVEL": "2",
				"displayName": null,
				"email": null
			}
		}
	};

	if (assertionResult.attributes["icon"]) {
		result.attributes.credentialData["AUTHENTICATOR_ICON"] = assertionResult.attributes["icon"];
	}

	return tm.getAccessToken(req)
	.then((access_token) => {
		// look up username from user.id
		console.log("about to call getUserAttributes");
		return getUserAttributes(req, null, result.user.id);
	}).then((ua) => {
		console.log("getUserAttributes returned: " + JSON.stringify(ua));
		// fill in user details
		result.user.name = ua.username;
		result.attributes.credentialData.displayName = ua.displayName;
		result.attributes.credentialData.email = ua.username;
		// all done
		return result;
	});
}

/**
* Proxies what is expected to be a valid FIDO2 server request to one of:
* /attestation/options
* /attestation/result
* /assertion/options
* /assertion/result
*
* to the CI server. There is little validation done other than to ensure
* that the client is not sending a request for a user other than the user
* who is currently logged in.
*/
function proxyFIDO2ServerRequest(req, rsp, validateUsername, allowEmptyUsername) {
	let userDetails = getUserDetails(req);
	let bodyToSend = validateUsername ? validateSelf(req.body, userDetails.username, allowEmptyUsername) : req.body;

	// the CI body is slightly different from the FIDO server spec. 
	// instead of username (validity of which has already been checked above), 
	// we need to provide userId which is the CI IUI for the user.
	if (bodyToSend.username != null) {
		delete bodyToSend.username;
		if (userDetails.userSCIMId) {
			bodyToSend.userId = userDetails.userSCIMId;
		}
	}

	// when performing registrations, I want the registration 
	// enabled immediately so insert this additional option
	if (req.url.endsWith("/attestation/result")) {
		bodyToSend.enabled = true;
	}

	let access_token = null;
	tm.getAccessToken(req)
	.then( (at) => {
		access_token = at;		
		return rpIdTorpUuid(req, process.env.RPID);
	}).then((rpUuid) => {
		let options = {
			url: process.env.CI_TENANT_ENDPOINT + "/v2.0/factors/fido2/relyingparties/" + rpUuid + req.url,
			method: "POST",
			headers: {
				"Content-type": "application/json",
				"Accept": "application/json",
				"Authorization": "Bearer " + access_token
			},
			json: true,
			body: bodyToSend
		};
		logger.logWithTS("proxyFIDO2ServerRequest.options: " + JSON.stringify(options));
		return requestp(options);
	}).then((proxyResponse) => {
		// worked
		let rspBody = proxyResponse;


		// coerce CI responses to format client expects (comes from original implementation)
		if (req.url.endsWith("/attestation/result")) {
			return coerceAttestationResultToClientFormat(req, proxyResponse);
		} else if (req.url.endsWith("/assertion/result")) {
			return coerceAssertionResultToClientFormat(req, bodyToSend, proxyResponse);
		} else {
			return rspBody;
		}
	}).then((rspBody) => {
		// just add server spec status and error message fields and send it
		rspBody.status = "ok";
		rspBody.errorMessage = "";
		logger.logWithTS("proxyFIDO2ServerRequest.success: " + JSON.stringify(rspBody));
		rsp.json(rspBody);
	}).catch((e)  => {
		handleErrorResponse("proxyFIDO2ServerRequest", rsp, e, "Unable to proxy FIDO2 request");
	});
}

/*
* Performs just-in-time provisioning of a relying party in cloud identity. Means less manual
* provisioning of the Cloud Identity tenant.
*/
function jitpRelyingParty(req, rpId) {
	logger.logWithTS("Just-in-time provisioning the RP with rpId: " + rpId);
	return tm.getAccessToken(req)
	.then((access_token) => {
		return requestp({
			url: process.env.CI_TENANT_ENDPOINT + "/config/v2.0/factors/fido2/relyingparties",
			method: "POST",
			headers: {
				"Content-type": "application/json",
				"Accept": "application/json",
				"Authorization": "Bearer " + access_token
			},
			json: true,
			body: {
			  "rpId": rpId,
			  "origins": [
			  	"https://" + rpId,
			    "https://" + rpId + ":" + process.env.LOCAL_SSL_PORT
			  ],
			  "name": "Photo Verifier Relying Party: " + rpId,
			  "allowedAttestationFormats": [
			    "PACKED",
			    "TPM", 
			    "FIDO_U2F", 
			    "ANDROID_SAFETYNET", 
			    "ANDROID_KEY", 
			    "NONE"
			  ],
			  "allowedAttestationTypes": [
			    "BASIC", 
			    "ATTCA", 
			    "SELF", 
			    "NONE"
			  ],
			  "metadataConfig": {
			    "enforcement": false, 
			    "includeAll": true
			  },
			  "enabled": true,
			  // allow UP=false
			  "webAuthn": false
			}
		});
	}).then(() => {
		logger.logWithTS("RP provisioning complete");
		return updateRPMaps();
	});
}

/**
* Lookup RP's rpUuid from an rpId
*/
function rpIdTorpUuid(req, rpId) {
	if (rpIdMap[rpId] != null) {
		return rpIdMap[rpId];
	} else {
		return updateRPMaps()
		.then(() => {
			// provision RP if we still don't have it
			if (rpIdMap[rpId] == null) {
				return jitpRelyingParty(req, rpId);
			}
		}).then(() => {
			if (rpIdMap[rpId] != null) {
				return rpIdMap[rpId];
			} else {
				// hmm - no rpId, fatal at this point.
				throw new fido2error.fido2Error("rpId: " + rpId + " could not be resolved");
			}			
		});
	}
}

/**
* First checks that the registration identified by the provided id is owned by the currently 
* logged in user, then Uses a DELETE operation to delete it.
* Returns the remaining registered credentials in the same format as sendUserResponse.
*/
function deleteRegistration(req, rsp) {
	let userDetails = getUserDetails(req);
	if (userDetails.isAuthenticated()) {
		let regId = req.body.id;
		if (regId != null) {
			let access_token = null;
			tm.getAccessToken(req).then((at) => {
				access_token = at;
				// first search for the suggested registration
				return requestp({
					url: process.env.CI_TENANT_ENDPOINT + "/v2.0/factors/fido2/registrations/" + regId,
					method: "GET",
					headers: {
						"Accept": "application/json",
						"Authorization": "Bearer " + access_token
					},
					json: true
				});
			}).then((regToDelete) => {
				// is it owned by the currenty authenticated user
				if (regToDelete.userId == userDetails.userSCIMId) {
					return requestp({
						url: process.env.CI_TENANT_ENDPOINT + "/v2.0/factors/fido2/registrations/" + regId,
						method: "DELETE",
						headers: {
							"Accept": "application/json",
							"Authorization": "Bearer " + access_token
						},
						json: true
					}).then(() => {
						logger.logWithTS("Registration deleted: " + regId);
					});
				} else {
					throw new fido2error.fido2Error("Not owner of registration");
				}
			}).then((deleteResult) => { 
				// we care not about the deleteResult - just build and send the user response
				sendUserResponse(req, rsp); 
			}).catch((e)  => {
				handleErrorResponse("deleteRegistration", rsp, e, "Unable to delete registration");
			});
		} else {
			rsp.json(new fido2error.fido2Error("Invalid id in request"));
		}
	} else {
		rsp.json(new fido2error.fido2Error("Not logged in"));
	}
}

/**
* Returns the details of the indicated registration, provided it is owned by the currently 
* logged in user.
*/
function registrationDetails(req, rsp) {
	let userDetails = getUserDetails(req);
	if (userDetails.isAuthenticated()) {
		let regId = req.query.id;
		if (regId != null) {
			let access_token = null;
			tm.getAccessToken(req).then((at) => {
				access_token = at;
				// first retrieve the suggested registration
				return requestp({
					url: process.env.CI_TENANT_ENDPOINT + "/v2.0/factors/fido2/registrations/" + regId,
					method: "GET",
					headers: {
						"Accept": "application/json",
						"Authorization": "Bearer " + access_token
					},
					json: true
				});
			}).then((reg) => {
				// check it is owned by the currenty authenticated user
				if (reg.userId == userDetails.userSCIMId) {
					rsp.json(reg);
				} else {
					throw new fido2error.fido2Error("Not owner of registration");
				}
			}).catch((e)  => {
				handleErrorResponse("registrationDetails", rsp, e, "Unable to retrieve registration");
			});
		} else {
			rsp.json(new fido2error.fido2Error("Invalid id in request"));
		}
	} else {
		rsp.json(new fido2error.fido2Error("Not logged in"));
	}
}

function getDisplayNameFromSCIMResponse(scimResponse) {
	let result = scimResponse.userName;
	if (scimResponse.name != null && scimResponse.name.formatted != null) {
		result = scimResponse.name.formatted;
	}
	return result;
}


function updateRPMaps() {
	// reads all relying parties from discovery service and updates local caches
	return tm.getAccessToken(null)
	.then((access_token) => {
		return requestp({
			url: process.env.CI_TENANT_ENDPOINT + "/v2.0/factors/discover/fido2",
			method: "GET",
			headers: {
				"Accept": "application/json",
				"Authorization": "Bearer " + access_token
			},
			json: true
		});
	}).then((discoverResponse) => {
		rpUuidMap = [];
		rpIdMap = [];

		discoverResponse.relyingParties.forEach((rp) => {
			rpUuidMap[rp.id] = rp.rpId;
			rpIdMap[rp.rpId] = rp.id;
		});
	}).catch((e) => {
		logger.logWithTS("ciservices.updateRPMaps e: " + e + " stringify(e): " + (e != null ? JSON.stringify(e): "null"));
	});
}

function updateRegistrationsFromMaps(registrationsResponse) {
	registrationsResponse.fido2.forEach((reg) => {
		// there really shouldn't be any "UNKNOWN" rpIds because if an RP is deleted, 
		// all related registrations should be deleted at the same time
		reg.rpId = (rpUuidMap[reg.references.rpUuid] ? rpUuidMap[reg.references.rpUuid] : "UNKNOWN");
	});
	return registrationsResponse;	
}

function coerceCIRegistrationsToClientFormat(registrationsResponse) {
	return new Promise((resolve, reject) => {
		// Do this check so we only lookup each unknown rpUuid all at once
		let anyUnresolvedRpUuids = false;
		for (let i = 0; i < registrationsResponse.fido2.length && !anyUnresolvedRpUuids; i++) {
			if (rpUuidMap[registrationsResponse.fido2[i].references.rpUuid] == null) {
				anyUnresolvedRpUuids = true;
			}
		}

		// if we need to, refresh the rpUuidMap
		if (anyUnresolvedRpUuids) {
			updateRPMaps()
			.then(() => {
				resolve(updateRegistrationsFromMaps(registrationsResponse));
			});
		} else {
			resolve(updateRegistrationsFromMaps(registrationsResponse));
		}
	});
}

function getUserResponse(req) {

	let userDetails = getUserDetails(req);

	let username = userDetails.username;
	let userId = userDetails.userSCIMId;
	let displayName = userDetails.userDisplayName;
	let userAccessToken = userDetails.userAccessToken;

	let result = { "authenticated": true, "username": username, "displayName": displayName, "access_token": userAccessToken, "credentials": [], "admin": false};

	let search = 'userId="' + userId + '"';
	// to futher filter results for just my rpId, add this
	search += '&attributes/rpId="'+process.env.RPID+'"';

	return tm.getAccessToken(req)
	.then((access_token) => { 

		let options = {
			url: process.env.CI_TENANT_ENDPOINT + "/v2.0/factors/fido2/registrations",
			method: "GET",
			qs: { "search" : search },
			headers: {
				"Accept": "application/json",
				"Authorization": "Bearer " + access_token
			},
			json: true
		};

		// This includes an example of how to measure the response time for a call
		let start = (new Date()).getTime();
		return requestp(options).then((r) => {
			let now = (new Date()).getTime();
			//console.log("getUserResponse: call to get user registrations with options: " + JSON.stringify(options) + " took(msec): " + (now-start));
			return r;
		});
	}).then((registrationsResponse) => {
		return coerceCIRegistrationsToClientFormat(registrationsResponse);
	}).then((registrationsResponse) => {
		result.credentials = registrationsResponse.fido2;
		return result;
	}).then((userResponse) => {
		if (userDetails.isAdmin()) {
			result.admin = true;
		}
		return result;
	});
}

/**
* Determines if the user is logged in.
* If so, returns their username and list of currently registered FIDO2 credentials as determined from a CI API. 
* If not returns {"authenticated":false}
*/
function sendUserResponse(req, rsp) {
	let userDetails = getUserDetails(req);
	if (userDetails.isAuthenticated()) {

		getUserResponse(req)
		.then((userResponse) => {
			rsp.json(userResponse);
		}).catch((e)  => {
			handleErrorResponse("sendUserResponse", rsp, e, "Unable to get user registrations");
		});
	} else {
		rsp.json({"authenticated": false});
	}		
}

function sendMetadata(req, rsp) {
	let userDetails = getUserDetails(req);

	let baseURL = 'https://' + process.env.RPID + ((process.env.LOCAL_SSL_SERVER == "true") ? (':' + process.env.LOCAL_SSL_PORT) : '');
	if (userDetails.isAuthenticated()) {
		rsp.json({
			"username": userDetails.username,
			"displayName": userDetails.userDisplayName,
			"rpId": process.env.RPID,
			"attestation_options": baseURL + '/attestation/options',
			"attestation_result": baseURL + '/attestation/result',
			"assertion_options": baseURL + '/assertion/options',
			"assertion_result": baseURL + '/assertion/result'
		});
	} else {
		rsp.json({"error": "Not authenticated"});
	}		
}

function newAccessToken(req, rsp) {
	let userDetails = getUserDetails(req);
	if (userDetails.isAuthenticated()) {
		// force generate a new access token
		getUserAccessToken(req, true)
		.then((uat) => {
			// update session if there is one
			if (req.session != null && uat != null) {
				req.session.userAccessToken = uat;
			}
			// return the user response
			sendUserResponse(req, rsp);
		});
	} else {
		// return the user response
		sendUserResponse(req, rsp);
	}		
}

function storeUserAccessToken(req, userSCIMRecord, uat) {

	let userDetails = getUserDetails(req);
	return tm.getAccessToken()
	.then((access_token) => {
		/*
		 * attempt to write to custom schema attribute. If not yet created, catch 
		 * that error and provision the custom schema attribute then try again
		 */
		 logger.logWithTS("Existing user SCIM record: " + JSON.stringify(userSCIMRecord));

		 // this is a deep copy
		 let newUserSCIMRecord = JSON.parse(JSON.stringify(userSCIMRecord));


		 if (newUserSCIMRecord["urn:ietf:params:scim:schemas:extension:ibm:2.0:User"]["customAttributes"] == null) {
		 	newUserSCIMRecord["urn:ietf:params:scim:schemas:extension:ibm:2.0:User"]["customAttributes"] = [];
		 }
		 let found = false;
		 for (let i = 0; i < newUserSCIMRecord["urn:ietf:params:scim:schemas:extension:ibm:2.0:User"]["customAttributes"].length && !found; i++) {
		 	let ca = newUserSCIMRecord["urn:ietf:params:scim:schemas:extension:ibm:2.0:User"]["customAttributes"][i];
		 	if (ca.name == "userAccessToken") {
		 		found = true;
		 		ca.values = [ uat ];
		 	}
		 }
		 if (!found) {
		 	newUserSCIMRecord["urn:ietf:params:scim:schemas:extension:ibm:2.0:User"]["customAttributes"].push({
		 		"name": "userAccessToken",
		 		"values": [ uat ]
		 	});
		 }

		 newUserSCIMRecord["schemas"] = [
		 	"urn:ietf:params:scim:schemas:core:2.0:User", 
		 	"urn:ietf:params:scim:schemas:extension:ibm:2.0:User"
		 ];

		 let optionalSchemas = [ 
		 	"urn:ietf:params:scim:schemas:extension:enterprise:2.0:User", 
		 	"urn:ietf:params:scim:schemas:extension:ibm:2.0:Notification" 
		 ];
		 for (let i = 0; i < optionalSchemas.length; i++) {
		 	if (newUserSCIMRecord[optionalSchemas[i]] != null) {
		 		newUserSCIMRecord["schemas"].push(optionalSchemas[i]);
		 	}
		 }

		logger.logWithTS("Performing user PUT operation with new record: " + JSON.stringify(newUserSCIMRecord));

		return requestp({
			url: process.env.CI_TENANT_ENDPOINT + "/v2.0/Users/" + userDetails.userSCIMId,
			method: "PUT",
			headers: {
				"Content-type": "application/scim+json",
				"Authorization": "Bearer " + access_token
			},
			body: JSON.stringify(newUserSCIMRecord)
		}).then((userRecord) => {
			logger.logWithTS("Successfully stored userAccessToken for: " + userDetails.username);
		}).catch((e) => {
			// if this was a 400 with a particular error detail, attempt creating the schema attribute and then trying again, otherwise give up
			if (e != null && e.statusCode == 400 && e.error.indexOf('CSIAI0213E The custom attribute with SCIM name [userAccessToken] was not found') >= 0) {
				logger.logWithTS("Trying to JIT-P the custom schema attribute");

				// first get the current attributes to see if there is a "spare" custom attribute
				return requestp({
					url: process.env.CI_TENANT_ENDPOINT + "/v2.0/Schema/attributes",
					method: "GET",
					qs: { "filter" : "customAvailable" },
					headers: {
						"Accept": "application/scim+json",
						"Authorization": "Bearer " + access_token
					}
				}).then((attributesResponseStr) => {
					return JSON.parse(attributesResponseStr);
				}).then((attributesResponse) => {
					if (attributesResponse != null && attributesResponse.totalResults > 0) {
						return attributesResponse.Resources[0].name;
					} else {
						return null;
					}
				}).then((customAttrName) => {
					//logger.logWithTS("Using custom attribute: " + customAttrName);
					if (customAttrName != null) {
						let schemaAttributeBody = {
							"name": customAttrName,
							"displayName": "User Access Token",
							"description": "Custom access token to use as an API key for FIDO Photo application",
							"scimName": "userAccessToken",
							"readOnly": false,
							"multiValue": false,
							"schemas": [ "urn:ietf:params:scim:schemas:ibm:core:2.0:SchemaAttribute" ],
							"type": "string"
						};

						return requestp({
							url: process.env.CI_TENANT_ENDPOINT + "/v2.0/Schema/attributes",
							method: "POST",
							headers: {
								"Content-type": "application/scim+json",
								"Authorization": "Bearer " + access_token
							},
							body: JSON.stringify(schemaAttributeBody),
							resolveWithFullResponse: true
						}).then((httpResponse) => {
							if (httpResponse != null && httpResponse.statusCode == 201) {
								logger.logWithTS("Successfully created new schema attribute for userAccessToken");

								// now retry...
								return storeUserAccessToken(req, userSCIMRecord, uat);

							} else {
								// shouldn't get here
								logger.logWithTS("Unable to create new schema attribute for userAccessToken response code: " + httpResponse.statusCode);
								logger.logWithTS(JSON.stringify(httpResponse));
							}
						});
					} else {
						logger.logWithTS("Unable to create new schema attribute for userAccessToken because there are no custom attributes available");
					}
				});
			} else {
				logger.logWithTS("ciservices.storeUserAccessToken e: " + e + " stringify(e): " + (e != null ? JSON.stringify(e): "null"));
				throw e;
			}
		});
	});
}

/**
* Used to return the existing application group ID, cached if possible, otherwise
* from the SCIM registry, creating the group if needed
*/
function getApplicationGroupID(req) {
	if (applicationGroupSCIMId != null) {
		return applicationGroupSCIMId;
	} else {
		let access_token = null;
		return tm.getAccessToken(req)
		.then((at) => {
			access_token = at;
			// lookup group
			return requestp({
				url: process.env.CI_TENANT_ENDPOINT + "/v2.0/Groups",
				method: "GET",
				qs: { 
					"filter" : "displayName eq \"" + applicationGroupName + "\"",
					"attributes": "id,displayName"
				},
				headers: {
					"Accept": "application/scim+json",
					"Authorization": "Bearer " + access_token
				},
				json: true
			});
		}).then((scimResponse) => {
			// if we got the group, return it's id, otherwise create it, then return the id
			if (scimResponse.totalResults == 1) {
				applicationGroupSCIMId = scimResponse.Resources[0].id;
				return applicationGroupSCIMId;
			} else {
				// create the group, get id from resonse and return that
				let groupData = {
					"displayName": applicationGroupName,
					"urn:ietf:params:scim:schemas:extension:ibm:2.0:Group": {
						"description": "Application-specific group"
					},
					"schemas": [
						"urn:ietf:params:scim:schemas:core:2.0:Group",
						"urn:ietf:params:scim:schemas:extension:ibm:2.0:Group"
					]
				};

				return requestp({
					url: process.env.CI_TENANT_ENDPOINT + "/v2.0/Groups",
					method: "POST",
					headers: {
						"Content-type": "application/scim+json",
						"Authorization": "Bearer " + access_token
					},
					body: JSON.stringify(groupData),
					resolveWithFullResponse: true
				}).then((httpResponse) => {
					if (httpResponse != null && httpResponse.statusCode == 201) {
						logger.logWithTS("Successfully created new application group: " + applicationGroupName);

						// the ID should be in the body
						let applicationGroup = JSON.parse(httpResponse.body);
						applicationGroupSCIMId = applicationGroup.id;
						return applicationGroupSCIMId;
					} else {
						throw "Unable to create application group";
					}
				});
			}
		});
	}
}

/**
* Used to check the user is in the application group, and add them if not already there.
*/
function validateUserAccount(req) {

	let userDetails = getUserDetails(req);
	let access_token = null;

	return tm.getAccessToken(req)
	.then((at) => {
		access_token = at;

		// this shouldn't happen
		if (!userDetails.isAuthenticated()) {
			throw "Not authenticated";
		}

		// get the group id, creating the group if needed
		return getApplicationGroupID(req);
	}).then((groupId) => {
		// pull the full user record
		return requestp({
			url: process.env.CI_TENANT_ENDPOINT + "/v2.0/Users/" + userDetails.userSCIMId,
			method: "GET",
			headers: {
				"Accept": "application/scim+json",
				"Authorization": "Bearer " + access_token
			},
			json: true
		});
	}).then((userSCIMRecord) => {
		// If this user is not active, bail out
		if (!userSCIMRecord.active) {
			throw "User disabled";
		}

		// Is the user in the application group? If not, add them
		let inApplicationGroup = false;
		if (userSCIMRecord["groups"] != null) {
			for (let i = 0; i < userSCIMRecord.groups.length && !inApplicationGroup; i++) {
				if (userSCIMRecord.groups[i].id == applicationGroupSCIMId) {
					inApplicationGroup = true;
				}
			}
		}

		if (!inApplicationGroup) {
			let patchBody = {
				"schemas":["urn:ietf:params:scim:api:messages:2.0:PatchOp"],
				"Operations": [ 
					{ "op": "add", "path": "members", "value": [ { "type": "user", "value": userDetails.userSCIMId } ] } 
				]
			};

			return requestp({
				url: process.env.CI_TENANT_ENDPOINT + "/v2.0/Groups/" + applicationGroupSCIMId,
				method: "PATCH",
				headers: {
					"Content-type": "application/scim+json",
					"Authorization": "Bearer " + access_token
				},
				body: JSON.stringify(patchBody),
				resolveWithFullResponse: true
			}).then((httpResponse) => {
				if (httpResponse != null && httpResponse.statusCode == 204) {
					logger.logWithTS("Successfully added user: " + userDetails.userSCIMId + " to application group: " + applicationGroupSCIMId);
				} else {
					logger.logWithTS("Unable to add user to application group: " + JSON.stringify(httpResponse));
					throw "Unable to add user to application group";
				}
			});




		}
	});
}

/**
* Used to retrieve an existing (or generate a new) "user access token", which is an API key that users are 
* assigned to be able to programatically call the FIDO attestation (and assertion) APIs.
*/
function getUserAccessToken(req, forceGenerateNew) {

	let userDetails = getUserDetails(req);

	return tm.getAccessToken(req)
	.then((access_token) => {
		// if the user session already has a user access token in it, just return that
		if (!forceGenerateNew && userDetails.userAccessToken != null) {
			return userDetails.userAccessToken;
		} else {
			// try reading one from the user profile
			return requestp({
				url: process.env.CI_TENANT_ENDPOINT + "/v2.0/Users/" + userDetails.userSCIMId,
				method: "GET",
				headers: {
					"Accept": "application/scim+json",
					"Authorization": "Bearer " + access_token
				},
				json: true
			}).then((userSCIMRecord) => {
				if (userSCIMRecord.active) {
					// do they have a userAccessToken attribute we want?
					let uat = null;
					if (!forceGenerateNew) {
						if (userSCIMRecord["urn:ietf:params:scim:schemas:extension:ibm:2.0:User"]["customAttributes"] != null) {
							for (let i = 0; i < userSCIMRecord["urn:ietf:params:scim:schemas:extension:ibm:2.0:User"]["customAttributes"].length && uat == null; i++) {
								let ca = userSCIMRecord["urn:ietf:params:scim:schemas:extension:ibm:2.0:User"]["customAttributes"][i];
								if (ca.name == "userAccessToken") {
									uat = ca.values[0];
								}
							}
						}
					}

					if (uat != null) {
						// all good, return it
						return uat;
					} else {
						// user didn't have one, or we're forcing generation of a new token
						logger.logWithTS("Generating new userAccessToken for user: " + userDetails.username);
						uat = tm.generateAccessTokenForUser(userDetails.userSCIMId);

						// store it - with error handling in case custom SCIM attribute doesn't yet exist
						return storeUserAccessToken(req, userSCIMRecord, uat)
						.then(() => {
							return uat;
						});
					}
				} else {
					logger.logWithTS("User disabled: " + userDetails.userSCIMId);
					return null;
				}
			});
		}
	}).catch((e) => {
		logger.logWithTS("ciservices.getUserAccessToken e: " + e + " stringify(e): " + (e != null ? JSON.stringify(e): "null"));
		return null;
	});
}

/**
* Used to verify the signature information in the exif of an image against registered
* credentials in Cloud Identity. If a matching credential can be found and the signature
* is valid, return information about the credential and the registered owner, otherwise
* return a general failed status.
*/
function photoVerifier(req,rsp) {
	let result = { "status": "failed" };

	try {
		let imageHash = req.body.imageHash;
		let sigInfoStr = req.body.sigInfo;	
		let sigInfo = JSON.parse(sigInfoStr);

		if (imageHash == null || imageHash.length  == 0) {
			throw "Invalid image hash";
		}

		if (sigInfo.credentialId == null) {
			throw "Signature Info JSON missing credentialId";
		}
		if (sigInfo.signature == null) {
			throw "Signature Info JSON missing signature";
		}
		if (sigInfo.authenticatorData == null) {
			throw "Signature Info JSON missing authenticatorData";
		}

		// In Cloud Identity, credentialId is stored in b64u
		let credentialId = KJUR.hextob64u(sigInfo.credentialId);

		let access_token = null;

		// perform lookup on credentialId (well that's the long-term plan - for now we have to do a scan)
		tm.getAccessToken(req)
		.then( (at) => {
			access_token = at;

			// until there is a way to search by credId, have to scan all registrations for the RPID :(
			return requestp({
				url: process.env.CI_TENANT_ENDPOINT + "/v2.0/factors/fido2/registrations",
				method: "GET",
				headers: {
					"Accept": "application/json",
					"Authorization": "Bearer " + access_token
				},
				json: true
			});
		}).then((allRegistrations) => {
			//logger.logWithTS("ciservices.photoVerifier allRegistrations: " + JSON.stringify(allRegistrations));
			let foundReg = null;
			for (let i = 0; i < allRegistrations.fido2.length && foundReg == null; i++) {
				let reg = allRegistrations.fido2[i];

				if (credentialId == reg.attributes.credentialId && process.env.RPID == reg.attributes.rpId) {
					foundReg = reg;
				}
			}

			if (foundReg == null) {
				throw "Unknown credentialId: " + credentialId;
			}

			if (!foundReg.enabled) {
				throw "Registration disabled for credentialId: " + credentialId;
			}

			return foundReg;
		}).then((foundReg) => {
			// get public key and check signature
			let coseKey = cryptoutils.cpkB64toCoseKey(foundReg.attributes.credentialPublicKey);
			let sigBaseHex = sigInfo.authenticatorData + imageHash;

			if (!cryptoutils.verifyFIDOSignature(
				sigBaseHex,
				coseKey,
				sigInfo.signature,
				-7)) {
				throw "Signature verification failed";
			}

			return foundReg;
		}).then((foundReg) => {
			//
			// retrieve the full registration record (this will include any metadata attributes)
			// Hopefully this can be optimised out when we are able to do a credentialId search.
			// 
			return requestp({
				url: process.env.CI_TENANT_ENDPOINT + "/v2.0/factors/fido2/registrations/" + foundReg.id,
				method: "GET",
				headers: {
					"Accept": "application/json",
					"Authorization": "Bearer " + access_token
				},
				json: true
			});
		}).then((reg) => {
			// format what we get from this for client needs
			result.reg = {};

			if (reg.attributes.nickname != null) {
				result.reg.nickname = reg.attributes.nickname;
			}

			if (reg.attributes.icon != null && reg.attributes.description != null) {
				result.reg.metadata = {
					"icon": reg.attributes.icon,
					"description": reg.attributes.description
				};
			}

			// look up owner for username, and anything else of interest
			return requestp({
				url: process.env.CI_TENANT_ENDPOINT + "/v2.0/Users/" + reg.userId,
				method: "GET",
				headers: {
					"Accept": "application/scim+json",
					"Authorization": "Bearer " + access_token
				},
				json: true
			});
		}).then((userSCIMRecord) => {

			//console.log("The user record is: " + JSON.stringify(userSCIMRecord));

			result.reg.username = userSCIMRecord.userName;

			// this is canned data for now, but could come from the user record if stored there
			result.reg.department = "Emergency Services";
			
			result.status = "ok";

			// send it
			rsp.json(result);
		}).catch((e)  => {
			logger.logWithTS("ciservices.photoVerifier e: " + e + " stringify(e): " + (e != null ? JSON.stringify(e): "null"));
			result.status = "failed";
			rsp.json(result);
		});
	} catch (e) {
		logger.logWithTS("ciservices.photoVerifier e: " + e + " stringify(e): " + (e != null ? JSON.stringify(e): "null"));
		result.status = "failed";
		rsp.json(result);
	}
}

/**
* Retrieves a list of all users in the applicationGroup, and calculates the number of registrations for each.
* Admin access is guaranteed by middleware before this can be called.
*/

function adminGetUsersProcessMember(req, member, fidoRegistrationsByUserId, result) {
	var m = {
		"username": member.userName,
		"userId": member.id,
		"displayName": getDisplayNameFromSCIMResponse(member),
		"oauthAccessToken": null,
		"numRegistrations": (fidoRegistrationsByUserId[member.id] ? fidoRegistrationsByUserId[member.id].length : 0)
	};

	let access_token = null;

	return tm.getAccessToken(req)
	.then((at) => {
		access_token = at;

		// try reading user access token from the user profile
		return requestp({
			url: process.env.CI_TENANT_ENDPOINT + "/v2.0/Users/" + member.id,
			method: "GET",
			headers: {
				"Accept": "application/scim+json",
				"Authorization": "Bearer " + access_token
			},
			json: true
		});
	}).then((userSCIMRecord) => {
		// if there is a user access token, add it to the result
		if (userSCIMRecord.active) {
			// do they have a userAccessToken
			if (userSCIMRecord["urn:ietf:params:scim:schemas:extension:ibm:2.0:User"]["customAttributes"] != null) {
				for (let i = 0; i < userSCIMRecord["urn:ietf:params:scim:schemas:extension:ibm:2.0:User"]["customAttributes"].length && m.oauthAccessToken == null; i++) {
					let ca = userSCIMRecord["urn:ietf:params:scim:schemas:extension:ibm:2.0:User"]["customAttributes"][i];
					if (ca.name == "userAccessToken") {
						m.oauthAccessToken = ca.values[0];
					}
				}
			}
		}
	}).then(() => {
		result.push(m);
	});
}

function adminGetUsers(req, rsp) {
	let result = [];

	let access_token = null;
	let fidoRegistrationsByUserId = {};

	// perform lookup on group
	tm.getAccessToken(req)
	.then((at) => {
		access_token = at;

		// lookup all FIDO registrations (for the RP) once as this will be more efficient than
		// a separate CI search per user

		// unfortunately RPID search doesn't work at the moment, so just get the lot...
		//let search += 'attributes/rpId="'+process.env.RPID+'"';

		return requestp({
			url: process.env.CI_TENANT_ENDPOINT + "/v2.0/factors/fido2/registrations",
			method: "GET",
			//qs: { "search" : search },
			headers: {
				"Accept": "application/json",
				"Authorization": "Bearer " + access_token
			},
			json: true
		});
	}).then((registrationsResponse) => {
		// this filter is done because we can't do a search on RPID yet
		registrationsResponse.fido2.forEach((reg) => {
			if (reg.attributes.rpId == process.env.RPID) {
				if (fidoRegistrationsByUserId[reg.userId] == null) {
					fidoRegistrationsByUserId[reg.userId] = [];
				}
				fidoRegistrationsByUserId[reg.userId].push(reg);
			}
		});
	}).then(() => {
		// lookup group - given we are logged in, applicationGroupSCIMId should be populated
		return requestp({
			url: process.env.CI_TENANT_ENDPOINT + "/v2.0/Groups/" + applicationGroupSCIMId,
			method: "GET",
			headers: {
				"Accept": "application/scim+json",
				"Authorization": "Bearer " + access_token
			},
			json: true
		});
	}).then((groupResponse) => {
		// if we got the group, return it's id, otherwise create it, then return the id
		let allPromises = [];
		if (groupResponse != null && groupResponse.members != null) {
			groupResponse.members.forEach((member) => {
				allPromises.push(adminGetUsersProcessMember(req, member, fidoRegistrationsByUserId, result));
			});
		}
		return Promise.all(allPromises);
	}).then(() => {
		rsp.json(result);
	});
}

function getUserAttributes(req, userIdMap, userId) {
	return tm.getAccessToken(req)
	.then((access_token) => {
		if (userIdMap != null && userIdMap[userId] != null) {
			return userIdMap[userId];
		} else {
			return requestp({
				url: process.env.CI_TENANT_ENDPOINT + "/v2.0/Users/" + userId,
				method: "GET",
				headers: {
					"Accept": "application/scim+json",
					"Authorization": "Bearer " + access_token
				},
				json: true
			}).then((userSCIMRecord) => {
				let result = {
					"username": userSCIMRecord.userName,
					"displayName": getDisplayNameFromSCIMResponse(userSCIMRecord),
					"userAccessToken": null
				};

				// do they have a userAccessToken?
				if (userSCIMRecord["urn:ietf:params:scim:schemas:extension:ibm:2.0:User"]["customAttributes"] != null) {
					for (let i = 0; i < userSCIMRecord["urn:ietf:params:scim:schemas:extension:ibm:2.0:User"]["customAttributes"].length && result.userAccessToken == null; i++) {
						let ca = userSCIMRecord["urn:ietf:params:scim:schemas:extension:ibm:2.0:User"]["customAttributes"][i];
						if (ca.name == "userAccessToken") {
							result.userAccessToken = ca.values[0];
						}
					}
				}

				// add to cache if using one
				if (userIdMap != null) {
					userIdMap[userId] = result;
				}

				return result;
			});
		}
	});
}

function adminGetRegistrations(req, rsp) {
	let result = [];

	let access_token = null;

	// Cache to map userId to basic user attributes as it's possible/likely there are 
	// multiple registrations owned by the same user. 
	// Declared at this scope so it is essentially flushed each admin load.
	let userIdMap = {};


	// perform lookup on group
	tm.getAccessToken(req)
	.then((at) => {
		access_token = at;

		// lookup all FIDO registrations (for the RP and optional userId) 
		let search = null;
		if (req["query"] && req["query"]["userId"] && req["query"]["userId"].length > 0) {
			search = 'userId="' + req.query.userId + '"';
			search += '&attributes/rpId="' + process.env.RPID + '"';
		} else {
			// unfortunately RPID-only search doesn't work at the moment, so just get the lot...
			//let search = 'attributes/rpId="'+process.env.RPID+'"';
		}

		let options = {
			url: process.env.CI_TENANT_ENDPOINT + "/v2.0/factors/fido2/registrations",
			method: "GET",
			headers: {
				"Accept": "application/json",
				"Authorization": "Bearer " + access_token
			},
			json: true			
		};

		if (search != null) {
			options.qs = { "search" : search };
		}

		return requestp(options);
	}).then((registrationsResponse) => {

		let allPromises = [];

		// iterate over all registrations for the RPID, creating a response object for each
		registrationsResponse.fido2.forEach((reg) => {

			// this filter is done because we can't do a search on RPID-only yet
			if (reg.attributes.rpId == process.env.RPID) {

				// coerce into client-expected format
				allPromises.push(
					getUserAttributes(req, userIdMap, reg.userId)
					.then((ua) => {
						var formattedRegistration = {
							"username": ua.username,
							"displayName": ua.displayName,
							"userId": reg.userId,
							"rpId": reg.attributes.rpId,
							"nickname": reg.attributes.nickname,
							"id": reg.id,
							"credentialId": reg.attributes.credentialId,
							"credentialPublicKey": reg.attributes.credentialPublicKey,
							"aaguid": reg.attributes.aaGuid,
							// not currently available
							// "attestationFormat": reg.attributes.attestationFormat, 
							"attestationType": reg.attributes.attestationType, 
							// not currently available
							// "wasUserPresent": reg.attributes.userPresent, 
							"wasUserVerified": reg.attributes.userVerified, 
							"enabled": reg.enabled,
							"counter": reg.attributes.counter,
							"lastUsed": reg.updated,
							"created": reg.created,
							"x5c": reg.attributes.x5c,
							"metadata": {
								"icon": reg.attributes.icon,
								"description": reg.attributes.description
							}
						};

						return formattedRegistration;
					}).then((formattedRegistration) => {

						// if the metadata information is missing, it may be because we did an all
						// registrations search, so we'll try a per-registration search which will
						// have it if it's available
						if (formattedRegistration.metadata.description == null) {
							return requestp({
								url: process.env.CI_TENANT_ENDPOINT + "/v2.0/factors/fido2/registrations/" + reg.id,
								method: "GET",
								headers: {
									"Accept": "application/json",
									"Authorization": "Bearer " + access_token
								},
								json: true			
							}).then((detailedReg) => {
								formattedRegistration.metadata.icon = detailedReg.attributes.icon;
								formattedRegistration.metadata.description = detailedReg.attributes.description;
								return formattedRegistration;
							})
						} else {
							return formattedRegistration;
						}
					}).then((formattedRegistration) => {
						// that's the best we can do - push it
						result.push(formattedRegistration);
					})
				);
			}
		});

		return Promise.all(allPromises);

	}).then(() => {
		rsp.json(result);
	});
}

function adminDeleteRegistration(req,rsp) {
	let regId = req.body.id;
	if (regId != null) {
		tm.getAccessToken(req).then((access_token) => {
			return requestp({
				url: process.env.CI_TENANT_ENDPOINT + "/v2.0/factors/fido2/registrations/" + regId,
				method: "DELETE",
				headers: {
					"Accept": "application/json",
					"Authorization": "Bearer " + access_token
				},
				json: true
			});
		}).then((deleteResult) => { 
			// we care not about the deleteResult - just send the id back
			logger.logWithTS("adminDeleteRegistration deleted registration: " + regId);
			rsp.json({"id": regId}); 
		}).catch((e)  => {
			handleErrorResponse("adminDeleteRegistration", rsp, e, "Unable to delete registration");
		});
	} else {
		rsp.json(new fido2error.fido2Error("Invalid id in request"));
	}	
}

module.exports = { 
	validateUserAccount: validateUserAccount,
	getUserAccessToken: getUserAccessToken,
	newAccessToken: newAccessToken,
	sendUserResponse: sendUserResponse, 
	sendMetadata: sendMetadata, 
	deleteRegistration: deleteRegistration,
	registrationDetails: registrationDetails,
	proxyFIDO2ServerRequest: proxyFIDO2ServerRequest,
	photoVerifier: photoVerifier,
	adminGetUsers: adminGetUsers,
	adminGetRegistrations: adminGetRegistrations,
	adminDeleteRegistration: adminDeleteRegistration
};
