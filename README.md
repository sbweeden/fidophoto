# fidophoto

This is a demonstration Node.js application that utilises IBM Cloud Identity for authentication and FIDO2 services to support a signed photograph mobile application.

To use locally:

1. Update your local hosts file to have www.fidophoto.com as a hostname alias (I do this for the loopback address 127.0.0.1) where your Node application is going to listen.
1. Make sure you have Node.js installed.
1. clone the repo into a directory and cd to that directory
1. npm install
1. cp .env.example to .env 
1. edit the .env file and update SECRET, CI_TENANT_ENDPOINT, OAUTH_CLIENT_ID, OAUTH_CLIENT_SECRET, OIDC_CLIENT_ID, OIDC_CLIENT_SECRET.
1. npm run start_local


CI tenant requirements:

1. Create an API client_id and client_secret (these go into the .env file as OAUTH_CLIENT_ID and OAUTH_CLIENT_SECRET) with the following entitlements:
    1. Authenticate any user
    1. Manage second-factor authentication enrollment for all users
    1. Manage second-factor authentication method configuration
    1. Manage users and standard groups
1. Configure an identity source (I used Google SSO) if you want to allow "any user" to self-register into your app. Note this could get noisy, so you may instead want to manually provision users and manage entitlements via groups.
1. Configure an "application", using custom OIDC connector. 
	1. Use the authorization code flow WITHOUT PKCE. 
	1. Use application URL https://www.fidophoto.com:9443, and redirect URL https://www.fidophoto.com:9443/callback. 
	1. I would suggest "Do not ask for consent". This provides a more seamless SSO experience.
	1. Token settings are not important as this application uses an admin-like API client rather than the user access token provided in OIDC. This is done to allow JIT-P of the FIDO definition, and custom SCIM attribute for the long-lived user access token. 
	1. No specific attributes need to be added to the id_token. 
	1. Under Access Policies, I customized the identity sources for this application to just "Google". This provides a seamless SSO experience from the fidophoto app through Cloud Identity to Google and back, without the user having to stop at a Cloud Identity selection page for identity sources.
	1. No API Access is needed as we do not make use of the OIDC-provided delegated access token in this application.
	1. Under Entitlments, I selected "All users are entitled to this application". Of course you could be more restrictive, particularly if using the Cloud Directory identity source.

Other possible customizations:

1. If you want to customize the "department" that the user belongs to as seen when verifying a photo, see ciservices.js, and search for "result.reg.department". You could use any attribute from the user profile (to trace what is avaialable: console.log(JSON.stringify(userSCIMRecord));
1. In the Cloud Identity application definition you could enforce conditional 2FA for SSO to the application if desired.


Testing end-to-end with Postman and signing and verifying a photograph:

1. In Postman, create globals call fidotools and fidoutils from the corresponding JS files in the phototools/postman/globals directory.
1. Import the environment and update the access_token to be your user access token from the Account Settings page in the app. 
1. Also in the environment, validate the origin in fidoutilsConfig, and the values for hostport and rpId. These vary depending on the hostname used for exposing the application.
1. Import the collection, and walk through the APIs from top to bottom, i.e. 
	1. WhoAmI - this uses your access_token, and verifies you can authenticate with it to the application. Make sure this works and that a user profile is returned.
	1. FetchAttestationOptions - obtains challenge used for registration. Again, make sure this works and you can an options object back.
	1. PostAttestationResult - creates a FIDO keypair, and registers the public key. After this has run you should be able to see your registration in the FIDO2 Registrations page of the web app.
	1. FetchAssertionOptions - obtains an authentication challenge, and the allowedCredentials list which should include the credential just registered.
	1. PostAssertionResult - completes authentication with the registered credential.
1. AFTER all the APIs in the Postman collection have been run successfully, inspect the environment object, and pull out the "Current value" of these two working variables: last_CredentialId and last_privKeyHex. 
1. Update the command-line application phototools/sign_image.js with:
	1. The value of var credentialId should be replaced with the value from last_CredentialId collected in the previous step.
	1. The value of var privateKeyHex should be replaced with the value from last_privKeyHex collected in the previous step.
	1. Verify that rpId matches your rpId from the Postman environment.
	1. Set filename to point to the jpg file you wish to sign. This can be any existing JPG file you have, but one which contains GPS exif data looks better in the verifier later.
	1. Set fileout to point to the destination filename you wish the signed image to be saved as.
1. Run the signing app with "node sign_image.js". On success it completes silently, and your fileout should be populated.
1. In the web app, go to the "Verify a photo" page, and upload the signed image. It should validate successfully and show the user details of the owner of the credential registration.
