// server.js
// where your node app starts

// init project
const express = require('express');
const session = require('express-session');
const https = require('https');
const fs = require('fs');
const passport = require('passport');
const cookieParser = require("cookie-parser");
const oidcStrategy = require('passport-openidconnect').Strategy;
const tm = require('./oauthtokenmanager.js');
const identityServices = require('./ciservices.js');
const logger = require('./logging.js');
const app = express();
const authsvc = require('./authsvc.js');
const adminsvc = require('./adminsvc.js');
const request = require('request');

// set to ignore ssl cert errors when making requests
process.env["NODE_TLS_REJECT_UNAUTHORIZED"] = 0;

app.use(session({
	secret: process.env.SECRET,
	resave: false,
	saveUninitialized: true
}));

app.use(express.json());
app.use(express.urlencoded({ extended: true }));
app.use(cookieParser());

// http://expressjs.com/en/starter/static-files.html
app.use('/static', express.static('static'));

// For OIDC login
app.use(passport.initialize());
app.use(passport.session());

passport.use("oidc", new oidcStrategy({
	issuer: process.env.CI_TENANT_ENDPOINT + "/oidc/endpoint/default",
	authorizationURL: process.env.CI_TENANT_ENDPOINT + "/oidc/endpoint/default/authorize",
	tokenURL: process.env.CI_TENANT_ENDPOINT + "/oidc/endpoint/default/token",
	userInfoURL: process.env.CI_TENANT_ENDPOINT + "/oidc/endpoint/default/userinfo",
	clientID: process.env.OIDC_CLIENT_ID,
	clientSecret: process.env.OIDC_CLIENT_SECRET,
	callbackURL: "https://"+process.env.RPID+ (process.env.LOCAL_SSL_SERVER == "true" ? (":"+process.env.LOCAL_SSL_PORT) : "") +"/callback",
	scope: "openid profile"
	}, 
	(issuer, sub, profile, accessToken, refreshToken, done) => {
		let data = {
			issuer: issuer,
			sub: sub,
			profile: profile,
			accessToken: accessToken,
			refreshToken: refreshToken
		};
		console.log("OIDC callback function called with: " + JSON.stringify(data));
		return done(null, data);
	}
));

passport.serializeUser((user, next) => {
	next(null, user);
});

passport.deserializeUser((obj, next) => {
	next(null, obj);
});

app.use("/loginoidc", passport.authenticate("oidc"));

app.use("/callback", 
	passport.authenticate("oidc", { failureRedirect: "/error" }),
	(req, res) => {
		console.log("Callback post-authentication function called with req.user: " + JSON.stringify(req.user));
		req.session.username = req.user.profile._json.preferred_username;
		req.session.userDisplayName = req.user.profile.displayName;
		req.session.userSCIMId = req.user.profile.id;

		// this is redundant, but doesn't hurt
		req.user.username = req.user.profile._json.preferred_username;
		req.user.userDisplayName = req.user.profile.displayName;
		req.user.userSCIMId = req.user.profile.id;

		identityServices.validateUserAccount(req)
		.then(() => {
			return identityServices.getUserAccessToken(req, false);
		}).then((uat) => {
			req.session.userAccessToken = uat;
			res.redirect('/');
		}).catch((e)  => {
			logger.logWithTS("OIDC login failed with error. e: " + 
				e + " stringify(e): " + (e != null ? JSON.stringify(e): "null"));
			res.redirect('/error');
		});
});

// This permits optional authentication of requests via user access tokens
app.use(authsvc.validateAccessToken());

// This checks that certain requests are only made by an admin
app.use(adminsvc.validateAdminAccess());

//console.log(process.env);

// http://expressjs.com/en/starter/basic-routing.html
app.get('/', (req, rsp) => {
  	rsp.sendFile(__dirname + '/views/index.html');
});

/*
* Glitch doesn't allow dumping of images in a directory other than it's content delivery network
* So we try to detect these local files and serve them from local content if they exist, otherwise
* fallback to a location where I have uploaded them on Glitch.
*/
app.get('/favicon.ico', (req, rsp) => {
  	//rsp.sendFile(__dirname + '/static/favicon.ico');

	fs.access(__dirname + '/static/favicon.ico', fs.constants.F_OK, (err) => {
	 	if (err == null) {
			rsp.sendFile(__dirname + '/static/favicon.ico');
	  	} else {
	  		request.get("https://cdn.glitch.com/8035aca4-73b7-4374-abd0-7779d1378069%2Ffavicon.ico?v=1585551659111").pipe(rsp);
	  	}
	});
});

app.get('/static/ibm-logo.png', (req, rsp) => {
	fs.access(__dirname + '/static/ibm-logo.png', fs.constants.F_OK, (err) => {
	 	if (err == null) {
			rsp.sendFile(__dirname + '/static/ibm-logo.png');
	  	} else {
	  		request.get("https://cdn.glitch.com/8035aca4-73b7-4374-abd0-7779d1378069%2Fibm-logo.png?v=1585551692987").pipe(rsp);
	  	}
	});
});

app.get('/static/ibm_logo.jpg', (req, rsp) => {
	fs.access(__dirname + '/static/ibm_logo.jpg', fs.constants.F_OK, (err) => {
	 	if (err == null) {
			rsp.sendFile(__dirname + '/static/ibm_logo.jpg');
	  	} else {
	  		request.get("https://cdn.glitch.com/8035aca4-73b7-4374-abd0-7779d1378069%2Fibm_logo.jpg?v=1585552484835").pipe(rsp);
	  	}
	});
});

app.get('/error', (req,rsp) => {
	rsp.sendFile(__dirname + '/views/error.html');
});

app.get('/logout', (req, rsp) => {
	req.logout();
	req.session.destroy();
  	rsp.json({"authenticated": false});
});

app.get('/me', (req, rsp) => {
	identityServices.sendUserResponse(req, rsp);
});

app.get('/metadata', (req, rsp) => {
	identityServices.sendMetadata(req, rsp);
});

app.get('/newAccessToken', (req, rsp) => {
	identityServices.newAccessToken(req, rsp);
});

app.get('/registrationDetails', (req, rsp) => {
	identityServices.registrationDetails(req, rsp);
});

app.post('/deleteRegistration', (req, rsp) => {
	identityServices.deleteRegistration(req, rsp);
});

app.post('/attestation/options', (req, rsp) => {
	identityServices.proxyFIDO2ServerRequest(req,rsp,true,false);
});

app.post('/attestation/result', (req, rsp) => {
	identityServices.proxyFIDO2ServerRequest(req,rsp,false,false);
});

app.post('/assertion/options', (req, rsp) => {
	identityServices.proxyFIDO2ServerRequest(req,rsp,true,true);
});

app.post('/assertion/result', (req, rsp) => {
	identityServices.proxyFIDO2ServerRequest(req,rsp,false,false);
});

app.post('/assertion/login', (req, rsp) => {
	identityServices.validateFIDO2Login(req,rsp);
});

// admin operations
app.get('/admin', (req, rsp) => {
  	rsp.sendFile(__dirname + '/views/admin.html');
});

app.get('/admin/users', (req, rsp) => {
  	identityServices.adminGetUsers(req,rsp);
});

app.get('/admin/registrations', (req, rsp) => {
  	identityServices.adminGetRegistrations(req,rsp);
});

app.post('/admin/deleteRegistration', (req, rsp) => {
  	identityServices.adminDeleteRegistration(req,rsp);
});

// the photo verifier page
app.post('/photo_verifier', (req, rsp) => {
	identityServices.photoVerifier(req,rsp);
});

// listen for requests
if (process.env.LOCAL_SSL_SERVER == "true") {
	https.createServer({
	    key: fs.readFileSync('./server.key'),
	    cert: fs.readFileSync('./server.cert')
	}, app)
	.listen(process.env.LOCAL_SSL_PORT, function() {
	  	console.log('Your SSL app is listening on port ' + process.env.LOCAL_SSL_PORT);
	});
} else {
	const listener = app.listen(process.env.PORT, function() {
	  	console.log('Your app is listening on port ' + listener.address().port);
	});
}
