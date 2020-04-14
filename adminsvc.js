//
// Express middleware for the app that verifies certain requests (those with a URL path starting with /admin) are made by an administrator
//
const userutils = require('./userutils.js');


function validateAdminAccess() {
	return (req, rsp, next) => {
		try {
			if (req.url && req.url.startsWith("/admin")) {
				let userDetails = userutils.getUserDetails(req);

				if (!userDetails.isAdmin()) {
					throw (userDetails.isAuthenticated() ? "Not an administrator" : "Not logged in");
				}
			}

			return next();
		} catch (e) {
			//rsp.send("<html>Error: " + e + "</html>");
			//rsp.end();
			rsp.redirect("/");
		}
	}
}

module.exports = { 
	validateAdminAccess: validateAdminAccess
};

