//
// Basic user tools
//

function getUserDetails(req) {
	let result = {
		username: null,
		userDisplayName: null,
		userSCIMId: null,
		userAccessToken: null		
	};
	// prefer session information if availabe, otherwise look in user object
	// OAuth authentication uses user object
	if (req.session != null) {
		if (result.username ==  null && req.session.username != null) {
			result.username = req.session.username;
		}
		if (result.userDisplayName ==  null && req.session.userDisplayName != null) {
			result.userDisplayName = req.session.userDisplayName;
		}
		if (result.userSCIMId ==  null && req.session.userSCIMId != null) {
			result.userSCIMId = req.session.userSCIMId;
		}
		if (result.userAccessToken ==  null && req.session.userAccessToken != null) {
			result.userAccessToken = req.session.userAccessToken;
		}
	}

	if (req.user != null) {
		if (result.username ==  null && req.user.username != null) {
			result.username = req.user.username;
		}
		if (result.userDisplayName ==  null && req.user.userDisplayName != null) {
			result.userDisplayName = req.user.userDisplayName;
		}
		if (result.userSCIMId ==  null && req.user.userSCIMId != null) {
			result.userSCIMId = req.user.userSCIMId;
		}		
		if (result.userAccessToken ==  null && req.user.userAccessToken != null) {
			result.userAccessToken = req.user.userAccessToken;
		}		
	}

	// plus some functions
	result["isAdmin"] = () => {
		var adminUsers = (process.env.ADMINS ? process.env.ADMINS : "").split(',');
		return (adminUsers.indexOf(result.username) >= 0);
	}

	result["isAuthenticated"] = () => {
		return (result.username != null);
	}

	return result;
}

module.exports = { 
	getUserDetails: getUserDetails
};
