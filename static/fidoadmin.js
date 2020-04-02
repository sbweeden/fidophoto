var locationHostPort = location.hostname+(location.port ? ':'+location.port: ''); 
var baseURL = location.protocol+'//'+locationHostPort;

var userData = {};

function htmlEncode(value){
    if (value) {
        return value.replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;').replace(/"/g, '&quot;');
    } else {
        return '';
    }
}

function getDisplayName() {
    // username is guaranteed, but displayName preferred
    return (userData.displayName != null ? userData.displayName : userData.username);
}

function showDiv(id) {
    document.getElementById(id).style.display = "block";
}

function hideDiv(id) {
    document.getElementById(id).style.display = "none";
}

function populateUserInfo() {
    $.ajax({
        type: "GET",
        url: baseURL + '/me',
    }).done((data, textStatus, jqXHR) => {
        var rspStatus = jqXHR.status;
        if (rspStatus == 200) {
            userData = data;
            if (userData.authenticated) {
                document.getElementById("usernamediv").textContent = getDisplayName();
                showDiv("userinfodiv");
            }
        }
    });
}

function doLogout() {
    $.ajax({
        type: "GET",
        url: baseURL + '/logout',
        beforeSend: (request) => {
        request.setRequestHeader("Accept", "application/json");
        }
    }).done((data, textStatus, jqXHR) => {
        var rspStatus = jqXHR.status;
        if (rspStatus == 200) {
            window.location = baseURL;
        } else {
            updateMsg("Unexpected HTTP response code: " + rspStatus);
        }
    });
}

/*************** FUNCTIONS FOR USER ADMINISTRATION ****************/

var existingUsers = [];

function loadUsers() {
    $.ajax({
        type: "GET",
        url: baseURL + '/admin/users',
        beforeSend: (request) => {
            request.setRequestHeader("Accept", "application/json");
        }               
    }).done((data, textStatus, jqXHR) => {
        var rspStatus = jqXHR.status;
        if (rspStatus == 200) {
            existingUsers = data;
            processExistingUsers();
        } else {
            console.log("error retrieving users");
        }
    });
}

function userDetails(idx) {
    var jsonAttributes = []; // none at the moment
    
    // dump details of this user into the msgdiv
    var details = "User Details<br />";
    details += "<table class=\"dataTable\" border=\"1\">";
    details += "<tr><th>Attribute</th><th>Value</th></tr>";
    var keys = Object.keys(existingUsers[idx]);
    if (keys != null && keys.length > 0) {
        for (var i = 0; i < keys.length; i++) {
            var keyname = keys[i];
            var val = existingUsers[idx][keys[i]];
            
            // some special formatting for certain well-known attributes
            if (jsonAttributes.indexOf(keyname) >=0) {
                // these are JSON objects
                if (val != null) {
                    val = htmlEncode(JSON.stringify(val));
                }
            } 

            // don't re-encode json attributes since we already did that above when formatting
            details += "<tr><td>" + htmlEncode(keyname) + "</td><td>" + 
                (jsonAttributes.indexOf(keyname) >= 0 ? val : htmlEncode(''+val)) + "</td></tr>";
        }
    }
    details += "</table>";
    document.getElementById("msgdiv").innerHTML = details;      
}

function defaultUserSort(a,b) {
    var aUser = a.username;
    var bUser = b.username;

    if (aUser < bUser) {
        return -1;
    } else if (aUser > bUser) {
        return 1;
    }
    return 0;
}
                
function sortByMostRegistrations(a,b) {
    // more registrations comes first
    if (a.numRegistrations > b.numRegistrations) {
        return -1;
    } else if (a.numRegistrations < b.numRegistrations) {
        return 1;
    } 
    return defaultUserSort(a,b);
}

function registrationsForUser(idx) {
    adminRegistrations(existingUsers[idx].userId, existingUsers[idx].username);
}

function processExistingUsers() {
    // hide table in the case this is a re-sort
    document.getElementById("eudiv").style.display = "hidden";
    if (existingUsers.length > 0) {
        
        // sort according to desired sort criteria
        var sortCriteria = document.getElementById("sortSelect").value;
        if (sortCriteria == "numregistrations") {
            existingUsers.sort(function(a,b) {
                return sortByMostRegistrations(a,b);
            });                     
        } else {
            // just use default sort
            existingUsers.sort(function(a,b) {
                return defaultUserSort(a,b);
            });
        }
    
        // display existing users
        var t = document.getElementById("eutable");
        var tbody = document.createElement('tbody');
        for (var i = 0; i < existingUsers.length; i++) {
            var row = tbody.insertRow(-1);
            row.insertCell(0).textContent = existingUsers[i]["username"];
            row.insertCell(1).textContent = existingUsers[i]["displayName"];
            row.insertCell(2).textContent = existingUsers[i]["oauthAccessToken"];
            row.insertCell(3).textContent = existingUsers[i]["numRegistrations"];
            
            row.insertCell(4).innerHTML = "<input type=\"button\" value=\"Details\" onClick=\"userDetails("+i+")\">" +
                "<br /><input type=\"button\" value=\"Show Registrations\" onClick=\"registrationsForUser("+i+")\">";
        }
        
        // replace existing tbody with this new one
        t.replaceChild(tbody, t.getElementsByTagName("tbody")[0]);
    }
    document.getElementById("eudiv").style.display = "block";
}

function adminUsers() {
    hideDiv('operationDiv');
    let contentHTML = '<div id="eudiv">'+ 
        '<h2 class="sectionTitle">User Registrations</h2>' +
        '<br />' +
        'Sort by:&nbsp;<select id="sortSelect" onchange="processExistingUsers()">' +
            '<option value="numregistrations" selected>Most registrations</option>' +
            '<option value="default">Username</option>' +
        '</select>' +
        '<br />' +
        
        '<table class="dataTable" id="eutable" border="1">' +
          '<thead>' +
            '<tr class="headerRow"><th>Username</th><th>Display Name</th><th>OAuth Access Token</th><th>Number of Registrations</th><th>Operation</th></tr>' +
          '</thead>' +
          '<tbody></tbody>' +
        '</table>' +
      '</div>' +
      '<br />' +
      '<h2 class="sectionTitle">Details</h2>' +
      '<div id="msgdiv"></div>';


    $('#operationDiv').html(contentHTML);
    loadUsers();
    showDiv('operationDiv');
}

/*************** END FUNCTIONS FOR USER ADMINISTRATION ****************/


/*************** FUNCTIONS FOR REGSITRATION ADMINISTRATION ****************/

var existingRegistrations = [];

function loadRegistrations(userId) {
    $.ajax({
        type: "GET",
        url: baseURL + '/admin/registrations',
        data: { "userId": (userId == null ? "" : userId) },
        beforeSend: (request) => {
            request.setRequestHeader("Accept", "application/json");
        }               
    }).done((data, textStatus, jqXHR) => {
        var rspStatus = jqXHR.status;
        if (rspStatus == 200) {
            existingRegistrations = data;
            processExistingRegistrations();
        } else {
            console.log("error retrieving registrations");
        }
    });
}


function registrationDetails(idx) {
    var jsonAttributes = [ "x5c", "metadata" ]; 
    
    // dump details of this registration into the msgdiv
    var details = "Registration Details<br />";
    details += "<table class=\"dataTable\" border=\"1\">";
    details += "<tr><th>Attribute</th><th>Value</th></tr>";
    var keys = Object.keys(existingRegistrations[idx]);
    if (keys != null && keys.length > 0) {
        for (var i = 0; i < keys.length; i++) {
            var keyname = keys[i];
            var val = existingRegistrations[idx][keys[i]];
            
            // some special formatting for certain well-known attributes
            if (jsonAttributes.indexOf(keyname) >=0) {
                // these are JSON objects
                if (val != null) {
                    val = htmlEncode(JSON.stringify(val));
                    //val = htmlEncode(JSON.stringify(val,null,2)).replace(/\n/g,'<br>');
                }
            } else if (keyname == "aaguid") {
                if (val != null) {
                    if (val.toUpperCase() === "6028B017-B1D4-4C02-B4B3-AFCDAFC96BB2") {
                        val = val + " (Windows Hello software authenticator)";
                    } else if (val.toUpperCase() === "08987058-CADC-4B81-B6E1-30DE50DCBE96") {
                        val = val + " (Windows Hello hardware authenticator)";
                    } else if (val.toUpperCase() === "6E96969E-A5CF-4AAD-9B56-305FE6C82795") {
                        val = val + " (Windows Hello VBS software authenticator)";
                    } else if (val.toUpperCase() === "9DDD1817-AF5A-4672-A2B9-3E3DD95000A9") {
                        val = val + " (Windows Hello VBS hardware authenticator)";
                    } else if (val.toUpperCase() === "ADCE0002-35BC-C60A-648B-0B25F1F05503") {
                        val = val + " (Mac touchbar)";
                    }
                }
            } 
            // don't re-encode json attributes since we already did that above when formatting
            details += "<tr><td>" + htmlEncode(keyname) + "</td><td>" + 
                (jsonAttributes.indexOf(keyname) >= 0 ? val : htmlEncode(''+val)) + "</td></tr>";
        }
    }
    details += "</table>";
    document.getElementById("msgdiv").innerHTML = details;      
}

function unregister(idx) {
    $.ajax({
        type: "POST",
        url: baseURL + '/admin/deleteRegistration',
        data: JSON.stringify({"id": existingRegistrations[idx].id}),
        beforeSend: (request) => {
        request.setRequestHeader("Content-type", "application/json");
        request.setRequestHeader("Accept", "application/json");
        }
    }).done((data, textStatus, jqXHR) => {
        var rspStatus = jqXHR.status;
        if (rspStatus == 200) {
            // remove from the array, then redraw
            existingRegistrations.splice(idx, 1);
            processExistingRegistrations();
        }
    });
}

function defaultRegistrationSort(a,b) {
    
    // sort first by username, then rpid, nickname, credentialId
    if (a.username < b.username) {
        return -1;
    } else if (a.username > b.username) {
        return 1;
    } else {
        if (a.rpId < b.rpId) {
            return -1;
        } else if (a.rpId > b.rpId) {
            return 1;
        } else {
            if (a.nickname < b.nickname) {
                return -1;
            }   else if (a.nickname > b.nickname) {
                return 1;
            } else {
                if (a.credentialId < b.credentialId) {
                    return -1;
                } else if (a.credentialId > b.credentialId) {
                    return 1;
                }
            }
        }
    }
    return 0;
}

function sortByMostRecent(aTime,bTime,a,b) {
    // unknowns are always last, otherwise most-recent is smallest
    if (aTime == "unknown" && bTime == "unknown") {
        return defaultRegistrationSort(a,b);
    } else if (aTime == "unknown") {
        return 1;
    } else if (bTime == "unknown") {
        return -1;
    } else if (bTime < aTime) {
        return -1;
    } else if (bTime > aTime) {
        return 1;
    } else {
        // must be same time - fallback to default sort
        return defaultRegistrationSort(a,b);
    }
}

function processExistingRegistrations() {

    // hide table in the case this is a re-sort
    document.getElementById("erdiv").style.display = "hidden";
    if (existingRegistrations.length > 0) {

        
        // sort according to desired sort criteria
        var sortCriteria = document.getElementById("sortSelect").value;
        console.log('processExistingRegistrations sortCriteria: ' + sortCriteria);
        if (sortCriteria == "lastused") {
            existingRegistrations.sort(function(a,b) {
                var aLastUsed = (a["lastUsed"] || "unknown");
                var bLastUsed = (b["lastUsed"] || "unknown");
                
                return sortByMostRecent(aLastUsed,bLastUsed,a,b);
            });                     
        } else if (sortCriteria == "created") {
            existingRegistrations.sort(function(a,b) {
                var aCreated = (a["created"] || "unknown");
                var bCreated = (b["created"] || "unknown");
                
                return sortByMostRecent(aCreated,bCreated,a,b);
            });                     
        } else {
            // just use default sort
            existingRegistrations.sort(function(a,b) {
                return defaultRegistrationSort(a,b);
            });
        }
                
        // display existing registrations
        var t = document.getElementById("ertable");
        var tbody = document.createElement('tbody');
        for (var i = 0; i < existingRegistrations.length; i++) {
            var row = tbody.insertRow(-1);
            row.insertCell(0).innerHTML = htmlEncode(existingRegistrations[i]["username"]);
            row.insertCell(1).innerHTML = htmlEncode(existingRegistrations[i]["displayName"]);
            row.insertCell(2).innerHTML = htmlEncode(existingRegistrations[i]["rpId"]);
            row.insertCell(3).innerHTML = htmlEncode(existingRegistrations[i]["nickname"]);
            
            var vendorDescription = '';
            var vendorIcon = '';
            if (existingRegistrations[i]["metadata"] != null) {
                if (existingRegistrations[i]["metadata"]["description"] != null) {
                    vendorDescription = htmlEncode(existingRegistrations[i]["metadata"]["description"]);
                }
                if (existingRegistrations[i]["metadata"]["icon"] != null) {
                    vendorIcon = "<img style= \"max-height: 50px; max-width: 100px;\" src=\"" + existingRegistrations[i]["metadata"]["icon"] + "\"/>";
                }
            }
            var vendorTD = row.insertCell(4);
            vendorTD.align = "center";
            vendorTD.innerHTML = vendorDescription + (vendorIcon.length > 0 ? "<br/>" + vendorIcon : '');

            
            row.insertCell(5).innerHTML = htmlEncode(existingRegistrations[i]["created"]);
            row.insertCell(6).innerHTML = htmlEncode(existingRegistrations[i]["lastUsed"]);

            row.insertCell(7).innerHTML = "<input type=\"button\" value=\"Details\" onClick=\"registrationDetails("+i+")\">" 
                + "<br />"
                + "<input type=\"button\" value=\"Delete\" onClick=\"unregister("+i+")\">";
        }
        
        // replace existing tbody with this new one
        t.replaceChild(tbody, t.getElementsByTagName("tbody")[0]);
    }
    document.getElementById("erdiv").style.display = "block";
}

function adminRegistrations(userId, username) {
    hideDiv('operationDiv');
    let contentHTML = '<div id="erdiv">'+
        '<h2 class="sectionTitle">FIDO Registrations' + (username != null ? (' for: ' + htmlEncode(username)) : '') + '</h2>' +
        '<br />' +
        'Sort by:&nbsp;<select id="sortSelect" onchange="processExistingRegistrations()">' +
            '<option value="lastused" selected>Most recently Used</option>' +
            '<option value="created">Most recently Created</option>' +
            '<option value="default">Owner</option>' +
        '</select>' +
        '<br />' +
        
        '<table class="dataTable" id="ertable" border="1">' +
          '<thead>' +
            '<tr class="headerRow"><th>Username</th><th>Display Name</th><th>Relying Party ID</th><th>Registration Nickname</th><th>Vendor</th><th>Created</th><th>Last Used</th><th>Operation</th></tr>' +
          '</thead>' +
          '<tbody></tbody>' +
        '</table>' +
      '</div>' +
      '<br />' +
      '<h2 class="sectionTitle">Details</h2>' +
      '<div id="msgdiv"></div>';
    $('#operationDiv').html(contentHTML);
    loadRegistrations(userId);
    showDiv('operationDiv');
}

/*************** END FUNCTIONS FOR REGSITRATION ADMINISTRATION ****************/
