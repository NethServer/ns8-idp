// LDAP_ID (objectGUID string) in uppercase, like Nextcloud user_ldap
var ldapId = user.getFirstAttribute("LDAP_ID");
exports = ldapId ? ldapId.toUpperCase() : null;
