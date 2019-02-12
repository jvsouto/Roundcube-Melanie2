<?php

/*
 * +-----------------------------------------------------------------------+
 * | Local configuration for the Roundcube Webmail installation. |
 * | |
 * | This is a sample configuration file only containing the minumum |
 * | setup required for a functional installation. Copy more options |
 * | from defaults.inc.php to this file to override the defaults. |
 * | |
 * | This file is part of the Roundcube Webmail client |
 * | Copyright (C) 2005-2013, The Roundcube Dev Team |
 * | |
 * | Licensed under the GNU General Public License version 3 or |
 * | any later version with exceptions for skins & plugins. |
 * | See the README file for a full license statement. |
 * +-----------------------------------------------------------------------+
 */
$config = array();

// $config['devel_mode'] = true;

// Database connection string (DSN) for read+write operations
// Format (compatible with PEAR MDB2): db_provider://user:password@host/database
// Currently supported db_providers: mysql, pgsql, sqlite, mssql or sqlsrv
// For examples see http://pear.php.net/manual/en/package.database.mdb2.intro-dsn.php
// NOTE: for SQLite use absolute path: 'sqlite:////full/path/to/sqlite.db?mode=0646'
$config['db_dsnw'] = 'pgsql://roundcube:roundcube@sgbd-ida01.ida.melanie2.i2/roundcube';

// The mail host chosen to perform the log-in.
// Leave blank to show a textbox at login, give a list of hosts
// to display a pulldown menu or set one host as string.
// To use SSL/TLS connection, enter hostname with prefix ssl:// or tls://
// Supported replacement variables:
// %n - hostname ($_SERVER['SERVER_NAME'])
// %t - hostname without the first part
// %d - domain (http hostname $_SERVER['HTTP_HOST'] without the first part)
// %s - domain name after the '@' from e-mail address provided at login screen
// For example %n = mail.domain.tld, %t = domain.tld
$config['default_host'] = array(
		'Server',
		'ssl://amelie-01.ac.melanie2.i2',
		'ssl://amelie-02.ac.melanie2.i2',
		'ssl://amelie-03.ac.melanie2.i2',
		'ssl://amelie-04.ac.melanie2.i2',
		'ssl://amelie-05.ac.melanie2.i2',
		'ssl://amelie-06.ac.melanie2.i2',
		'ssl://amelie-08.ac.melanie2.i2'
);

// IMAP socket context options
// See http://php.net/manual/en/context.ssl.php
// The example below enables server certificate validation
//$config['imap_conn_options'] = array(
//  'ssl'         => array(
//     'verify_peer'  => true,
//     'verify_depth' => 3,
//     'cafile'       => '/etc/openssl/certs/ca.crt',
//   ),
// );
$config['imap_conn_options'] = array(
    'ssl' => array(
        'verify_peer'  => false,
    ),
);

// SMTP server host (for sending mails).
// To use SSL/TLS connection, enter hostname with prefix ssl:// or tls://
// If left blank, the PHP mail() function is used
// Supported replacement variables:
// %h - user's IMAP hostname
// %n - hostname ($_SERVER['SERVER_NAME'])
// %t - hostname without the first part
// %d - domain (http hostname $_SERVER['HTTP_HOST'] without the first part)
// %z - IMAP domain (IMAP hostname without the first part)
// For example %n = mail.domain.tld, %t = domain.tld
$config['smtp_server'] = 'tls://%h';

// SMTP port (default is 25; use 587 for STARTTLS or 465 for the
// deprecated SSL over SMTP (aka SMTPS))
$config['smtp_port'] = 25;

// SMTP username (if required) if you use %u as the username Roundcube
// will use the current username for login
$config['smtp_user'] = '%u';

// SMTP password (if required) if you use %p as the password Roundcube
// will use the current user's password for login
$config['smtp_pass'] = '%p';

// List of active plugins (in plugins/ directory)
$config['plugins'] = array(
		//'managesieve',
		//'password',
		// 'infinitescroll',
		// 'threecol',
		// 'owncloud',
		//'calendar',
		// 'enigma',
		'mobile'
);

// Log successful/failed logins to <log_dir>/userlogins or to syslog
$config['log_logins'] = true;

// Log session authentication errors to <log_dir>/session or to syslog
$config['log_session'] = true;

// Log SQL queries to <log_dir>/sql or to syslog
$config['sql_debug'] = true;

// Log IMAP conversation to <log_dir>/imap or to syslog
$config['imap_debug'] = true;

// Log LDAP conversation to <log_dir>/ldap or to syslog
$config['ldap_debug'] = true;

// Log SMTP conversation to <log_dir>/smtp or to syslog
$config['smtp_debug'] = true;

/*
 * Config Fédérateur directory
 */
$rcmail_config['ldap_public']['amande'] = array(
		'name' => 'Amande',
		// Replacement variables supported in host names:
		// %h - user's IMAP hostname
		// %n - hostname ($_SERVER['SERVER_NAME'])
		// %t - hostname without the first part
		// %d - domain (http hostname $_SERVER['HTTP_HOST'] without the first part)
		// %z - IMAP domain (IMAP hostname without the first part)
		// For example %n = mail.domain.tld, %t = domain.tld
		'hosts' => array(
				'ldap.m2.e2.rie.gouv.fr'
		),
		'port' => 389,
		'use_tls' => false,
		'ldap_version' => 3, // using LDAPv3
		'network_timeout' => 10, // The timeout (in seconds) for connect + bind arrempts. This is only supported in PHP >= 5.3.0 with OpenLDAP 2.x
		'user_specific' => false, // If true the base_dn, bind_dn and bind_pass default to the user's IMAP login.
		                          // %fu - The full username provided, assumes the username is an email
		                          // address, uses the username_domain value if not an email address.
		                          // %u - The username prior to the '@'.
		                          // %d - The domain name after the '@'.
		                          // %dc - The domain name hierarchal string e.g. "dc=test,dc=domain,dc=com"
		                          // %dn - DN found by ldap search when search_filter/search_base_dn are used
		'base_dn' => 'ou=organisation,dc=equipement,dc=gouv,dc=fr',
		// 'bind_dn' => '',
		// 'bind_pass' => '',
		// It's possible to bind for an individual address book
		// The login name is used to search for the DN to bind with
		'search_base_dn' => '',
		'search_filter' => '', // e.g. '(&(objectClass=posixAccount)(uid=%u))'
		                        // DN and password to bind as before searching for bind DN, if anonymous search is not allowed
		'search_bind_dn' => '',
		'search_bind_pw' => '',
		// Default for %dn variable if search doesn't return DN value
		'search_dn_default' => '',
		// Optional authentication identifier to be used as SASL authorization proxy
		// bind_dn need to be empty
		'auth_cid' => '',
		// SASL authentication method (for proxy auth), e.g. DIGEST-MD5
		'auth_method' => '',
		// Indicates if the addressbook shall be hidden from the list.
		// With this option enabled you can still search/view contacts.
		'hidden' => true,
		// Indicates if the addressbook shall not list contacts but only allows searching.
		'searchonly' => true,
		// Indicates if we can write to the LDAP directory or not.
		// If writable is true then these fields need to be populated:
		// LDAP_Object_Classes, required_fields, LDAP_rdn
		'writable' => false,
		// To create a new contact these are the object classes to specify
		// (or any other classes you wish to use).
		'LDAP_Object_Classes' => array(
				'top',
				'inetOrgPerson'
		),
		// The RDN field that is used for new entries, this field needs
		// to be one of the search_fields, the base of base_dn is appended
		// to the RDN to insert into the LDAP directory.
		'LDAP_rdn' => 'cn',
		// The required fields needed to build a new contact as required by
		// the object classes (can include additional fields not required by the object classes).
		'required_fields' => array(
				'cn',
				'sn',
				'uid',
				'mailPR'
		),
		'search_fields' => array(
				'cn'
		), // fields to search in
		                                  // mapping of contact fields to directory attributes
		                                  // for every attribute one can specify the number of values (limit) allowed.
		                                  // default is 1, a wildcard * means unlimited
		'fieldmap' => array(
				// Roundcube => LDAP:limit
				'username' => 'uid',
				'name' => 'cn',
				'surname' => 'sn',
				'firstname' => 'givenName',
				'jobtitle' => 'title',
				'email' => 'mailPR:*',
				'phone:home' => 'homePhone',
				'phone:work' => 'telephoneNumber',
				'phone:mobile' => 'mobile',
				'phone:pager' => 'pager',
				'street' => 'street',
				'zipcode' => 'postalCode',
				'region' => 'st',
				'locality' => 'l',
				// if you country is a complex object, you need to configure 'sub_fields' below
				'country' => 'c',
				'organization' => 'o',
				'department' => 'ou',
				'jobtitle' => 'title',
				'notes' => 'description',
				// these currently don't work:
				// 'phone:workfax' => 'facsimileTelephoneNumber',
				'photo' => 'jpegPhoto'
			// 'manager' => 'manager',
			// 'assistant' => 'secretary',
		),
		// Map of contact sub-objects (attribute name => objectClass(es)), e.g. 'c' => 'country'
		'sub_fields' => array(),
		// Generate values for the following LDAP attributes automatically when creating a new record
		'autovalues' => array(
			// 'uid' => 'md5(microtime())', // You may specify PHP code snippets which are then eval'ed
			// 'mail' => '{givenname}.{sn}@mydomain.com', // or composite strings with placeholders for existing attributes
		),
		'sort' => 'cn', // The field to sort the listing by.
		'scope' => 'sub', // search mode: sub|base|list
		'filter' => '(mineqPortee>=01)', // used for basic listing (if not empty) and will be &'d with search queries. example: status=act
		'fuzzy_search' => true, // server allows wildcard search
		'vlv' => true, // Enable Virtual List View to more efficiently fetch paginated data (if server supports it)
		'numsub_filter' => '(objectClass=organizationalUnit)', // with VLV, we also use numSubOrdinates to query the total number of records. Set this filter to get all numSubOrdinates attributes for counting
		'sizelimit' => '500', // Enables you to limit the count of entries fetched. Setting this to 0 means no limit.
		'timelimit' => '10', // Sets the number of seconds how long is spend on the search. Setting this to 0 means no limit.
		'referrals' => true | false // Sets the LDAP_OPT_REFERRALS option. Mostly used in multi-domain Active Directory setups
			                               
// definition for contact groups (uncomment if no groups are supported)
			                               // for the groups base_dn, the user replacements %fu, %u, $d and %dc work as for base_dn (see above)
			                               // if the groups base_dn is empty, the contact base_dn is used for the groups as well
			                               // -> in this case, assure that groups and contacts are separated due to the concernig filters!
	/*
 * 'groups' => array(
 * 'base_dn' => '',
 * 'scope' => 'sub', // search mode: sub|base|list
 * 'filter' => '(objectClass=groupOfNames)',
 * 'object_classes' => array("top", "groupOfNames"),
 * 'member_attr' => 'member', // name of the member attribute, e.g. uniqueMember
 * 'name_attr' => 'cn', // attribute to be used as group name
 * ),
 */
);

// An ordered array of the ids of the addressbooks that should be searched
// when populating address autocomplete fields server-side. ex: array('sql','Verisign');
$rcmail_config['autocomplete_addressbooks'] = array(
		'amande'
);

// The minimum number of characters required to be typed in an autocomplete field
// before address books will be searched. Most useful for LDAP directories that
// may need to do lengthy results building given overly-broad searches
$rcmail_config['autocomplete_min_length'] = 3;

// Number of parallel autocomplete requests.
// If there's more than one address book, n parallel (async) requests will be created,
// where each request will search in one address book. By default (0), all address
// books are searched in one request.
$rcmail_config['autocomplete_threads'] = 2;

// Max. numer of entries in autocomplete popup. Default: 15.
$rcmail_config['autocomplete_max'] = 50;

// show address fields in this order
// available placeholders: {street}, {locality}, {zipcode}, {country}, {region}
$rcmail_config['address_template'] = '{street}<br/>{locality} {zipcode}<br/>{country} {region}';

// Matching mode for addressbook search (including autocompletion)
// 0 - partial (*abc*), default
// 1 - strict (abc)
// 2 - prefix (abc*)
// Note: For LDAP sources fuzzy_search must be enabled to use 'partial' or 'prefix' mode
$rcmail_config['addressbook_search_mode'] = 2;

// Defaults of the addressbook search field configuration.
$config['addressbook_search_mods'] = array(
		'name' => 0,
		'firstname' => 0,
		'surname' => 0,
		'email' => 0,
		'*' => 0
);  // Example: array('name'=>1, 'firstname'=>1, 'surname'=>1, 'email'=>1, '*'=>1);

