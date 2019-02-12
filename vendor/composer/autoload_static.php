<?php

// autoload_static.php @generated by Composer

namespace Composer\Autoload;

class ComposerStaticInit2b147ea006218e8a9d04d18caa35c1d7
{
    public static $files = array (
        '3a36fb0a6bafb8b516d4768ba4636f67' => __DIR__ . '/..' . '/messagerie-melanie2/ORM-M2/includes/includes_conf.php',
    );

    public static $prefixLengthsPsr4 = array (
        'S' => 
        array (
            'Sabre\\VObject\\' => 14,
        ),
        'L' => 
        array (
            'LibMelanie\\' => 11,
        ),
        'E' => 
        array (
            'Endroid\\QrCode\\' => 15,
        ),
        'C' => 
        array (
            'Composer\\Semver\\' => 16,
        ),
    );

    public static $prefixDirsPsr4 = array (
        'Sabre\\VObject\\' => 
        array (
            0 => __DIR__ . '/..' . '/sabre/vobject/lib',
        ),
        'LibMelanie\\' => 
        array (
            0 => __DIR__ . '/..' . '/messagerie-melanie2/ORM-M2/src',
        ),
        'Endroid\\QrCode\\' => 
        array (
            0 => __DIR__ . '/..' . '/endroid/qr-code/src',
        ),
        'Composer\\Semver\\' => 
        array (
            0 => __DIR__ . '/..' . '/composer/semver/src',
        ),
    );

    public static $prefixesPsr0 = array (
        'R' => 
        array (
            'Roundcube\\Composer' => 
            array (
                0 => __DIR__ . '/..' . '/roundcube/plugin-installer/src',
            ),
        ),
        'P' => 
        array (
            'PEAR' => 
            array (
                0 => __DIR__ . '/..' . '/pear/pear_exception',
            ),
        ),
        'N' => 
        array (
            'Net' => 
            array (
                0 => __DIR__ . '/..' . '/pear/net_idna2',
                1 => __DIR__ . '/..' . '/pear/net_socket',
                2 => __DIR__ . '/..' . '/pear/net_smtp',
            ),
        ),
        'M' => 
        array (
            'Mail' => 
            array (
                0 => __DIR__ . '/..' . '/pear/mail_mime',
            ),
        ),
        'C' => 
        array (
            'Crypt' => 
            array (
                0 => __DIR__ . '/..' . '/pear/crypt_gpg',
            ),
            'Console' => 
            array (
                0 => __DIR__ . '/..' . '/pear/console_commandline',
                1 => __DIR__ . '/..' . '/pear/console_getopt',
            ),
        ),
        'A' => 
        array (
            'Auth' => 
            array (
                0 => __DIR__ . '/..' . '/pear/auth_sasl',
            ),
        ),
    );

    public static $fallbackDirsPsr0 = array (
        0 => __DIR__ . '/..' . '/pear/pear-core-minimal/src',
    );

    public static $classMap = array (
        'Auth_SASL' => __DIR__ . '/..' . '/pear/auth_sasl/Auth/SASL.php',
        'Auth_SASL_Anonymous' => __DIR__ . '/..' . '/pear/auth_sasl/Auth/SASL/Anonymous.php',
        'Auth_SASL_Common' => __DIR__ . '/..' . '/pear/auth_sasl/Auth/SASL/Common.php',
        'Auth_SASL_CramMD5' => __DIR__ . '/..' . '/pear/auth_sasl/Auth/SASL/CramMD5.php',
        'Auth_SASL_DigestMD5' => __DIR__ . '/..' . '/pear/auth_sasl/Auth/SASL/DigestMD5.php',
        'Auth_SASL_External' => __DIR__ . '/..' . '/pear/auth_sasl/Auth/SASL/External.php',
        'Auth_SASL_Login' => __DIR__ . '/..' . '/pear/auth_sasl/Auth/SASL/Login.php',
        'Auth_SASL_Plain' => __DIR__ . '/..' . '/pear/auth_sasl/Auth/SASL/Plain.php',
        'Auth_SASL_SCRAM' => __DIR__ . '/..' . '/pear/auth_sasl/Auth/SASL/SCRAM.php',
        'Composer\\Semver\\Comparator' => __DIR__ . '/..' . '/composer/semver/src/Comparator.php',
        'Composer\\Semver\\Constraint\\AbstractConstraint' => __DIR__ . '/..' . '/composer/semver/src/Constraint/AbstractConstraint.php',
        'Composer\\Semver\\Constraint\\Constraint' => __DIR__ . '/..' . '/composer/semver/src/Constraint/Constraint.php',
        'Composer\\Semver\\Constraint\\ConstraintInterface' => __DIR__ . '/..' . '/composer/semver/src/Constraint/ConstraintInterface.php',
        'Composer\\Semver\\Constraint\\EmptyConstraint' => __DIR__ . '/..' . '/composer/semver/src/Constraint/EmptyConstraint.php',
        'Composer\\Semver\\Constraint\\MultiConstraint' => __DIR__ . '/..' . '/composer/semver/src/Constraint/MultiConstraint.php',
        'Composer\\Semver\\Semver' => __DIR__ . '/..' . '/composer/semver/src/Semver.php',
        'Composer\\Semver\\VersionParser' => __DIR__ . '/..' . '/composer/semver/src/VersionParser.php',
        'Console_CommandLine' => __DIR__ . '/..' . '/pear/console_commandline/Console/CommandLine.php',
        'Console_CommandLine_Action' => __DIR__ . '/..' . '/pear/console_commandline/Console/CommandLine/Action.php',
        'Console_CommandLine_Action_Callback' => __DIR__ . '/..' . '/pear/console_commandline/Console/CommandLine/Action/Callback.php',
        'Console_CommandLine_Action_Counter' => __DIR__ . '/..' . '/pear/console_commandline/Console/CommandLine/Action/Counter.php',
        'Console_CommandLine_Action_Help' => __DIR__ . '/..' . '/pear/console_commandline/Console/CommandLine/Action/Help.php',
        'Console_CommandLine_Action_List' => __DIR__ . '/..' . '/pear/console_commandline/Console/CommandLine/Action/List.php',
        'Console_CommandLine_Action_Password' => __DIR__ . '/..' . '/pear/console_commandline/Console/CommandLine/Action/Password.php',
        'Console_CommandLine_Action_StoreArray' => __DIR__ . '/..' . '/pear/console_commandline/Console/CommandLine/Action/StoreArray.php',
        'Console_CommandLine_Action_StoreFalse' => __DIR__ . '/..' . '/pear/console_commandline/Console/CommandLine/Action/StoreFalse.php',
        'Console_CommandLine_Action_StoreFloat' => __DIR__ . '/..' . '/pear/console_commandline/Console/CommandLine/Action/StoreFloat.php',
        'Console_CommandLine_Action_StoreInt' => __DIR__ . '/..' . '/pear/console_commandline/Console/CommandLine/Action/StoreInt.php',
        'Console_CommandLine_Action_StoreString' => __DIR__ . '/..' . '/pear/console_commandline/Console/CommandLine/Action/StoreString.php',
        'Console_CommandLine_Action_StoreTrue' => __DIR__ . '/..' . '/pear/console_commandline/Console/CommandLine/Action/StoreTrue.php',
        'Console_CommandLine_Action_Version' => __DIR__ . '/..' . '/pear/console_commandline/Console/CommandLine/Action/Version.php',
        'Console_CommandLine_AllTests' => __DIR__ . '/..' . '/pear/console_commandline/tests/AllTests.php',
        'Console_CommandLine_Argument' => __DIR__ . '/..' . '/pear/console_commandline/Console/CommandLine/Argument.php',
        'Console_CommandLine_Command' => __DIR__ . '/..' . '/pear/console_commandline/Console/CommandLine/Command.php',
        'Console_CommandLine_CustomMessageProvider' => __DIR__ . '/..' . '/pear/console_commandline/Console/CommandLine/CustomMessageProvider.php',
        'Console_CommandLine_Element' => __DIR__ . '/..' . '/pear/console_commandline/Console/CommandLine/Element.php',
        'Console_CommandLine_Exception' => __DIR__ . '/..' . '/pear/console_commandline/Console/CommandLine/Exception.php',
        'Console_CommandLine_MessageProvider' => __DIR__ . '/..' . '/pear/console_commandline/Console/CommandLine/MessageProvider.php',
        'Console_CommandLine_MessageProvider_Default' => __DIR__ . '/..' . '/pear/console_commandline/Console/CommandLine/MessageProvider/Default.php',
        'Console_CommandLine_Option' => __DIR__ . '/..' . '/pear/console_commandline/Console/CommandLine/Option.php',
        'Console_CommandLine_Outputter' => __DIR__ . '/..' . '/pear/console_commandline/Console/CommandLine/Outputter.php',
        'Console_CommandLine_Outputter_Default' => __DIR__ . '/..' . '/pear/console_commandline/Console/CommandLine/Outputter/Default.php',
        'Console_CommandLine_Renderer' => __DIR__ . '/..' . '/pear/console_commandline/Console/CommandLine/Renderer.php',
        'Console_CommandLine_Renderer_Default' => __DIR__ . '/..' . '/pear/console_commandline/Console/CommandLine/Renderer/Default.php',
        'Console_CommandLine_Result' => __DIR__ . '/..' . '/pear/console_commandline/Console/CommandLine/Result.php',
        'Console_CommandLine_XmlParser' => __DIR__ . '/..' . '/pear/console_commandline/Console/CommandLine/XmlParser.php',
        'Console_Getopt' => __DIR__ . '/..' . '/pear/console_getopt/Console/Getopt.php',
        'Crypt_GPG' => __DIR__ . '/..' . '/pear/crypt_gpg/Crypt/GPG.php',
        'Crypt_GPGAbstract' => __DIR__ . '/..' . '/pear/crypt_gpg/Crypt/GPGAbstract.php',
        'Crypt_GPG_BadPassphraseException' => __DIR__ . '/..' . '/pear/crypt_gpg/Crypt/GPG/Exceptions.php',
        'Crypt_GPG_DeletePrivateKeyException' => __DIR__ . '/..' . '/pear/crypt_gpg/Crypt/GPG/Exceptions.php',
        'Crypt_GPG_Engine' => __DIR__ . '/..' . '/pear/crypt_gpg/Crypt/GPG/Engine.php',
        'Crypt_GPG_Exception' => __DIR__ . '/..' . '/pear/crypt_gpg/Crypt/GPG/Exceptions.php',
        'Crypt_GPG_FileException' => __DIR__ . '/..' . '/pear/crypt_gpg/Crypt/GPG/Exceptions.php',
        'Crypt_GPG_InvalidKeyParamsException' => __DIR__ . '/..' . '/pear/crypt_gpg/Crypt/GPG/Exceptions.php',
        'Crypt_GPG_InvalidOperationException' => __DIR__ . '/..' . '/pear/crypt_gpg/Crypt/GPG/Exceptions.php',
        'Crypt_GPG_Key' => __DIR__ . '/..' . '/pear/crypt_gpg/Crypt/GPG/Key.php',
        'Crypt_GPG_KeyGenerator' => __DIR__ . '/..' . '/pear/crypt_gpg/Crypt/GPG/KeyGenerator.php',
        'Crypt_GPG_KeyNotCreatedException' => __DIR__ . '/..' . '/pear/crypt_gpg/Crypt/GPG/Exceptions.php',
        'Crypt_GPG_KeyNotFoundException' => __DIR__ . '/..' . '/pear/crypt_gpg/Crypt/GPG/Exceptions.php',
        'Crypt_GPG_NoDataException' => __DIR__ . '/..' . '/pear/crypt_gpg/Crypt/GPG/Exceptions.php',
        'Crypt_GPG_OpenSubprocessException' => __DIR__ . '/..' . '/pear/crypt_gpg/Crypt/GPG/Exceptions.php',
        'Crypt_GPG_PinEntry' => __DIR__ . '/..' . '/pear/crypt_gpg/Crypt/GPG/PinEntry.php',
        'Crypt_GPG_ProcessControl' => __DIR__ . '/..' . '/pear/crypt_gpg/Crypt/GPG/ProcessControl.php',
        'Crypt_GPG_ProcessHandler' => __DIR__ . '/..' . '/pear/crypt_gpg/Crypt/GPG/ProcessHandler.php',
        'Crypt_GPG_Signature' => __DIR__ . '/..' . '/pear/crypt_gpg/Crypt/GPG/Signature.php',
        'Crypt_GPG_SignatureCreationInfo' => __DIR__ . '/..' . '/pear/crypt_gpg/Crypt/GPG/SignatureCreationInfo.php',
        'Crypt_GPG_SubKey' => __DIR__ . '/..' . '/pear/crypt_gpg/Crypt/GPG/SubKey.php',
        'Crypt_GPG_TestCase' => __DIR__ . '/..' . '/pear/crypt_gpg/tests/TestCase.php',
        'Crypt_GPG_UserId' => __DIR__ . '/..' . '/pear/crypt_gpg/Crypt/GPG/UserId.php',
        'Endroid\\QrCode\\Exceptions\\DataDoesntExistsException' => __DIR__ . '/..' . '/endroid/qr-code/src/Exceptions/DataDoesntExistsException.php',
        'Endroid\\QrCode\\Exceptions\\FreeTypeLibraryMissingException' => __DIR__ . '/..' . '/endroid/qr-code/src/Exceptions/FreeTypeLibraryMissingException.php',
        'Endroid\\QrCode\\Exceptions\\ImageFunctionFailedException' => __DIR__ . '/..' . '/endroid/qr-code/src/Exceptions/ImageFunctionFailedException.php',
        'Endroid\\QrCode\\Exceptions\\ImageFunctionUnknownException' => __DIR__ . '/..' . '/endroid/qr-code/src/Exceptions/ImageFunctionUnknownException.php',
        'Endroid\\QrCode\\Exceptions\\ImageSizeTooLargeException' => __DIR__ . '/..' . '/endroid/qr-code/src/Exceptions/ImageSizeTooLargeException.php',
        'Endroid\\QrCode\\Exceptions\\VersionTooLargeException' => __DIR__ . '/..' . '/endroid/qr-code/src/Exceptions/VersionTooLargeException.php',
        'Endroid\\QrCode\\QrCode' => __DIR__ . '/..' . '/endroid/qr-code/src/QrCode.php',
        'LibMelanie\\Api\\Melanie2\\Addressbook' => __DIR__ . '/..' . '/messagerie-melanie2/ORM-M2/src/Api/Melanie2/Addressbook.php',
        'LibMelanie\\Api\\Melanie2\\AddressbookSync' => __DIR__ . '/..' . '/messagerie-melanie2/ORM-M2/src/Api/Melanie2/AddressbookSync.php',
        'LibMelanie\\Api\\Melanie2\\Attachment' => __DIR__ . '/..' . '/messagerie-melanie2/ORM-M2/src/Api/Melanie2/Attachment.php',
        'LibMelanie\\Api\\Melanie2\\Attendee' => __DIR__ . '/..' . '/messagerie-melanie2/ORM-M2/src/Api/Melanie2/Attendee.php',
        'LibMelanie\\Api\\Melanie2\\Calendar' => __DIR__ . '/..' . '/messagerie-melanie2/ORM-M2/src/Api/Melanie2/Calendar.php',
        'LibMelanie\\Api\\Melanie2\\CalendarSync' => __DIR__ . '/..' . '/messagerie-melanie2/ORM-M2/src/Api/Melanie2/CalendarSync.php',
        'LibMelanie\\Api\\Melanie2\\Contact' => __DIR__ . '/..' . '/messagerie-melanie2/ORM-M2/src/Api/Melanie2/Contact.php',
        'LibMelanie\\Api\\Melanie2\\Event' => __DIR__ . '/..' . '/messagerie-melanie2/ORM-M2/src/Api/Melanie2/Event.php',
        'LibMelanie\\Api\\Melanie2\\EventProperty' => __DIR__ . '/..' . '/messagerie-melanie2/ORM-M2/src/Api/Melanie2/EventProperty.php',
        'LibMelanie\\Api\\Melanie2\\Exception' => __DIR__ . '/..' . '/messagerie-melanie2/ORM-M2/src/Api/Melanie2/Exception.php',
        'LibMelanie\\Api\\Melanie2\\ObjectShare' => __DIR__ . '/..' . '/messagerie-melanie2/ORM-M2/src/Api/Melanie2/ObjectShare.php',
        'LibMelanie\\Api\\Melanie2\\Organizer' => __DIR__ . '/..' . '/messagerie-melanie2/ORM-M2/src/Api/Melanie2/Organizer.php',
        'LibMelanie\\Api\\Melanie2\\Recurrence' => __DIR__ . '/..' . '/messagerie-melanie2/ORM-M2/src/Api/Melanie2/Recurrence.php',
        'LibMelanie\\Api\\Melanie2\\Share' => __DIR__ . '/..' . '/messagerie-melanie2/ORM-M2/src/Api/Melanie2/Share.php',
        'LibMelanie\\Api\\Melanie2\\Task' => __DIR__ . '/..' . '/messagerie-melanie2/ORM-M2/src/Api/Melanie2/Task.php',
        'LibMelanie\\Api\\Melanie2\\TaskProperty' => __DIR__ . '/..' . '/messagerie-melanie2/ORM-M2/src/Api/Melanie2/TaskProperty.php',
        'LibMelanie\\Api\\Melanie2\\Taskslist' => __DIR__ . '/..' . '/messagerie-melanie2/ORM-M2/src/Api/Melanie2/Taskslist.php',
        'LibMelanie\\Api\\Melanie2\\TaskslistSync' => __DIR__ . '/..' . '/messagerie-melanie2/ORM-M2/src/Api/Melanie2/TaskslistSync.php',
        'LibMelanie\\Api\\Melanie2\\User' => __DIR__ . '/..' . '/messagerie-melanie2/ORM-M2/src/Api/Melanie2/User.php',
        'LibMelanie\\Api\\Melanie2\\UserPrefs' => __DIR__ . '/..' . '/messagerie-melanie2/ORM-M2/src/Api/Melanie2/UserPrefs.php',
        'LibMelanie\\Cache\\Cache' => __DIR__ . '/..' . '/messagerie-melanie2/ORM-M2/src/Cache/Cache.php',
        'LibMelanie\\Config\\Config' => __DIR__ . '/..' . '/messagerie-melanie2/ORM-M2/src/Config/Config.php',
        'LibMelanie\\Config\\DefaultConfig' => __DIR__ . '/..' . '/messagerie-melanie2/ORM-M2/src/Config/DefaultConfig.php',
        'LibMelanie\\Config\\MappingMelanie' => __DIR__ . '/..' . '/messagerie-melanie2/ORM-M2/src/Config/MappingMelanie.php',
        'LibMelanie\\Exceptions\\Melanie2DatabaseException' => __DIR__ . '/..' . '/messagerie-melanie2/ORM-M2/src/Exceptions/Melanie2DatabaseException.php',
        'LibMelanie\\Exceptions\\Melanie2Exception' => __DIR__ . '/..' . '/messagerie-melanie2/ORM-M2/src/Exceptions/Melanie2Exception.php',
        'LibMelanie\\Exceptions\\Melanie2LdapException' => __DIR__ . '/..' . '/messagerie-melanie2/ORM-M2/src/Exceptions/Melanie2LdapException.php',
        'LibMelanie\\Exceptions\\ObjectMelanieUndefinedException' => __DIR__ . '/..' . '/messagerie-melanie2/ORM-M2/src/Exceptions/ObjectMelanieUndefinedException.php',
        'LibMelanie\\Exceptions\\PropertyDoesNotExistException' => __DIR__ . '/..' . '/messagerie-melanie2/ORM-M2/src/Exceptions/PropertyDoesNotExistException.php',
        'LibMelanie\\Exceptions\\UndefinedMappingException' => __DIR__ . '/..' . '/messagerie-melanie2/ORM-M2/src/Exceptions/UndefinedMappingException.php',
        'LibMelanie\\Exceptions\\UndefinedPrimaryKeyException' => __DIR__ . '/..' . '/messagerie-melanie2/ORM-M2/src/Exceptions/UndefinedPrimaryKeyException.php',
        'LibMelanie\\Interfaces\\IObjectMelanie' => __DIR__ . '/..' . '/messagerie-melanie2/ORM-M2/src/Interfaces/IObjectMelanie.php',
        'LibMelanie\\Ldap\\LDAPMelanie' => __DIR__ . '/..' . '/messagerie-melanie2/ORM-M2/src/Ldap/LDAPMelanie.php',
        'LibMelanie\\Ldap\\Ldap' => __DIR__ . '/..' . '/messagerie-melanie2/ORM-M2/src/Ldap/Ldap.php',
        'LibMelanie\\Lib\\ContactToVCard' => __DIR__ . '/..' . '/messagerie-melanie2/ORM-M2/src/Lib/ContactToVCard.php',
        'LibMelanie\\Lib\\EventToICS' => __DIR__ . '/..' . '/messagerie-melanie2/ORM-M2/src/Lib/EventToICS.php',
        'LibMelanie\\Lib\\ICS' => __DIR__ . '/..' . '/messagerie-melanie2/ORM-M2/src/Lib/ICS.php',
        'LibMelanie\\Lib\\ICSToEvent' => __DIR__ . '/..' . '/messagerie-melanie2/ORM-M2/src/Lib/ICSToEvent.php',
        'LibMelanie\\Lib\\ICSToTask' => __DIR__ . '/..' . '/messagerie-melanie2/ORM-M2/src/Lib/ICSToTask.php',
        'LibMelanie\\Lib\\MagicObject' => __DIR__ . '/..' . '/messagerie-melanie2/ORM-M2/src/Lib/MagicObject.php',
        'LibMelanie\\Lib\\Melanie2Object' => __DIR__ . '/..' . '/messagerie-melanie2/ORM-M2/src/Lib/Melanie2Object.php',
        'LibMelanie\\Lib\\Selaforme' => __DIR__ . '/..' . '/messagerie-melanie2/ORM-M2/src/Lib/Selaforme.php',
        'LibMelanie\\Lib\\TaskToICS' => __DIR__ . '/..' . '/messagerie-melanie2/ORM-M2/src/Lib/TaskToICS.php',
        'LibMelanie\\Lib\\VCard' => __DIR__ . '/..' . '/messagerie-melanie2/ORM-M2/src/Lib/VCard.php',
        'LibMelanie\\Lib\\VCardToContact' => __DIR__ . '/..' . '/messagerie-melanie2/ORM-M2/src/Lib/VCardToContact.php',
        'LibMelanie\\Log\\Log' => __DIR__ . '/..' . '/messagerie-melanie2/ORM-M2/src/Log/Log.php',
        'LibMelanie\\Log\\M2Log' => __DIR__ . '/..' . '/messagerie-melanie2/ORM-M2/src/Log/M2Log.php',
        'LibMelanie\\Objects\\AddressbookMelanie' => __DIR__ . '/..' . '/messagerie-melanie2/ORM-M2/src/Objects/AddressbookMelanie.php',
        'LibMelanie\\Objects\\AttachmentMelanie' => __DIR__ . '/..' . '/messagerie-melanie2/ORM-M2/src/Objects/AttachmentMelanie.php',
        'LibMelanie\\Objects\\CalendarMelanie' => __DIR__ . '/..' . '/messagerie-melanie2/ORM-M2/src/Objects/CalendarMelanie.php',
        'LibMelanie\\Objects\\EventMelanie' => __DIR__ . '/..' . '/messagerie-melanie2/ORM-M2/src/Objects/EventMelanie.php',
        'LibMelanie\\Objects\\HistoryMelanie' => __DIR__ . '/..' . '/messagerie-melanie2/ORM-M2/src/Objects/HistoryMelanie.php',
        'LibMelanie\\Objects\\ObjectMelanie' => __DIR__ . '/..' . '/messagerie-melanie2/ORM-M2/src/Objects/ObjectMelanie.php',
        'LibMelanie\\Objects\\TaskslistMelanie' => __DIR__ . '/..' . '/messagerie-melanie2/ORM-M2/src/Objects/TaskslistMelanie.php',
        'LibMelanie\\Objects\\UserMelanie' => __DIR__ . '/..' . '/messagerie-melanie2/ORM-M2/src/Objects/UserMelanie.php',
        'LibMelanie\\Sql\\DBMelanie' => __DIR__ . '/..' . '/messagerie-melanie2/ORM-M2/src/Sql/DBMelanie.php',
        'LibMelanie\\Sql\\Sql' => __DIR__ . '/..' . '/messagerie-melanie2/ORM-M2/src/Sql/Sql.php',
        'LibMelanie\\Sql\\SqlAttachmentRequests' => __DIR__ . '/..' . '/messagerie-melanie2/ORM-M2/src/Sql/SqlAttachmentRequests.php',
        'LibMelanie\\Sql\\SqlCalendarRequests' => __DIR__ . '/..' . '/messagerie-melanie2/ORM-M2/src/Sql/SqlCalendarRequests.php',
        'LibMelanie\\Sql\\SqlContactRequests' => __DIR__ . '/..' . '/messagerie-melanie2/ORM-M2/src/Sql/SqlContactRequests.php',
        'LibMelanie\\Sql\\SqlHistoryRequests' => __DIR__ . '/..' . '/messagerie-melanie2/ORM-M2/src/Sql/SqlHistoryRequests.php',
        'LibMelanie\\Sql\\SqlMelanieRequests' => __DIR__ . '/..' . '/messagerie-melanie2/ORM-M2/src/Sql/SqlMelanieRequests.php',
        'LibMelanie\\Sql\\SqlObjectPropertyRequests' => __DIR__ . '/..' . '/messagerie-melanie2/ORM-M2/src/Sql/SqlObjectPropertyRequests.php',
        'LibMelanie\\Sql\\SqlObjectRequests' => __DIR__ . '/..' . '/messagerie-melanie2/ORM-M2/src/Sql/SqlObjectRequests.php',
        'LibMelanie\\Sql\\SqlTaskRequests' => __DIR__ . '/..' . '/messagerie-melanie2/ORM-M2/src/Sql/SqlTaskRequests.php',
        'Mail_mime' => __DIR__ . '/..' . '/pear/mail_mime/Mail/mime.php',
        'Mail_mimePart' => __DIR__ . '/..' . '/pear/mail_mime/Mail/mimePart.php',
        'Net_IDNA2' => __DIR__ . '/..' . '/pear/net_idna2/Net/IDNA2.php',
        'Net_IDNA2Test' => __DIR__ . '/..' . '/pear/net_idna2/tests/Net_IDNA2Test.php',
        'Net_IDNA2_Exception' => __DIR__ . '/..' . '/pear/net_idna2/Net/IDNA2/Exception.php',
        'Net_IDNA2_Exception_Nameprep' => __DIR__ . '/..' . '/pear/net_idna2/Net/IDNA2/Exception/Nameprep.php',
        'Net_LDAP2' => __DIR__ . '/..' . '/pear/net_ldap2/Net/LDAP2.php',
        'Net_LDAP2_Entry' => __DIR__ . '/..' . '/pear/net_ldap2/Net/LDAP2/Entry.php',
        'Net_LDAP2_Error' => __DIR__ . '/..' . '/pear/net_ldap2/Net/LDAP2.php',
        'Net_LDAP2_Filter' => __DIR__ . '/..' . '/pear/net_ldap2/Net/LDAP2/Filter.php',
        'Net_LDAP2_LDIF' => __DIR__ . '/..' . '/pear/net_ldap2/Net/LDAP2/LDIF.php',
        'Net_LDAP2_RootDSE' => __DIR__ . '/..' . '/pear/net_ldap2/Net/LDAP2/RootDSE.php',
        'Net_LDAP2_Schema' => __DIR__ . '/..' . '/pear/net_ldap2/Net/LDAP2/Schema.php',
        'Net_LDAP2_SchemaCache' => __DIR__ . '/..' . '/pear/net_ldap2/Net/LDAP2/SchemaCache.interface.php',
        'Net_LDAP2_Search' => __DIR__ . '/..' . '/pear/net_ldap2/Net/LDAP2/Search.php',
        'Net_LDAP2_SimpleFileSchemaCache' => __DIR__ . '/..' . '/pear/net_ldap2/Net/LDAP2/SimpleFileSchemaCache.php',
        'Net_LDAP2_Util' => __DIR__ . '/..' . '/pear/net_ldap2/Net/LDAP2/Util.php',
        'Net_LDAP3' => __DIR__ . '/..' . '/kolab/net_ldap3/lib/Net/LDAP3.php',
        'Net_LDAP3_Result' => __DIR__ . '/..' . '/kolab/net_ldap3/lib/Net/LDAP3/Result.php',
        'Net_SMTP' => __DIR__ . '/..' . '/pear/net_smtp/Net/SMTP.php',
        'Net_Sieve' => __DIR__ . '/..' . '/pear/net_sieve/Sieve.php',
        'Net_Socket' => __DIR__ . '/..' . '/pear/net_socket/Net/Socket.php',
        'OS_Guess' => __DIR__ . '/..' . '/pear/pear-core-minimal/src/OS/Guess.php',
        'PEAR' => __DIR__ . '/..' . '/pear/pear-core-minimal/src/PEAR.php',
        'PEAR_Error' => __DIR__ . '/..' . '/pear/pear-core-minimal/src/PEAR.php',
        'PEAR_ErrorStack' => __DIR__ . '/..' . '/pear/pear-core-minimal/src/PEAR/ErrorStack.php',
        'PEAR_Exception' => __DIR__ . '/..' . '/pear/pear_exception/PEAR/Exception.php',
        'PEAR_ExceptionTest' => __DIR__ . '/..' . '/pear/pear_exception/tests/PEAR/ExceptionTest.php',
        'Roundcube\\Composer\\PluginInstaller' => __DIR__ . '/..' . '/roundcube/plugin-installer/src/Roundcube/Composer/PluginInstaller.php',
        'Sabre\\VObject\\Cli' => __DIR__ . '/..' . '/sabre/vobject/lib/Cli.php',
        'Sabre\\VObject\\Component' => __DIR__ . '/..' . '/sabre/vobject/lib/Component.php',
        'Sabre\\VObject\\Component\\Available' => __DIR__ . '/..' . '/sabre/vobject/lib/Component/Available.php',
        'Sabre\\VObject\\Component\\VAlarm' => __DIR__ . '/..' . '/sabre/vobject/lib/Component/VAlarm.php',
        'Sabre\\VObject\\Component\\VAvailability' => __DIR__ . '/..' . '/sabre/vobject/lib/Component/VAvailability.php',
        'Sabre\\VObject\\Component\\VCalendar' => __DIR__ . '/..' . '/sabre/vobject/lib/Component/VCalendar.php',
        'Sabre\\VObject\\Component\\VCard' => __DIR__ . '/..' . '/sabre/vobject/lib/Component/VCard.php',
        'Sabre\\VObject\\Component\\VEvent' => __DIR__ . '/..' . '/sabre/vobject/lib/Component/VEvent.php',
        'Sabre\\VObject\\Component\\VFreeBusy' => __DIR__ . '/..' . '/sabre/vobject/lib/Component/VFreeBusy.php',
        'Sabre\\VObject\\Component\\VJournal' => __DIR__ . '/..' . '/sabre/vobject/lib/Component/VJournal.php',
        'Sabre\\VObject\\Component\\VTimeZone' => __DIR__ . '/..' . '/sabre/vobject/lib/Component/VTimeZone.php',
        'Sabre\\VObject\\Component\\VTodo' => __DIR__ . '/..' . '/sabre/vobject/lib/Component/VTodo.php',
        'Sabre\\VObject\\DateTimeParser' => __DIR__ . '/..' . '/sabre/vobject/lib/DateTimeParser.php',
        'Sabre\\VObject\\Document' => __DIR__ . '/..' . '/sabre/vobject/lib/Document.php',
        'Sabre\\VObject\\ElementList' => __DIR__ . '/..' . '/sabre/vobject/lib/ElementList.php',
        'Sabre\\VObject\\EofException' => __DIR__ . '/..' . '/sabre/vobject/lib/EofException.php',
        'Sabre\\VObject\\FreeBusyGenerator' => __DIR__ . '/..' . '/sabre/vobject/lib/FreeBusyGenerator.php',
        'Sabre\\VObject\\ITip\\Broker' => __DIR__ . '/..' . '/sabre/vobject/lib/ITip/Broker.php',
        'Sabre\\VObject\\ITip\\ITipException' => __DIR__ . '/..' . '/sabre/vobject/lib/ITip/ITipException.php',
        'Sabre\\VObject\\ITip\\Message' => __DIR__ . '/..' . '/sabre/vobject/lib/ITip/Message.php',
        'Sabre\\VObject\\ITip\\SameOrganizerForAllComponentsException' => __DIR__ . '/..' . '/sabre/vobject/lib/ITip/SameOrganizerForAllComponentsException.php',
        'Sabre\\VObject\\Node' => __DIR__ . '/..' . '/sabre/vobject/lib/Node.php',
        'Sabre\\VObject\\Parameter' => __DIR__ . '/..' . '/sabre/vobject/lib/Parameter.php',
        'Sabre\\VObject\\ParseException' => __DIR__ . '/..' . '/sabre/vobject/lib/ParseException.php',
        'Sabre\\VObject\\Parser\\Json' => __DIR__ . '/..' . '/sabre/vobject/lib/Parser/Json.php',
        'Sabre\\VObject\\Parser\\MimeDir' => __DIR__ . '/..' . '/sabre/vobject/lib/Parser/MimeDir.php',
        'Sabre\\VObject\\Parser\\Parser' => __DIR__ . '/..' . '/sabre/vobject/lib/Parser/Parser.php',
        'Sabre\\VObject\\Property' => __DIR__ . '/..' . '/sabre/vobject/lib/Property.php',
        'Sabre\\VObject\\Property\\Binary' => __DIR__ . '/..' . '/sabre/vobject/lib/Property/Binary.php',
        'Sabre\\VObject\\Property\\Boolean' => __DIR__ . '/..' . '/sabre/vobject/lib/Property/Boolean.php',
        'Sabre\\VObject\\Property\\FlatText' => __DIR__ . '/..' . '/sabre/vobject/lib/Property/FlatText.php',
        'Sabre\\VObject\\Property\\FloatValue' => __DIR__ . '/..' . '/sabre/vobject/lib/Property/FloatValue.php',
        'Sabre\\VObject\\Property\\ICalendar\\CalAddress' => __DIR__ . '/..' . '/sabre/vobject/lib/Property/ICalendar/CalAddress.php',
        'Sabre\\VObject\\Property\\ICalendar\\Date' => __DIR__ . '/..' . '/sabre/vobject/lib/Property/ICalendar/Date.php',
        'Sabre\\VObject\\Property\\ICalendar\\DateTime' => __DIR__ . '/..' . '/sabre/vobject/lib/Property/ICalendar/DateTime.php',
        'Sabre\\VObject\\Property\\ICalendar\\Duration' => __DIR__ . '/..' . '/sabre/vobject/lib/Property/ICalendar/Duration.php',
        'Sabre\\VObject\\Property\\ICalendar\\Period' => __DIR__ . '/..' . '/sabre/vobject/lib/Property/ICalendar/Period.php',
        'Sabre\\VObject\\Property\\ICalendar\\Recur' => __DIR__ . '/..' . '/sabre/vobject/lib/Property/ICalendar/Recur.php',
        'Sabre\\VObject\\Property\\IntegerValue' => __DIR__ . '/..' . '/sabre/vobject/lib/Property/IntegerValue.php',
        'Sabre\\VObject\\Property\\Text' => __DIR__ . '/..' . '/sabre/vobject/lib/Property/Text.php',
        'Sabre\\VObject\\Property\\Time' => __DIR__ . '/..' . '/sabre/vobject/lib/Property/Time.php',
        'Sabre\\VObject\\Property\\Unknown' => __DIR__ . '/..' . '/sabre/vobject/lib/Property/Unknown.php',
        'Sabre\\VObject\\Property\\Uri' => __DIR__ . '/..' . '/sabre/vobject/lib/Property/Uri.php',
        'Sabre\\VObject\\Property\\UtcOffset' => __DIR__ . '/..' . '/sabre/vobject/lib/Property/UtcOffset.php',
        'Sabre\\VObject\\Property\\VCard\\Date' => __DIR__ . '/..' . '/sabre/vobject/lib/Property/VCard/Date.php',
        'Sabre\\VObject\\Property\\VCard\\DateAndOrTime' => __DIR__ . '/..' . '/sabre/vobject/lib/Property/VCard/DateAndOrTime.php',
        'Sabre\\VObject\\Property\\VCard\\DateTime' => __DIR__ . '/..' . '/sabre/vobject/lib/Property/VCard/DateTime.php',
        'Sabre\\VObject\\Property\\VCard\\LanguageTag' => __DIR__ . '/..' . '/sabre/vobject/lib/Property/VCard/LanguageTag.php',
        'Sabre\\VObject\\Property\\VCard\\TimeStamp' => __DIR__ . '/..' . '/sabre/vobject/lib/Property/VCard/TimeStamp.php',
        'Sabre\\VObject\\Reader' => __DIR__ . '/..' . '/sabre/vobject/lib/Reader.php',
        'Sabre\\VObject\\Recur\\EventIterator' => __DIR__ . '/..' . '/sabre/vobject/lib/Recur/EventIterator.php',
        'Sabre\\VObject\\Recur\\NoInstancesException' => __DIR__ . '/..' . '/sabre/vobject/lib/Recur/NoInstancesException.php',
        'Sabre\\VObject\\Recur\\RDateIterator' => __DIR__ . '/..' . '/sabre/vobject/lib/Recur/RDateIterator.php',
        'Sabre\\VObject\\Recur\\RRuleIterator' => __DIR__ . '/..' . '/sabre/vobject/lib/Recur/RRuleIterator.php',
        'Sabre\\VObject\\RecurrenceIterator' => __DIR__ . '/..' . '/sabre/vobject/lib/RecurrenceIterator.php',
        'Sabre\\VObject\\Splitter\\ICalendar' => __DIR__ . '/..' . '/sabre/vobject/lib/Splitter/ICalendar.php',
        'Sabre\\VObject\\Splitter\\SplitterInterface' => __DIR__ . '/..' . '/sabre/vobject/lib/Splitter/SplitterInterface.php',
        'Sabre\\VObject\\Splitter\\VCard' => __DIR__ . '/..' . '/sabre/vobject/lib/Splitter/VCard.php',
        'Sabre\\VObject\\StringUtil' => __DIR__ . '/..' . '/sabre/vobject/lib/StringUtil.php',
        'Sabre\\VObject\\TimeZoneUtil' => __DIR__ . '/..' . '/sabre/vobject/lib/TimeZoneUtil.php',
        'Sabre\\VObject\\UUIDUtil' => __DIR__ . '/..' . '/sabre/vobject/lib/UUIDUtil.php',
        'Sabre\\VObject\\VCardConverter' => __DIR__ . '/..' . '/sabre/vobject/lib/VCardConverter.php',
        'Sabre\\VObject\\Version' => __DIR__ . '/..' . '/sabre/vobject/lib/Version.php',
        'SieveTest' => __DIR__ . '/..' . '/pear/net_sieve/tests/SieveTest.php',
        'System' => __DIR__ . '/..' . '/pear/pear-core-minimal/src/System.php',
    );

    public static function getInitializer(ClassLoader $loader)
    {
        return \Closure::bind(function () use ($loader) {
            $loader->prefixLengthsPsr4 = ComposerStaticInit2b147ea006218e8a9d04d18caa35c1d7::$prefixLengthsPsr4;
            $loader->prefixDirsPsr4 = ComposerStaticInit2b147ea006218e8a9d04d18caa35c1d7::$prefixDirsPsr4;
            $loader->prefixesPsr0 = ComposerStaticInit2b147ea006218e8a9d04d18caa35c1d7::$prefixesPsr0;
            $loader->fallbackDirsPsr0 = ComposerStaticInit2b147ea006218e8a9d04d18caa35c1d7::$fallbackDirsPsr0;
            $loader->classMap = ComposerStaticInit2b147ea006218e8a9d04d18caa35c1d7::$classMap;

        }, null, ClassLoader::class);
    }
}
