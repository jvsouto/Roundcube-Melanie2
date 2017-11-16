<?php
/**
 * Fichier de configuration pour l'URL de freebusy publique
 */

$config = array();

// Nombre de jour par défaut (si le paramètre end n'est pas défini)
$config['nb_days'] = 90;

// Nom du fichier de freebusy à générer, utiliser %uid
$config['fb_filename'] = "fb_%uid.vfb";

// Nom du fichier ICS à générer, utiliser %calendar
$config['ics_filename'] = "calendar_%calendar.ics";