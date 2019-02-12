<?php
/**
 * Ce fichier est développé pour la gestion de la librairie Mélanie2
 * Cette Librairie permet d'accèder aux données sans avoir à implémenter de couche SQL
 * Des objets génériques vont permettre d'accèder et de mettre à jour les données
 * ORM M2 Copyright © 2017 PNE Annuaire et Messagerie/MEDDE
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
 * GNU General Public License for more details.
 * You should have received a copy of the GNU General Public License
 * along with this program. If not, see <http://www.gnu.org/licenses/>.
 */
namespace LibMelanie\Api\Melanie2;

use LibMelanie\Lib\Melanie2Object;
use LibMelanie\Objects\CalendarMelanie;
use LibMelanie\Log\M2Log;

/**
 * Classe calendrier pour Melanie2
 * 
 * @author PNE Messagerie/Apitech
 * @package Librairie Mélanie2
 * @subpackage API Mélanie2
 *             @api
 * @property string $id Identifiant unique du calendrier
 * @property string $owner Identifiant du propriétaire du calendrier
 * @property string $name Nom complet du calendrier
 * @property int $perm Permission associée, utiliser asRight()
 * @property string $ctag CTag du calendrier
 * @property int $synctoken SyncToken du calendrier
 * @method bool load() Charge les données du calendrier depuis la base de données
 * @method bool exists() Non implémentée
 * @method bool save() Non implémentée
 * @method bool delete() Non implémentée
 * @method void getCTag() Charge la propriété ctag avec l'identifiant de modification du calendrier
 * @method void getTimezone() Charge la propriété timezone avec le timezone du calendrier
 * @method bool asRight($action) Retourne un boolean pour savoir si les droits sont présents
 */
class Calendar extends Melanie2Object {
  /**
   * Accès aux objets associés
   * Utilisateur associé à l'objet
   * 
   * @var UserMelanie
   * @ignore
   *
   */
  protected $usermelanie;
  
  /**
   * Constructeur de l'objet
   * 
   * @param UserMelanie $usermelanie          
   */
  function __construct($usermelanie = null) {
    // Défini la classe courante
    $this->get_class = get_class($this);
    
    M2Log::Log(M2Log::LEVEL_DEBUG, $this->get_class . "->__construct()");
    // Définition du calendrier melanie2
    $this->objectmelanie = new CalendarMelanie();
    
    // Définition des objets associés
    if (isset($usermelanie)) {
      $this->usermelanie = $usermelanie;
      $this->objectmelanie->user_uid = $this->usermelanie->uid;
    }
  }
  
  /**
   * Défini l'utilisateur Melanie
   * 
   * @param UserMelanie $usermelanie          
   * @ignore
   *
   */
  public function setUserMelanie($usermelanie) {
    M2Log::Log(M2Log::LEVEL_DEBUG, $this->get_class . "->setUserMelanie()");
    $this->usermelanie = $usermelanie;
    $this->objectmelanie->user_uid = $this->usermelanie->uid;
  }
  
  /**
   * ***************************************************
   * METHOD MAPPING
   */
  /**
   * Récupère la liste de tous les évènements
   * need: $this->id
   * 
   * @return Event[]
   */
  public function getAllEvents() {
    M2Log::Log(M2Log::LEVEL_DEBUG, $this->get_class . "->getAllEvents()");
    $_events = $this->objectmelanie->getAllEvents();
    if (!isset($_events))
      return null;
    $events = [];
    $exceptions = [];
    foreach ($_events as $_event) {
      try {
        if (strpos($_event->uid, Exception::RECURRENCE_ID) === false) {
          $event = new Event($this->usermelanie, $this);
          $event->setObjectMelanie($_event);
          $events[$event->uid . $event->calendar] = $event;
        } else {
          $exception = new Exception(null, $this->usermelanie, $this);
          $exception->setObjectMelanie($_event);
          if (!isset($exceptions[$exception->uid . $exception->calendar]) || !is_array($exceptions[$exception->uid . $exception->calendar]))
            $exceptions[$exception->uid . $exception->calendar] = [];
          // Filtrer les exceptions qui n'ont pas de date
          if (empty($exception->start) || empty($exception->end)) {
            $exception->deleted = true;
          } else {
            $exception->deleted = false;
          }
          $recId = new \DateTime(substr($exception->realuid, strlen($exception->realuid) - strlen(Exception::FORMAT_STR . Exception::RECURRENCE_ID), strlen(Exception::FORMAT_STR)));
          $exception->recurrenceId = $recId->format(Exception::FORMAT_ID);
          $exceptions[$exception->uid . $exception->calendar][$exception->recurrenceId] = $exception;
        }
      } catch ( \Exception $ex ) {
        M2Log::Log(M2Log::LEVEL_DEBUG, $this->get_class . "->getAllEvents() Exception: " . $ex);
      }
    }
    // Détruit les variables pour libérer le plus rapidement de la mémoire
    unset($_events);
    // Traitement des exceptions qui n'ont pas d'évènement associé
    // On crée un faux évènement qui va contenir ces exceptions
    foreach ($exceptions as $key => $_exceptions) {
      if (!isset($events[$key])) {
        $event = new Event($this->usermelanie, $this);
        $modified = 0;
        foreach ($_exceptions as $_exception) {
          $uid = $_exception->uid;
          $_exception->setEventParent($event);
          if (!isset($_exception->modified))
            $_exception->modified = 0;
          if ($_exception->modified > $modified)
            $modified = $_exception->modified;
        }
        if (isset($uid)) {
          $event->uid = $uid;
          $event->deleted = true;
          $event->modified = $modified;
          $event->exceptions = $_exceptions;
          $events[$event->uid . $event->calendar] = $event;
        }
      } else {
        foreach ($_exceptions as $_exception) {
          $events[$key]->addException($_exception);
        }
      }
    }
    // Détruit les variables pour libérer le plus rapidement de la mémoire
    unset($exceptions);
    // TODO: Test - Nettoyage mémoire
    //gc_collect_cycles();
    return $events;
  }
  
  /**
   * Récupère la liste des évènements entre start et end
   * need: $this->id
   * 
   * @param string $start
   *          Date de début
   * @param string $end
   *          Date de fin
   * @param int $modified
   *          Date de derniere modification des événements
   * @param boolean $is_freebusy
   *          Est-ce que l'on cherche des freebusy
   * @return Event[]
   */
  public function getRangeEvents($start = null, $end = null, $modified = null, $is_freebusy = false) {
    M2Log::Log(M2Log::LEVEL_DEBUG, $this->get_class . "->getRangeEvents()");
    $_events = $this->objectmelanie->getRangeEvents($start, $end, $modified, $is_freebusy);
    if (!isset($_events) || $_events === false)
      return null;
    $events = [];
    $exceptions = [];
    foreach ($_events as $_event) {
      try {
        if (strpos($_event->uid, Exception::RECURRENCE_ID) === false) {
          $event = new Event($this->usermelanie, $this);
          $event->setObjectMelanie($_event);
          $events[$event->uid . $event->calendar] = $event;
        } else {
          $exception = new Exception(null, $this->usermelanie, $this);
          $exception->setObjectMelanie($_event);
          if (!isset($exceptions[$exception->uid . $exception->calendar]) || !is_array($exceptions[$exception->uid . $exception->calendar]))
            $exceptions[$exception->uid . $exception->calendar] = [];
          // Filtrer les exceptions qui n'ont pas de date
          if (empty($exception->start) || empty($exception->end)) {
            $exception->deleted = true;
          } else {
            $exception->deleted = false;
          }
          $recId = new \DateTime(substr($exception->realuid, strlen($exception->realuid) - strlen(Exception::FORMAT_STR . Exception::RECURRENCE_ID), strlen(Exception::FORMAT_STR)));
          $exception->recurrenceId = $recId->format(Exception::FORMAT_ID);
          $exceptions[$exception->uid . $exception->calendar][$exception->recurrenceId] = $exception;
        }
      } catch ( \Exception $ex ) {
        M2Log::Log(M2Log::LEVEL_DEBUG, $this->get_class . "->getRangeEvents() Exception: " . $ex);
      }
    }
    // Détruit les variables pour libérer le plus rapidement de la mémoire
    unset($_events);
    // Traitement des exceptions qui n'ont pas d'évènement associé
    // On crée un faux évènement qui va contenir ces exceptions
    foreach ($exceptions as $key => $_exceptions) {
      if (!isset($events[$key])) {
        $event = new Event($this->usermelanie, $this);
        $modified = 0;
        foreach ($_exceptions as $_exception) {
          $uid = $_exception->uid;
          $_exception->setEventParent($event);
          if (!isset($_exception->modified))
            $_exception->modified = 0;
          if ($_exception->modified > $modified)
            $modified = $_exception->modified;
        }
        if (isset($uid)) {
          $event->uid = $uid;
          $event->deleted = true;
          $event->modified = $modified;
          $event->exceptions = $_exceptions;
          $events[$event->uid . $event->calendar] = $event;
        }
      } else {
        foreach ($_exceptions as $_exception) {
          $events[$key]->addException($_exception);
        }
      }
    }
    // Détruit les variables pour libérer le plus rapidement de la mémoire
    unset($exceptions);
    // TODO: Test - Nettoyage mémoire
    //gc_collect_cycles();
    return $events;
  }
}