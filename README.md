# NetPulse

Dépôt GitHub : **https://github.com/Les-Doubles-A/NetPulse**

Tableau de bord de surveillance et d'analyse du réseau local pour Windows, écrit en
**Rust** (interface `egui`/`eframe`, base `SQLite` embarquée). Un seul exécutable
natif, sans Python, sans Npcap et sans droits administrateur.

> **Usage responsable** : n'utilisez NetPulse que sur des réseaux que vous possédez
> ou que vous êtes explicitement autorisé(e) à auditer. Scanner un réseau tiers sans
> autorisation peut être illégal selon votre juridiction (en France : articles
> 323-1 et suivants du Code pénal).

## Installation

Téléchargez **`NetPulse-Setup-2.0.0.exe`** depuis la [dernière release](https://github.com/Les-Doubles-A/NetPulse/releases/latest), puis lancez-le.

- Installation pour l'utilisateur courant, sans droits administrateur (par défaut dans `%LOCALAPPDATA%\Programs\NetPulse`).
- Raccourci dans le menu Démarrer, icône de bureau et lancement à l'ouverture de session en option.
- Désinstallation depuis les Paramètres Windows. L'installeur met à jour une version 1.x existante.

L'installeur n'est pas signé : si Windows SmartScreen l'affiche, cliquez sur « Informations complémentaires » puis « Exécuter quand même ».

## Fonctionnalités

### Tableau de bord
- Appareils en ligne, appareils non approuvés, latence de la passerelle et d'Internet, IP locale et publique, score de sécurité moyen.
- Graphiques en temps réel de la latence (passerelle + cibles configurables) et du trafic réseau total.
- Répartition des appareils par type et derniers événements.

### Appareils
- Découverte du réseau sans privilèges : ICMP natif (`IcmpSendEcho`), résolution ARP (`SendARP`) qui détecte aussi les appareils qui ignorent le ping, et sonde TCP complémentaire.
- Cibles flexibles : `192.168.1.0/24`, `192.168.1.10-50`, `10.0.0.1-10.0.0.40`, listes séparées par des virgules (jusqu'à 65 536 adresses).
- Fabricant via la base IEEE complète embarquée (plus de 40 000 préfixes, mise à jour en un clic), détection des adresses MAC privées (aléatoires).
- Nom d'hôte par DNS inverse et NetBIOS, type d'appareil deviné (box, smartphone, imprimante, NAS, caméra, IoT, console, machine virtuelle...).
- Nom personnalisé, notes, type, statut « approuvé » et favoris pour chaque appareil, conservés en base.
- Tri, recherche, filtres (en ligne, hors ligne, non approuvés, favoris), export CSV et JSON.
- Panneau de détail : scan de ports, ping, traceroute, Wake-on-LAN, ouverture HTTP/HTTPS, copie IP/MAC, historique de l'appareil.
- Alertes : nouvel appareil, appareil hors ligne, retour en ligne, changement d'adresse MAC (réattribution ou usurpation ARP possible), avec notifications Windows.
- Analyse automatique périodique.

### Ports et sécurité
- Scanner TCP multithreadé (jusqu'à 1000 connexions simultanées) sur une IP ou un nom d'hôte, de quelques ports à la plage complète 1-65535.
- Présélections : courants, web, bases de données, accès distant, partage de fichiers, IoT/multimédia, 1-1024, 1-10000, tous.
- Récupération de bannières (en-tête `Server` HTTP, SSH, FTP, SMTP...).
- Score de sécurité sur 100 avec note A à F, constats classés par gravité (critique, élevé, moyen, faible) et recommandations : Telnet, SMB, RDP, VNC, bases de données exposées, API Docker, ADB, Redis, MongoDB, MQTT, RTSP, versions obsolètes détectées dans les bannières, interface web sans HTTPS, surface d'attaque excessive...
- Évolution du score dans le temps, rapport HTML autonome et export JSON.

### Outils
- **Ping continu** avec graphique, perte, min/moy/max et gigue.
- **Traceroute** ICMP avec noms d'hôtes.
- **DNS** : résolution directe (A/AAAA) et inverse (PTR).
- **Wake-on-LAN** vers un appareil connu ou une adresse MAC.
- **IP publique** : fournisseur, localisation, fuseau horaire (via ipinfo.io), lien vers la carte.
- **Test de débit** descendant/montant et latence (serveurs Cloudflare).
- **Vérification HTTP** : code, temps de réponse, taille, en-têtes, contrôle des en-têtes de sécurité.
- **Calculateur de sous-réseau** : masque, wildcard, diffusion, plage d'hôtes, classe, type d'adresse, binaire.
- **Recherche de fabricant** à partir d'une adresse MAC.

### Connexions
- Toutes les sockets TCP/UDP IPv4 de la machine (équivalent de `netstat -ano`) avec le processus propriétaire, filtres et actualisation automatique.

### Interfaces et trafic
- Interfaces réseau avec adresses, MAC, MTU, volumes reçus/envoyés et débit instantané, graphique du trafic.

### Historique
- Journal SQLite de tous les événements (scans, nouveaux appareils, coupures, rétablissements, tests de débit...), recherche, filtre par type, export CSV.
- Surveillance de la connexion : coupure signalée après 3 échecs consécutifs vers une cible, puis rétablissement.

### Paramètres
- Thème système/clair/sombre et zoom, délais et parallélisme des scans, ports par défaut, analyse automatique, notifications, cibles de latence.
- Ouverture du dossier de données, sauvegarde de la base, mise à jour de la base des fabricants.

## Ligne de commande

Le même exécutable fonctionne en ligne de commande :

```
NetPulse.exe scan [cible] [--json]     Découvre les appareils
NetPulse.exe ports <hôte> [ports] [--json]
NetPulse.exe ping <hôte> [nombre]
NetPulse.exe trace <hôte>
NetPulse.exe dns <nom|ip>
NetPulse.exe wol <mac>
NetPulse.exe ip                         IP publique
NetPulse.exe interfaces
NetPulse.exe subnet <cidr>
NetPulse.exe --help
```

## Données

Tout est stocké localement dans `%LOCALAPPDATA%\NetPulse` :
- `netpulse.db` : appareils, événements, scans de ports, scores, latences ;
- `settings.json` : paramètres ;
- `oui.txt` : base des fabricants mise à jour (facultatif).

Seules les fonctions IP publique (ipinfo.io), test de débit (speed.cloudflare.com) et mise à jour des fabricants (standards-oui.ieee.org) contactent Internet, et uniquement à votre demande.

## Compiler depuis les sources

Prérequis : [Rust](https://rustup.rs/) (toolchain MSVC) et, pour l'installeur, [Inno Setup 6](https://jrsoftware.org/isinfo.php).

```
cargo build --release            # target\release\NetPulse.exe
iscc installer\NetPulse.iss      # installer\Output\NetPulse-Setup-2.0.0.exe
```

## Structure

```
src/
  main.rs        point d'entrée (interface graphique ou ligne de commande)
  app.rs         état de l'application, tâches de fond, logique
  views.rs       interface egui (onglets)
  discovery.rs   découverte des appareils, NetBIOS, type d'appareil
  ports.rs       scanner de ports, bannières, rapport HTML
  security.rs    règles d'analyse de sécurité
  tools.rs       ping, traceroute, DNS, WoL, IP publique, débit, HTTP, sous-réseau
  platform.rs    API Windows (ICMP, ARP, routes, tables TCP/UDP)
  storage.rs     paramètres et base SQLite
  oui.rs         base des fabricants IEEE
  cli.rs         ligne de commande
assets/oui.txt   base IEEE embarquée
installer/       script Inno Setup
```

## Limites

- Les tables de connexions et la découverte native ciblent IPv4.
- Le scan de ports effectue uniquement des connexions TCP complètes et la lecture de bannières : aucune exploitation ni test d'intrusion actif.
- Le type d'appareil est une estimation fondée sur le fabricant, le nom d'hôte et les ports ouverts.
