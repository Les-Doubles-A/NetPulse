# NetPulse

Dépôt GitHub : **https://github.com/Les-Doubles-A/NetPulse**

Tableau de bord de surveillance et d'analyse du réseau local, construit avec
`customtkinter`, `scapy`, `python-nmap` (optionnel) et `SQLite`.

> ⚠️ **Usage responsable** : n'utilisez NetPulse que sur des réseaux que vous possédez
> ou que vous êtes explicitement autorisé(e) à auditer. Scanner un réseau tiers sans
> autorisation peut être illégal selon votre juridiction (ex. en France : article
> 323-1 et suivants du Code pénal).

## 📁 Structure du projet

```
NetPulse/
├── main.py                  # Script principal de l'application
├── requirements.txt         # Dépendances Python
├── NetPulse.png              # Icône source (à fournir, 256x256 recommandé)
├── NetPulse.ico              # Icône .ico (générée automatiquement si absente)
└── netpulse_history.db       # Base SQLite (créée automatiquement au 1er lancement)
```

## 🔧 1. Installation des dépendances

```bash
pip install customtkinter pillow scapy python-nmap psutil pyinstaller
```

- `scapy` : scan ARP natif (le plus fiable pour découvrir les appareils).
- `python-nmap` : **optionnel**, améliore la détection de service/version des ports
  si le binaire **nmap** est également installé sur la machine
  (https://nmap.org/download.html). En son absence, NetPulse bascule automatiquement
  sur un scanner de ports interne basé sur les sockets Python (aucune dépendance
  externe requise).
- `psutil` : détection automatique du sous-réseau local.

### Droits nécessaires pour le scan ARP

Le scan ARP (via `scapy`) nécessite des privilèges élevés :
- **Windows** : installez [Npcap](https://npcap.com/) et lancez l'application en
  tant qu'administrateur.
- **Linux/macOS** : lancez avec `sudo python3 main.py`.

Si ces privilèges ne sont pas disponibles, NetPulse **bascule automatiquement**
sur une méthode de repli (ping sweep + lecture de la table ARP du système), sans
action requise de votre part.

## ▶️ 2. Lancer l'application en développement

```bash
cd NetPulse
python main.py
```

## 🖥️ 3. Fonctionnalités

### Onglet "📡 Appareils"
- Détection automatique du sous-réseau local (modifiable manuellement).
- Bouton **Scanner le réseau** : scan ARP (ou repli ping sweep) pour lister les
  appareils actifs.
- Tableau : Adresse IP, Adresse MAC, Fabricant (résolu via la base OUI de `scapy`,
  avec une table de repli intégrée), État (En ligne / Hors ligne), dernière détection.
- Double-clic sur un appareil → bascule directement vers l'onglet Ports & Sécurité.

### Onglet "🔒 Ports & Sécurité"
- Sélection d'un appareil détecté + liste de ports personnalisable (par défaut :
  21, 22, 23, 25, 53, 80, 110, 139, 143, 443, 445, 993, 995, 1723, 3306, 3389, 5900, 8080).
- Scan via `python-nmap` (si disponible) avec détection de bannière/service, sinon
  scanner socket interne multithreadé avec récupération de bannière.
- **Score de sécurité** sur 100, avec pénalités renforcées pour les ports sensibles
  ouverts (FTP, Telnet, NetBIOS, SMB, PPTP, RDP, VNC) et alertes détaillées.

### Onglet "🕘 Historique"
- Historique local (SQLite) de tous les événements : nouveaux appareils, appareils
  hors ligne, résultats de scans de ports, scores de sécurité.
- Boutons **Actualiser** et **Vider l'historique**.

### Thème
- `ctk.set_appearance_mode("System")` : suit automatiquement le thème clair/sombre
  de l'OS. Un sélecteur manuel (System/Light/Dark) est aussi disponible dans la
  barre de statut.

## 📦 4. Compilation en exécutable `.exe` (Windows)

Depuis le dossier `NetPulse/` (contenant `main.py` et `NetPulse.ico`) :

```bash
pyinstaller --noconsole --onefile --icon=NetPulse.ico --name=NetPulse main.py
```

L'exécutable final `NetPulse.exe` sera généré dans `dist/`.

> 💡 Pour bénéficier du scan ARP complet une fois compilé, exécutez `NetPulse.exe`
> en tant qu'administrateur (clic droit → « Exécuter en tant qu'administrateur »),
> et assurez-vous que [Npcap](https://npcap.com/) est installé sur la machine cible.

### Détail des options PyInstaller
| Option           | Rôle                                                  |
|-------------------|--------------------------------------------------------|
| `--noconsole`     | Masque la console (application purement graphique).    |
| `--onefile`       | Génère un unique fichier `.exe` autonome.               |
| `--icon=...`      | Intègre l'icône `NetPulse.ico` à l'exécutable.          |
| `--name=NetPulse` | Nom du fichier exécutable final.                        |

### ⚠️ Remarque importante pour PyInstaller + scapy
`scapy` charge dynamiquement certains modules. Si l'exécutable compilé ne
détecte aucun appareil en scan ARP (alors que cela fonctionne en mode script),
ajoutez les imports cachés suivants à la commande :

```bash
pyinstaller --noconsole --onefile --icon=NetPulse.ico --name=NetPulse ^
  --hidden-import=scapy.layers.all ^
  --hidden-import=scapy.arch.windows ^
  main.py
```//
(Sous Windows, `^` permet de poursuivre la commande sur plusieurs lignes ;
utilisez `\` sous Linux/macOS.)

## ⚠️ Remarques

- La base SQLite `netpulse_history.db` est créée automatiquement dans le dossier
  de l'application au premier lancement.
- Le scan de ports interne (repli sans `nmap`) est volontairement limité à des
  sondes TCP simples (connexion + lecture de bannière) : il ne réalise ni
  exploitation de vulnérabilité, ni test d'intrusion actif.
- Testé sous Windows, Linux et macOS (le scan ARP nécessite des privilèges
  administrateur/root sur toutes les plateformes).

<!-- installeur-release -->
## Installation

Téléchargez **`NetPulse-Setup-1.0.0.exe`** depuis la [dernière release](https://github.com/Les-Doubles-A/NetPulse/releases/latest), puis lancez-le.

L'installation se fait pour l'utilisateur courant, sans droits administrateur (par défaut dans `%LOCALAPPDATA%\Programs\NetPulse`), avec un raccourci dans le menu Démarrer et une désinstallation depuis les Paramètres Windows.

L'installeur n'est pas signé : si Windows SmartScreen l'affiche, cliquez sur « Informations complémentaires » puis « Exécuter quand même ».

### Recréer l'installeur

Compiler l'application (`pyinstaller NetPulse.spec`), puis lancer [Inno Setup 6](https://jrsoftware.org/isinfo.php) : `iscc installer\NetPulse.iss`. Le setup est créé dans `installer\Output\`.
