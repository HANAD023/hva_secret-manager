# Propedeuse-opdracht 2025-2026 Cyber Security blok 1 - Secret Manager

<img src="docs/img/hbo-ict-logo.png" width="175" height="175" alt="HBO-ICT-LOGO">

In dit bestand(readme.md) vind je algemene informatie over de repository, zoals hoe je deze kunt gebruiken. Daaronder is 

## Hoe is deze repository ingericht 🔠

Er zijn twee belangrijke directories:
- docs
- secretsapp

In de docs folder vind je de [opdrachtsomschrijving](docs/opdracht.md) en zal je zelf ook documentatie plaatsen. Zoals bijvoorbeeld ontwerpen van de user interface.

In de secretsapp directory vind je alle source code van het project. Nu staat daar alleen nog een hello world voorbeeld van een flask applicatie.

In de issue lijst van gitlab vind je alle user stories waar je aan gaat werken met dit project. Lees deze en de opdrachtomschrijving goed door. 

## Flask

Om flask applicaties te runnen moeten we flask geinstalleerd hebben. Dit doen we bij voorkeur in een virtual environment. Voordat je verder gaat stel eerst een aantal vscode settings zoals hieronder beschreven.

Om een virtual environment aan te maken voer je het volgende commando uit:
`py -m venv .venv` of `python3 -m venv .venv`

Je virtual environment zou automatisch nu moeten starten. Zo niet kan je het handmatig doen met `.venv\Scripts\activate.bat` of `.venv\Scripts\activate.ps1` op windows en `source .venv/bin/activate` op linux en mac

Installeer nu flask met:

`pip3 install -r requirements.txt`

Na het installeren kan je flask runnen met:

`flask --app secretsapp run --debug` 

## VSCode settings

Om automatisch virtual environments te activeren dien je de volgende instellingen te activeren:
- Python › Terminal: Activate Env In Current Terminal
- Python › Terminal: Activate Environment

Om dit te doen open je eerst het command pallete. Deze kun je openen door middel van F1 of Ctrl+Shift+P. (Cmd+Shift+P voor MacOS)

Type in "user settings" om snel "Preferences: Open User Settings" te vinden.

Type in het zoekveld hier "Activate Env" om bovenstaande settings te vinden.

tip: Wellicht wil je ook je telemetry instellingen aanpassen. Je kan ook de ai uitzetten onder "Chat: Disable AI Features"