SEELENKRAFT TAROT – CLOUDFLARE PAGES + D1

Projektinhalt:
- public/index.html: Gastansicht, vorhandene Tarot-Bedienung, Tagesimpuls, Admin-Oberfläche.
- functions/api/[[path]].js: serverseitige Anmeldung, Sitzungen und Benutzerverwaltung.
- lib/member.js: 78 Karten, 10 Fragen und Mitgliederansicht; wird serverseitig eingebunden, nicht als statische Datei ausgeliefert.
- migrations/0001_init.sql: Tabellen für Nutzer, Sitzungen und Anmeldeversuche.

WICHTIG: Die HTML-Datei allein ist nicht die fertige Cloudflare-Anwendung. Die ZIP vollständig entpacken und als Pages-Projekt mit Functions veröffentlichen. Keine Dashboard-Drag-and-drop-Bereitstellung verwenden; Pages Functions werden laut Cloudflare über Git-Integration oder Wrangler bereitgestellt.

Einrichtung im Cloudflare-Dashboard:
1. D1-Datenbank erstellen, z. B. seelenkraft-tarot.
2. SQL aus migrations/0001_init.sql in der D1-Konsole ausführen (alternativ: npx wrangler d1 execute seelenkraft-tarot --remote --file=./migrations/0001_init.sql).
3. Pages-Projekt über ein Git-Repository mit diesem Projektverzeichnis verbinden. Build-Befehl: keiner; Ausgabeverzeichnis: public. functions/ und lib/ bleiben außerhalb von public im Projektwurzelverzeichnis; nur public/ wird statisch ausgeliefert.
4. Unter Pages > Settings > Bindings die D1-Datenbank mit Variablennamen DB verbinden. Auch Preview konfigurieren, falls nötig.
5. Unter Pages > Settings > Variables and Secrets als Secrets setzen: ADMIN_PASSWORD (gewünschtes Admin-Passwort), DEFAULT_USER_PASSWORD (gewünschtes Startpasswort für seelenkraft). Keine Passwörter in Git, index.html oder Wrangler-Konfigurationsdateien speichern. Nach Änderung neu bereitstellen.
6. Die initiale Anmeldung als admin mit ADMIN_PASSWORD oder seelenkraft mit DEFAULT_USER_PASSWORD testen. Der Startnutzer wird beim ersten Login einmalig angelegt und nach einer Löschung nicht erneut automatisch angelegt. Admin kann Nutzer hinzufügen, Passwörter ändern und Nutzer löschen.

Sicherheit: Passwort-Hashes werden mit PBKDF2 und individuellem Salt gespeichert. Sitzungen sind HttpOnly/Secure/SameSite-Cookies; Admin-Zugangsdaten werden nur serverseitig aus einem Secret geprüft. Admin-Passwort aus der Anfrage ist kurz; vor öffentlichem Betrieb durch ein langes, einzigartiges Passwort ersetzen. Anmeldung wird nach wiederholten Fehlversuchen zeitweise gedrosselt. Mitgliederinhalt wird über eine authentifizierte API geliefert. Kein Ersatz für professionelle Sicherheitsprüfung.

Bilder: Historische Rider-Waite-Smith-JPGs werden von Wikimedia Commons geladen; die Karten benötigen Internet. Die Schumann-Resonanz wird als typischer Hintergrundwert (ca. 7,83 Hz), nicht als Live-Messung dargestellt. Mondphase wird näherungsweise berechnet; Tagesimpuls ist eine datumsabhängige Reflexion, keine Vorhersage.

Nicht durchgeführt: Bereitstellung in deinem Cloudflare-Konto, weil kein Zugriff auf dein Konto und keine D1-ID vorhanden ist. Teste Login und Benutzerverwaltung nach dem Einrichten über die Pages-Domain (nicht per file://).


