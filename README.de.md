# Sicherheit von Webanwendungen

Dies ist eine Anleitung um Web-Anwendungen abzusichern.

In erster Linie um Daten zu schützen:

* Ausspionieren von Daten und Datenklau (z.B. Entwenden von Logindaten)

Ferner um Systeme zu schützen:

* Überlastungsversuche, etc.

## 1. Sicherheitskonzepte via HTTP-Header Ausspielungen

Headereinstellungen können je nach verwendetem Webserver mittels seiner Webservereinstellungen, seiner in den Webprojekten vorhandenen Konfigurationsdateien z.B. der `.htaccess`-Datei (NCSA kompatible Webserver<sup>1</sup>) oder direkt in in den Script-Sprachen seiner ausgelieferten Webanwendungen selbst gesetzt werden (z.B. mittels einer Scriptsprache wie PHP, Ruby, Python, etc.). 

### 1.1 Vorbetrachtungen

#### 1.1.1 Webservereinstellungen

In Bearbeitung...

#### 1.1.2 `.htaccess`

Nachfolgend aufgeführt sind die `.htaccess` Einstellungen, um verschiedene Inhaltsaufrufe zu erkennen. Erkannt wird in dem nachfolgendem Beispiel der Aufruf des Backends TYPO3 (`/typo3/`), der Aufruf von Web-Assets (Bilder, etc.) und der Rest (alles außer TYPO3 und Web-Assets):

```bash
# ----------------------------------------------------------------------
# | Content detection                                                  |
# ----------------------------------------------------------------------
<IfModule mod_headers.c>
    # avoid double detection (only one is used below - even if more then one
    # conditions applies)
    SetEnvIfNoCase REQUEST_URI "^" content-type=default
    SetEnvIfNoCase REQUEST_URI "\.(png|jpg|jpeg|gif|css|js)$" content-type=assets
    SetEnvIfNoCase REQUEST_URI "^/(typo3/)" content-type=typo3

    # set single (boolean) variable from content-type (can be used everywhere: 
    # content-type-default, content-type-assets, content-type-api
    SetEnvIf content-type "^default$" content-type-default
    SetEnvIf content-type "^assets$"  content-type-assets
    SetEnvIf content-type "^typo3$"   content-type-typo3
</IfModule>
```

Mit Hilfe der nun zur Verfügung stehenden Variablen `content-type-default`, `content-type-assets` und `content-type-typo3` können dann in den nachfolgenden Beispielen entsprechend die Header gesetzt werden.

Eine Alternative für die Inhaltserkennung, jedoch etwas komplexer in der Notation, ist auch die Abfrage mit Hilfe der `RewriteRule`/`RewriteCond` "Technik":

```bash
<IfModule mod_headers.c>
    # avoid double detection (only one is used below - even if more then one
    # conditions applies)
    RewriteRule .* - [ENV=content-type:default]
    RewriteCond %{REQUEST_URI} "\.(png|jpg|jpeg|gif|css|js)$"
    RewriteRule .* - [ENV=content-type:assets]
    RewriteCond %{THE_REQUEST} "/v1/.*"
    RewriteRule .* - [ENV=content-type:api]

    # set single (boolean) variable from content-type (can be used everywhere: 
    # content-type-default, content-type-assets, content-type-api
    RewriteCond %{ENV:content-type} default
    RewriteRule .* - [ENV=content-type-default:true]
    RewriteCond %{ENV:content-type} assets
    RewriteRule .* - [ENV=content-type-assets:true]
    RewriteCond %{ENV:content-type} api
    RewriteRule .* - [ENV=content-type-api:true]
</IfModule>
```

Der Vorteil in der zuletzt genannten Version liegt darin, dass man neben dem Zugriff auf Standard-Servervariablen wie `REQUEST_URI` auch den Zugriff auf "besondere" Variablen (specials) wie `THE_REQUEST` erhält. Der Zugriff z.B. auf `THE_REQUEST` ist mittels `SetEnvIfNoCase` bzw. `SetEnvIf` nicht möglich.

#### 1.1.3 PHP

In Bearbeitung...

### 1.2 XSS

Durch [XSS](https://de.wikipedia.org/wiki/Cross-Site-Scripting)<sup>Wiki</sup> oder auch webseitenübergreifendem Skripting ist es dem Angreifer möglich ungewollt Script-Schadcode auf der Webseite auszuführen.

#### 1.2.1 Problem

Der ungewollt importierte und ausgespielte Schadcode ermöglicht es z.B. Session-Daten zu entwenden ([Session Hijacking](https://de.wikipedia.org/wiki/Session_Hijacking)<sup>Wiki</sup>). Ungewollter Fremdcode kann überall dort in das Webprojekt gelangen, wo Daten in das Projekt zur Auswertung importiert oder zur Datenspeicherung übertragen werden:

* Suchformulare
* Eingabemasken
  * Kommentare
  * Gästebuch
  * Emailversand-Formulare
  * Kontakt-Formulare
  * etc.
* Datenimporte
  * API-Anbindungen fremder Quellen
  * Parsing von fremden Quellen
  * Datenbankimporte fremder Quellen
  * Einbinden fremder Quellen in das Webprojekt (z.B. über die Paketverwaltung: npm, composer, etc.)
  * etc.

Werden diese kompromitierten Daten ungeprüft an den Client (Browser) gesendet, können diese im ungünstigsten Fall zur Ausführung gebracht werden (um z.B. ungewollt wichtige Daten zu entwenden). Generell ist es immer eine gute Idee alle möglichen Importe zu überwachen und gegebenenfalls zu filtern. Durch die unzählige Anzahl an Importmöglichkeiten, die Möglichkeit den schadhaften Code in unzähligen Varianten zu verschleiern, sollte man zusätzlich die Ausführungsebenen des Scriptings einschränken:

* Inline-Scripting generell verbieten und in externe Dateien in vertrauenswürdige Quellen auslagern, weil die Unterscheidung von eigenem (gutartigem) Code zu schadhaften Code beim Inline-Scripting besonders schwierig ist
* Nur vertrauenswürdige Quellen beim Nachladen der Script-Dateien erlauben
* Alle anderen Quellen als die vertrauenswürdigen verbieten

#### 1.2.2 Lösung (Content Security Policy)

Ein Lösungsansatz neben dem Filtern der importierten Dateien ist die Einschränkung der Script-Ausführungsebenen. Hierfür bieten die Browser den [Content Security Policy](https://de.wikipedia.org/wiki/Content_Security_Policy)<sup>Wiki</sup>-Ansatz. Die gewünschten Regeln werden über die [HTTP-Header](https://de.wikipedia.org/wiki/Liste_der_HTTP-Headerfelder)<sup>Wiki</sup> ausgespielt.

#### 1.2.3 Beispiele

##### 1.2.3.1 Beispiel via `.htaccess`

Im nachfolgendem Beispiel wird als Standard für das Projekt das Inline-Scripting verboten, die vertrauenswürdigen Script-Quellen auf die eigene Seite und die Domain https://code.jquery.com beschränkt. Für Assets (siehe Vorbetrachtung) werden keine weiteren Header und somit Einschränkungen gesetzt und sind hier deshalb nicht aufgeführt. Sollte ein bestimmter Bereich (z.B. das Backend wie TYPO3) mit bestimmten Einschränkungen nicht mehr funktionieren (z.B. Inline-Script), so muss dieser Bereich angepasst werden (`content-type-typo3`). Ältere Browser, welche den CSP Header nicht unterstützen, unterstützen unter Umständen eine ähnliche Technik [X-XSS-Protection](https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/X-XSS-Protection), welche Cross-Site-Scripting Filter aktivieren:

```bash
# ----------------------------------------------------------------------
# | Content Security Policy (CSP)                                      |
# ----------------------------------------------------------------------
<IfModule mod_headers.c>
    Header set Content-Security-Policy "script-src 'self' https://code.jquery.com;" env=content-type-default
    Header set Content-Security-Policy "script-src 'self' 'unsafe-inline' 'unsafe-eval';" env=content-type-typo3
</IfModule>

# ----------------------------------------------------------------------
# | X-XSS-Protection (for older browsers)                              |
# ----------------------------------------------------------------------
<IfModule mod_headers.c>
    Header set X-XSS-Protection "1; mode=block" env=content-type-default
    Header set X-XSS-Protection "1; mode=block" env=content-type-typo3
</IfModule>
```

##### 1.2.3.2 Beispiel via Meta-Tag

Die gewünschten Einschränkungen können ebenfalls via Meta-Tag angegeben werden:

```html
<!doctype html>
<head>
  <meta http-equiv="Content-Security-Policy" content="default-src 'self'; script-src 'self'">
  <meta http-equiv="X-Content-Security-Policy" content="default-src 'self'; script-src 'self'">
  <meta http-equiv="X-WebKit-CSP" content="default-src 'self'; script-src 'self'">
  <title>page that wants to use CSP</title>
</head>
```

#### 1.2.4 Hinweise

Ziel jeder Webentwicklung sollte es immer sein ohne Inline-Scripting und einer überschaubaren Anzahl von vertrauenswürdigen Script-Quellen auszukommen. Auch die Verwendung von Text zu Javascript umwandelnden Funktionen (`eval`) sollte strikt vermieden werden.

Generell empfehle ich jedem während der Webentwicklung sich tiefer mit dem Thema [Content Security Policy](https://content-security-policy.com/) zu beschäftigen. Neben dem Scripting können hierüber hinaus auch andere Datenquellen eingeschränkt und abgeschottet werden:

* Gültiger Standard - Alle nachfolgenden Quellen (`default-src`)
* Gültige Quellen für XMLHttpRequest (AJAX), WebSocket und EventSources-Verbindungen (`connect-src`)
* Gültige Quellen für Stylesheets (`style-src`)
* Gültige Bild-Quellen (`img-src`)
* Gültige Schriftquellen (`font-src`)
* etc.

Eine gute Idee ist es das Projekt während der Entwicklung anfangs komplett einzuschränken und nachträglich zusätzlich benötigte und vertrauenswürdige Quellen hinzuzufügen:

```bash
# ----------------------------------------------------------------------
# | Content Security Policy (CSP)                                      |
# ----------------------------------------------------------------------
<IfModule mod_headers.c>
    Header set Content-Security-Policy "default-src 'self';"
</IfModule>
```

Das obige Beispiel schließt "Inline"-Ausführungen aus und beschränkt die vertrauenswürdigen Quellen auf die ausliefernde Domain. Die blockierten Quellen können problemlos über die Entwicklerkonsole eingesehen werden:

<img alt="Blockierte Scriptausführungen" src="/images/console.log.1.png" width="584">

Ältere Browser nutzen unter Umständen nicht die browserübergreifende Option `Content-Security-Policy`, sondern nutzen einen browsereigenen "Standard":

* X-Content-Security-Policy
* X-Webkit-CSP

Diese sind "veraltet" (deprecated). Es ist durchaus dennoch eine gute Idee diese parallel mit zu integrieren:

```bash
# ----------------------------------------------------------------------
# | Content Security Policy (CSP)                                      |
# ----------------------------------------------------------------------
<IfModule mod_headers.c>
    Header set Content-Security-Policy "script-src 'self' https://code.jquery.com;" env=content-type-default
    Header set Content-Security-Policy "script-src 'self' 'unsafe-inline' 'unsafe-eval';" env=content-type-typo3
    Header set X-Content-Security-Policy "script-src 'self' https://code.jquery.com;" env=content-type-default
    Header set X-Content-Security-Policy "script-src 'self' 'unsafe-inline' 'unsafe-eval';" env=content-type-typo3
    Header set X-Webkit-CSP "script-src 'self' https://code.jquery.com;" env=content-type-default
    Header set X-Webkit-CSP "script-src 'self' 'unsafe-inline' 'unsafe-eval';" env=content-type-typo3
</IfModule>
```

Sie auch: [content-security-policy.com](https://content-security-policy.com/)

### 1.3 Clickjacking & Cross-Site-Request-Forgery (CSRF) mittels Inlineframes

Ziel beider Varianten ist das Unterschieben manipulierter URLs bzw. das Einbetten der eigenen Seite innerhalb einer anderen, um ungewünschte Aktionen zu provozieren.

Durch [Clickjacking](https://de.wikipedia.org/wiki/Clickjacking)<sup>Wiki</sup> ist es dem Angreifer möglich Clicks und Tastatureingaben für den Benutzer unbemerkt auf der eingebundenen Seite auszuführen bzw. diese Usereingaben abzufangen.

Beim sogenannten [CSRF](https://de.wikipedia.org/wiki/Cross-Site-Request-Forgery) wird bei der Inlineframe-Variante eine manipulierte URL aufgerufen, welche im ungünstigsten Fall eine ungewollte Aktion durchführt. Als Beispiel sei ein eingeloggter Administrator erwähnt, dem der Aufruf einer Benutzererstellen-Seite untergeschoben wird.

#### 1.3.1 Problem

Manchmal gewünscht, meist jedoch nicht und unbekannt, wird durch das Einbinden der eigenen Seite unter einer fremden und dem Angreifer gehörenden Domain die Möglichkeit geschaffen unsichtbare oder sichtbare Layer über diese zu legen. Mit diesen Layern ist es möglich Usereingaben abzufangen oder an die eingebundene Seite durchzureichen. Im noch "günstigsten" Fall wird ein Objekt z.B. über einen Like Button gelegt, welcher bei Click auf das Objekt die Aktionen des Like Buttons der eingebundenen Seite durchführt. In einem kritischeren Fall wird über eine Logineingabe der eingebundenen Seite eine unsichtbare Maske gelegt. Statt die Login-Daten wie erwartet in der eingebundenen Seite einzugeben und abzuschicken, werden die Daten in eine unsichtbar darüberliegenden Login-Form eingegeben und an den Angreifer gesendet. Die Angreifer besitzt nun die Login-Daten des eingebundenen Projektes.

#### 1.3.2 Lösung (`X-Frame-Options`)

Ein Lösungsansatz ist das Einbinden der eigenen Seite auf anderen Seiten zu verbieten. Hierfür bieten die Browser die Möglichkeit dies über den [HTTP-Header](https://de.wikipedia.org/wiki/Liste_der_HTTP-Headerfelder)<sup>Wiki</sup> `X-Frame-Options` zu steuern. Per Default ist es möglich, jede Seite auf jeder anderen Seite einzubinden. Mögliche Optionen für den Header `X-Frame-Options`  finden sich z.B. hier: [X-Frame-Options](https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/X-Frame-Options)

#### 1.3.3 Beispiel via `.htaccess`

Das nachfolgende Beispiel erlaubt das Einbinden der eigenen Seite innerhalb der eigenen Domain und verbietet es für andere Domains: 

```bash
# ----------------------------------------------------------------------
# | Clickjacking                                                       |
# ----------------------------------------------------------------------
<IfModule mod_headers.c>
    Header set X-Frame-Options "SAMEORIGIN" env=content-type-default
    Header set X-Frame-Options "SAMEORIGIN" env=content-type-typo3
</IfModule>
```

#### 1.3.4 Hinweise

Ein Verzicht auf das Einbinden der eigenen Seite in andere Seite sollte das Ziel sein und ist erfahrungsgemäß auch die Variante, welche am meisten auftritt. Ein Setzen und eine Einschränkung über die Verwendung des Headers `X-Frame-Options` ist wie im obigen Beispiel daher meist unproblematisch.

### 1.4 Zwang der verschlüsselten Übertragung (HTTPS)

Nur sichere, verschlüsselte Verbindungen ([HTTPS](https://de.wikipedia.org/wiki/Hypertext_Transfer_Protocol_Secure)<sup>Wiki</sup>, HTTP Secure, HTTP + SSL/TLS, etc.) erfüllen die drei wichtigsten Regeln der Informationssicherheit: [Vertraulichkeit](https://de.wikipedia.org/wiki/Vertraulichkeit)<sup>Wiki</sup>, [Integrität](https://de.wikipedia.org/wiki/Integrit%C3%A4t_(Informationssicherheit))<sup>Wiki</sup> und [Authentizität](https://de.wikipedia.org/wiki/Authentizit%C3%A4t)<sup>Wiki</sup>

#### 1.4.1 Problem

Unsichere, unverschlüsselte Verbindung können abgehört und verändert werden. Gerade wenn nicht bekannt ist welche Übertragungsmedien beim Aufruf des Webprojektes verwendet werden (offenes WLAN, etc.), ist es ohne großen Aufwand möglich übertragene Daten abzuhören und gegebenenfalls zu verändern. Besonders problematisch ist dies bei:

* Loginformularen (Zugangsdaten)
* der Übertragung von bedenklichen und bedeutenden Informationen (Zahlungsdaten, etc.)
* besonders zu schützenden Daten (personenbezogene Daten, etc.)

Weiterhin problematisch sind unbemerkt veränderte Daten, während man sich auf einer sicheren Seite wähnt:

* kompromitierte Downloads (Viren, Trojaner, Spyware und andere Schadprogramme)
* Falschinformationen (während der Übertragung zum Ziel geänderte Daten)

#### 1.4.2 Lösung

Per default ruft der Browser standardmäßig die Seite per http Protokoll (unverschlüsselt) ab, wenn nicht das HSTS Flag gesetzt wird oder eine Umleitung per RewriteRule vorgenommen wird. Nachfolgend werden diese Einstellungen z.B. mittels `.htaccess` Datei vorgenommen.

#### 1.4.3 Beispiel via `.htaccess`

```bash
# ----------------------------------------------------------------------
# | enable redirection                                                 |
# ----------------------------------------------------------------------
RewriteEngine On

# ----------------------------------------------------------------------
# | redirect nonwww to www (ignore /.well-known)                       |
# ----------------------------------------------------------------------
RewriteCond %{HTTP_HOST} !^www\. [NC]
RewriteCond %{REQUEST_URI} !^/.well-known
RewriteRule ^(.*)$ https://www.%{HTTP_HOST}%{REQUEST_URI} [R=301,L]

# ----------------------------------------------------------------------
# | redirect http to https I (ignore /.well-known)                      |
# ----------------------------------------------------------------------
RewriteCond %{HTTPS} !=on
RewriteCond %{REQUEST_URI} !^/.well-known
RewriteRule ^(.*)$ https://%{HTTP_HOST}$1 [R=301,L]

# ----------------------------------------------------------------------
# | redirect http to https II (ignore /.well-known)                    |
# ----------------------------------------------------------------------
RewriteCond %{SERVER_PORT} !^443$
RewriteCond %{REQUEST_URI} !^/.well-known
RewriteRule ^(.*)$ https://%{HTTP_HOST}$1 [R=301,L]

# ----------------------------------------------------------------------
# | HTTP Strict Transport Security (HSTS)                              |
# ----------------------------------------------------------------------
<IfModule mod_headers.c>
    Header always set Strict-Transport-Security "max-age=31536000; includeSubDomains; preload"
</IfModule>
```

#### 1.4.4 Hinweise

Für eine verschlüsselte Verbindung wird ein signiertes Zertifikat benötigt. Diese erhält man bei einer Zertifizierungsstelle der Wahl. Z.B.:

* [Let's Encrypt](https://letsencrypt.org/) (kostenlos)
* [Thawte](https://www.thawte.de/ssl/) (ab 129€ / Jahr)
* [Host Europe](https://www.hosteurope.de/SSL-Zertifikate/) (ab 2,99€ / Monat; Reseller)
* ...

Es gibt unterschiedliche Zertifizierungstypen und somit Zertifikatstypen:

* Domain Validation (DV)
* Organisation Validation (OV)
* Extended Validation (EV)

Google und andere Suchmaschinen bevorzugen bei den Ergebnissen verschlüsselte Verbindungen im Ranking. Browser weisen auf unverschlüsselte Verbindungen hin bzw. lehnen teilweise unsichere Verbindungen ab, wenn eine Datenübermittlung ungesichert stattfindet (z.B. ein abgesendetes Formular). Weiterhin wichtig: Eine erfolgreich eingerichtete sichere Übertragung zum Projekt allein reicht nicht. Auch eingebundene Quellen und Bibliotheken müssen gesichert eingebunden werden, damit die Seite im Browser als sicher eingestuft wird. Einen vollständig sicheren Aufruf erkennt man an der Adresszeile (*Variante 1*):

<kbd><img alt="Sichere Verbindung" src="/images/secure.png" width="244"></kbd> <sup>**_(Chrome)_**</sup>

Unsichere Aufrufe erkennt man wie folgt (*Variante 2*):

<kbd><img alt="Sichere Verbindung" src="/images/not-secure.png" width="150"></kbd> <sup>**_(Chrome)_**</sup>

Sichere Aufrufe, jedoch unsicher eingebundene Quellen erkennt man wie folgt (*Variante 3*):

<kbd><img alt="Sichere Verbindung" src="/images/secure-mixed-not-secure.png" width="107"></kbd> <sup>**_(Chrome)_**</sup>

Ziel sollte es immer sein, die Adressdarstellung "*Variante 1*" zu erhalten. Zu erkennen an der grünen Adresszeile.

### 1.5 Auflisten von Ordnerinhalten

Standarmäßig ist das Indexing der Dateien je nach Webserver-Einstellung aktviert. Damit ist es möglich durch Aufruf von Ordnern ohne Angabe von Dateien deren Inhalt aufzulisten und den Inhalt des Ordners einzusehen.

#### 1.5.1 Problem

Ruft man im Webprojekt direkt einen Ordner ohne Angabe einer Datei auf, so versucht der Webserver eine der angegebenen Index-Dateien zu finden und diese aufzurufen. Standardmäßig sind dies die Dateien:

* index.php
* index.html

Man kann den Standard mit folgender Konfiguration z.B. in der `.htaccess`-Datei ändern:

```bash
DirectoryIndex index.php index.html otherIndexFile.php otherIndexFile.html
```

Findet der Webserver keine der angegebenen Dateien bzw. Standard-Index-Dateien, so listet der Webserver den Inhalt des Ordners auf, sofern das Datei-Indexing nicht abgeschalten worden ist:

<kbd><img alt="enabled indexing" src="images/file-indexing-on.png" width="497"></kbd>

In diesem Fall kann der Angreifer den Inhalt dieses Ordners einsehen und seine Angriffe entsprechend anpassen bzw. einfach Zugriff auf versteckte Dateien bekommen. Das Dateilisting sollte, wenn nicht anders gefordert, immer deaktiviert werden.

#### 1.5.2 Lösung

Das Datei-Listing wird wie im nachfolgendem Beispiel angegeben deaktiviert.

#### 1.5.3 Beispiel via `.htaccess`

```bash
# ----------------------------------------------------------------------
# | Disable Indexing                                                   |
# ----------------------------------------------------------------------
Options -Indexes
```

Wird nun der Ordner ohne genaue Angabe der Datei aufgerufen, so verweigert der Webserver den Zugriff:

<kbd><img alt="enabled indexing" src="images/file-indexing-off.png" width="375"></kbd>

#### 1.5.4 Hinweise

Damit die Option `Options` und `DirectoryIndex` in der `.htaccess` funktioniert, muss im Webserver die Option `AllowOverride All` gesetzt sein.

### 1.6 Sichere Cookies

In Bearbeitung... (.git, etc.)

#### 1.6.1 Problem

In Bearbeitung...

#### 1.6.2 Lösung

In Bearbeitung...

#### 1.6.3 Beispiel via `.htaccess`

```bash
# ----------------------------------------------------------------------
# | Secure Cookies                                                     |
# ----------------------------------------------------------------------
<IfModule mod_headers.c>
    Header edit Set-Cookie "^(.*)$" "$1; HttpOnly; Secure" env=content-type-default
    Header edit Set-Cookie "^(.*)$" "$1; Secure" env=content-type-typo3
</IfModule>
```

```
# ----------------------------------------------------------------------
# | Secure Cookies                                                     |
# ----------------------------------------------------------------------
<IfModule mod_headers.c>
    Header edit Set-Cookie "(?i)^((?:(?!;\s?secure).)+)$" "$1; Secure"
    Header edit Set-Cookie "(?i)^((?:(?!;\s?httponly).)+)$" "$1; HTTPOnly"
    Header edit Set-Cookie "(?i)^((?:(?!;\s?samesite=).)+)$" "$1; SameSite=Lax"
</IfModule>
```

#### 1.6.4 Hinweise

In Bearbeitung...

### 1.7 Besonders zu schützende Ordner und Dateien (nicht öffentliche Bereiche)

Es gibt Bereiche auf der Webseite (z.B. das Backend, Infodateien, etc.), welche nicht für die Öffentlichkeit bestimmt sind. Diese sollten auch nicht öffentlich erreichbar sein und vor unberechtigtem Zugriff geschützt werden.

#### 1.7.1 Problem

Besonders zu schützende und nicht der Öffentlichkeit vorgehaltene Bereiche sollten einen erweiterten Schutz erhalten. Dies kann z.B. ein zusätzlicher Verzeichnisschutz sein und erschwert z.B. Angreifern das Ausspionieren von wichtigen Informationen oder Angriffe auf bekannte Sicherheitslücken. Besonders zu schützende Bereiche sind z.B.:

* Backenzugriffe
  * TYPO3: `/typo3`
  * Contao: `/contao`
  * Wordpress: `/wp-admin`
* Informationsseiten
  * Webserverinformationen, wie `/server-status` oder `/nginx_status`
  * Projektinformationen, wie `info.php`

Weitere sensible Bereiche können auch in der `robots.txt` ausgeschlossenen Dateien und Ordner sein (`Disallow`), wobei diese Datei problemlos von jedem Angreifer eingesehen werden kann. Diese sollten ebenfalls in den zusätzlichen Schutz mit aufgenommen werden:

```bash
User-Agent: *
Allow: /
Disallow: /typo3/
Disallow: /print/
```

#### 1.7.2 Lösung

Eine mögliche zusätzliche Absicherung kann der schon erwähnte **Verzeichnisschutz** sein. Weitere Möglichkeiten sind:

* Ausschließen der Auslieferung über den Webserver (HTTP-Statuscode 404)
* Auslieferung der Bereiche nur über bestimmte Erkennungsmerkmale (speziell angepasster User-Agent, etc.)

#### 1.7.3 Beispiel via `.htaccess`

##### 1.7.3.1 Create a `.htpasswd` file:

```bash
user$ htpasswd -cb /var/www/path/to/web/root/current/web/.htpasswd username password
```

##### 1.7.3.2 The `.htaccess` file

```bash
# ----------------------------------------------------------------------
# | Password protection for some areas                                 |
# ----------------------------------------------------------------------
<If "%{HTTP_HOST} =~ /(www\.)?(domain1|domain2)\.de/">
    AuthType     Basic
    AuthName     "rsmBE"
    AuthUserFile /var/www/path/to/web/root/current/web/.htpasswd
    require      valid-user

    # set protection env var if crucial pages are requested
    SetEnvIfNoCase REQUEST_URI "^/(typo3/|contao/|wp-admin/|print/|wp-login.php|wp-config.php|server-status|nginx_status|info.php)" protected-crm

    # Special Environments
    Order allow,deny
    Allow from env=!protected-crm
    Satisfy any
</If>

# ----------------------------------------------------------------------
# | Password protection for the entire page                            |
# ----------------------------------------------------------------------
<If "%{HTTP_HOST} =~ /(www\.)?(domain1|domain2)\.de/">
    AuthType     Basic
    AuthName     "rsm"
    AuthUserFile /var/www/path/to/web/root/current/web/.htpasswd
    require      valid-user
</If>


# ----------------------------------------------------------------------
# | Block access of some areas (always)                                |
# ----------------------------------------------------------------------
<IfModule mod_alias.c>
    RedirectMatch 404 /(info.php|folder1/|folder2/)/
</IfModule>

# ----------------------------------------------------------------------
# | Block access of some areas (if the user agent does not contain     |
# | the SPECIAL_STRING)                                                |
# ----------------------------------------------------------------------
<If "%{HTTP_USER_AGENT} !~ /\[SPECIAL_STRING\]/">
    RedirectMatch 404 ^/log
    RedirectMatch 404 ^/revision-infos
</If>
```

#### 1.7.4 Hinweise

In Bearbeitung...

### 1.8 Versteckte Ordner

Ähnlich wie die besonders zu schützenden Ordner und Dateien (nicht öffentliche Bereiche), gibt es Ordner und Dateien, welche generell nicht erreichbar sein sollen. Das können z.B. "Hilfsdateien" oder Konfigurationsordner sein, welche zum Betrieb des Projektes über die Konsole dienen (.git, .svn, .hg, etc.). Sofern diese nicht für das Webprojekt benötigt werden, sollten diese Bereiche komplett von der Auslieferung über den Webserver ausgeschlossen werden.

#### 1.8.1 Problem

Für das Projekt selbst "wertlose" Informationen, welche nicht für die eigentliche Auslieferung des Projektes benötigt werden, sind öffentlich erreichbar. Diese Informationen und vor allem die, die einem Angreifer helfen Angriffspunkte zu finden (Projektpfad, Repository-URL, etc.), sollten nicht erreichbar sein.

#### 1.8.2 Lösung

Die oben genannten Informationsorder und Informationsdateien können von der Auslieferung ausgeschlossen werden. Hierzu ist es beim versuchten Zugriff auf diese Quellen möglich ein "404 - Not Found" HTTP-Status-Code zu simulieren.

#### 1.8.3 Beispiel via `.htaccess`

```bash
# ----------------------------------------------------------------------
# | Block access to vcs directories (Git, SVN, Mercurial               |
# ----------------------------------------------------------------------
<IfModule mod_alias.c>
    RedirectMatch 404 /\.(?:git|svn|hg)/
</IfModule>
```

#### 1.8.4 Hinweise

Für das Einstellen des "404 - Not Found" HTTP-Status-Code sind derzeit keine Hinweise vorhanden.

### 1.9 Referrer Policy

Bei jedem Aufruf (vor allem beim Aufruf von externen Seiten) wird die Quelle der aktuellen Seite an die neu aufgerufene Seite übertragen (Referrer). Dieser sogenannte Referrer bezeichnet im World Wide Web die Webseite, über die der Benutzer zur aktuellen Webseite bzw. Datei gekommen ist. Die Übertragung ist manchmal gewünscht, um z.B. Statistiken des Aufrufs zu führen bzw. Einschränkungen des Aufrufes zu prüfen. In anderen Fällen ist dies nicht wirklich notwendig. "Zusätzliche" Informationen sollten nur übertragen werden, wenn diese auch wirklich benötigt werden (Stichwort Datenschutz). In solchen Fällen kann diese Informationsübertragung verhindert werden. Vor allem bei unverschlüsselten Übertragungen sollten unnötige Informationen weitestgehend eingeschränkt werden, damit Angreifer diese nicht lesen und abfangen können. Nachfolgend wird erläutert, wie die Referrer-Übertragung eingeschränkt werden kann (z.B. nur bei verschlüsselten Übertragungen).

#### 1.9.1 Problem

Unnötige Referrer-Informationen werden an externe Seiten übertragen, obwohl dies nicht notwenig ist.

#### 1.9.2 Lösung

Mit Hilfe des Headers `Referrer-Policy` kann man die Übertragung einschränken. Zu den möglichen Optionen, siehe auch [Referrer-Policy](https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Referrer-Policy).

#### 1.9.3 Beispiel via `.htaccess`

```bash
# ----------------------------------------------------------------------
# | Referrer Policy (RP)                                               |
# ----------------------------------------------------------------------
<IfModule mod_headers.c>
    Header always set Referrer-Policy "no-referrer-when-downgrade"
</IfModule>
```

#### 1.9.4 Hinweise

In Bearbeitung...

### 1.10 Feature Policy

In Bearbeitung...

#### 1.10.1 Problem

In Bearbeitung...

#### 1.10.2 Lösung

In Bearbeitung...

#### 1.10.3 Beispiel via `.htaccess`

```bash
# ----------------------------------------------------------------------
# | Feature Policy (RP)                                               |
# ----------------------------------------------------------------------
<IfModule mod_headers.c>
    Header always set Feature-Policy "geolocation 'none'; midi 'none'; camera 'none'; usb 'none'; magnetometer 'none'; accelerometer 'none'; vr 'none'; speaker 'none'; ambient-light-sensor 'none'; gyroscope 'none'; microphone 'none'"
</IfModule>
```

#### 1.10.4 Hinweise

In Bearbeitung...

### 1.11 Content sniffing (MIME Sniffing)

[Content sniffing](https://en.wikipedia.org/wiki/Content_sniffing)

Hochgeladene Elemente entsprechen nicht dem gewünschten Inhaltselement. Z.B. Javascript statt Bild. Eingebundenes Javascript-Bild wird eingebunden und ausgeführt.

#### 1.11.1 Problem

In Bearbeitung...

#### 1.11.2 Lösung

In Bearbeitung...

#### 1.11.3 Beispiel via `.htaccess`

```bash
# ----------------------------------------------------------------------
# | Content sniffing                                                   |
# ----------------------------------------------------------------------
<IfModule mod_headers.c>
    Header append X-Content-Type-Options "nosniff"
</IfModule>
```

#### 1.11.4 Hinweise

In Bearbeitung...

### 1.12 DDoS

In Bearbeitung...

#### 1.12.1 Problem

In Bearbeitung...

#### 1.12.2 Lösung

In Bearbeitung...

#### 1.12.3 Beispiel via `.htaccess`

In Bearbeitung...

#### 1.12.4 Hinweise

In Bearbeitung...

### 1.20 Anderes

* X-Powered-By
* ServerSignature

#### 1.20.1 Beispiel via `.htaccess`

```bash
# other security header
Header unset X-Powered-By
ServerSignature Off
SetEnvIf Range (,.*?){5,} bad-range=1
RequestHeader unset Range env=bad-range
LimitRequestBody 2147483647

# general settings
AddDefaultCharset UTF-8
AddLanguage de-DE .html .htm .css .js
AddCharset utf-8 .atom .css .js .json .rss .vtt .xml
SetEnv TZ Europe/Berlin
```

## A. Weitere Anleitungen

* [A tutorial to securely transfer messages](https://github.com/friends-of-tutorials/securely-transfer-messages)

## B. Quellen

* [Open Web Application Security Project](https://www.owasp.org/index.php/Main_Page)
* [Open Web Application Security Project (Wikipedia)](https://en.wikipedia.org/wiki/OWASP)
* [BSI-Standards zur Internet-Sicherheit (ISi-Reihe)](https://www.bsi.bund.de/DE/Themen/StandardsKriterien/ISi-Reihe/ISi-Reihe_node.html)
* [BSI-Standards: Sicheres Bereitstellen von Web-Angeboten (ISi-Webserver)](https://www.bsi.bund.de/SharedDocs/Downloads/DE/BSI/Internetsicherheit/isi_web_server_studie.pdf?__blob=publicationFile&v=2)
* [BSI-Checkliste zum sicheren Bereitstellen von Web-Angeboten auf LAMP-Basis](https://www.bsi.bund.de/SharedDocs/Downloads/DE/BSI/Internetsicherheit/isi_web_server_checkliste_LAMP.pdf?__blob=publicationFile&v=3)
* [BSI-Checkliste zum sicheren Bereitstellen von Web-Angeboten mit WordPress](https://www.bsi.bund.de/SharedDocs/Downloads/DE/BSI/Internetsicherheit/isi_web_server_checkliste_WordPress.pdf?__blob=publicationFile&v=2)
* [BSI-Checkliste zum sicheren Bereitstellen von Web-Angeboten mit TYPO3](https://www.bsi.bund.de/SharedDocs/Downloads/DE/BSI/Internetsicherheit/isi_web_server_checkliste_Typo3.pdf?__blob=publicationFile&v=2)
* [BSI-Checkliste zum sicheren Bereitstellen von Web-Angeboten mit Joomla!](https://www.bsi.bund.de/SharedDocs/Downloads/DE/BSI/Internetsicherheit/isi_web_server_checkliste_Joomla.pdf?__blob=publicationFile&v=4)
* [.htaccess boilerplate I (apache)](https://github.com/h5bp/html5-boilerplate/blob/master/dist/.htaccess)
* [.htaccess boilerplate II (apache)](https://gist.github.com/ludo237/5857215)
* [Header mit TYPO3](https://jweiland.net/index.php?id=1165&L=1)
* [.htaccess Beispiele](https://www.askapache.com/htaccess/htaccess-fresh/)
* [Referrer Policy](https://scotthelme.co.uk/a-new-security-header-referrer-policy/)

## C. Tools

* [https://securityheaders.com](https://securityheaders.com)

## D. Fußnoten

* <sup>1</sup> = z.B. der Apache Webserver mit entsprechend aktivierten Modulen (z.B. [mod_rewrite](https://httpd.apache.org/docs/current/mod/mod_rewrite.html) oder [mod_headers](http://httpd.apache.org/docs/current/mod/mod_headers.html))

## E. Autoren

* Björn Hempel <bjoern@hempel.li> - _Erste Arbeiten_ - [https://github.com/bjoern-hempel](https://github.com/bjoern-hempel)

## F. Lizenz

Dieses Tutorial steht unter der MIT-Lizenz - siehe die Datei [LICENSE.md](/LICENSE.md) für weitere Informationen.
