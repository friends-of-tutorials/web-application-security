# Sicherheit von Webanwendungen

Eine Anleitung um Web-Anwendungen abzusichern.

## 1. Sicherheitskonzepte via HTTP-Header Ausspielungen

Headereinstellungen können je nach verwendeten Webserver via seinen Webservereinstellungen, via Konfigurationsdateien à la `.htaccess`-Datei (NCSA kompatible Webserver<sup>1</sup>) oder direkt in der Webanwendung selbst vorgenommen werden (via Scriptsprache wie PHP, Ruby, Python, etc.). 

### 1.1 Vorbetrachtungen

#### 1.1.1 Webservereinstellungen

In Bearbeitung...

#### 1.1.2 `.htaccess`

Nachfolgend `.htaccess` Einstellungen, um verschiedene Inhaltsaufrufe zu erkennen. Erkannt wird in diesem Beispiel der Aufruf des Backends TYPO3 (`/typo3/`), der Aufruf von Web-Assets (Bilder, etc.) und der Rest (alles außer TYPO3 und Web-Assets):

```bash
# ----------------------------------------------------------------------
# | Content detection                                                  |
# ----------------------------------------------------------------------
<IfModule mod_headers.c>
    # detect the content type (default=other, assets - images, video, etc., typo3 backend)
    SetEnvIfNoCase REQUEST_URI "^" content-type=default
    SetEnvIfNoCase REQUEST_URI "\.(appcache|atom|bbaw|bmp|br|crx|css|cur|eot|f4[abpv]|flv|geojson|gif|gz|htc|ic[os]|jpe?g|m?js|json(ld)?|m4[av]|manifest|map|markdown|md|mp4|oex|og[agv]|opus|otf|pdf|png|rdf|rss|safariextz|svgz?|swf|topojson|tt[cf]|txt|vcard|vcf|vtt|wasm|webapp|web[mp]|webmanifest|woff2?|xloc|xml|xpi)$" content-type=assets
    SetEnvIfNoCase REQUEST_URI "^/(typo3/)" content-type=typo3

    # translate the detected type into an unambiguous variable (because it is not possible to check a given variable value with env parameter)
    SetEnvIf content-type "^default$" content-type-default
    SetEnvIf content-type "^assets$"  content-type-assets
    SetEnvIf content-type "^typo3$"   content-type-typo3
</IfModule>
```

Mit Hilfe der nun zur Verfügung stehenden Variablen `content-type-default`, `content-type-assets` und `content-type-typo3` können dann in den nachfolgenden Beispielen entsprechend die Header gesetzt werden.

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

Werden diese kompromitierten Daten ungeprüft an den Client (Browser) gesendet, können diese im ungünstigsten Fall zur Ausführung gebracht werden. Generell ist es immer eine gute Idee alle möglichen Importe zu überwachen und gegebenenfalls zu filtern. Durch die unzählige Anzahl an Importmöglichkeiten, die Möglichkeit den schadhaften Code in unzähligen Varianten zu verschleiern, sollte man zusätzlich die Ausführungsebenen des Scriptings einschränken:

* Inline-Scripting generell verbieten und in externe Dateien in vertrauenswürdige Quellen auslagern, weil die Unterscheidung von eigenem (gutartigem) Code zu schadhaften Code beim Inline-Scripting besonders schwierig ist
* Nur vertrauenswürdige Quellen beim Nachladen der Script-Dateien erlauben
* Alle anderen Quellen als die vertrauenswürdigen verbieten

#### 1.2.2 Lösung (Content Security Policy)

Ein weiterer Lösungsansatz neben dem Filtern der importierten Dateien ist die Einschränkung der Script-Ausführungsebenen. Hierfür bieten die Browser den [Content Security Policy](https://de.wikipedia.org/wiki/Content_Security_Policy)<sup>Wiki</sup>-Ansatz. Die gewünschten Regeln werden über die [HTTP-Header](https://de.wikipedia.org/wiki/Liste_der_HTTP-Headerfelder)<sup>Wiki</sup> ausgespielt.

#### 1.2.3 Beispiel via `.htaccess`

Im nachfolgenden Beispiel wird als Standard für das Projekt das Inline-Scripting verboten, die vertrauenswürdigen Script-Quellen auf die eigene Seite und die Domain https://code.jquery.com beschränkt. Für Assets (siehe Vorbetrachtung) werden keine weiteren Header und somit Einschränkungen gesetzt und sind hier deshalb nicht aufgeführt. Sollte ein bestimmter Bereich (z.B. das Backend wie TYPO3) mit bestimmten Einschränkungen nicht mehr funktionieren (z.B. Inline-Script), so muss dieser Bereich angepasst werden (`content-type-typo3`). Ältere Browser, welche den CSP Header nicht unterstützen, unterstützen unter Umständen eine ähnliche Technik [X-XSS-Protection](https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/X-XSS-Protection), welche Cross-Site-Scripting Filter aktivieren:

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

#### 1.2.4 Hinweise

Ziel jeder Webentwicklung sollte es immer sein ohne Inline-Scripting und einer überschaubaren Anzahl von vertrauenswürdigen Script-Quellen auszukommen. Auch die Verwendung von Text zu Javascript umwandelnden Funktionen (`eval`) sollte strikt vermieden werden.

Generell empfehle ich jedem während der Webentwicklung sich tiefer mit dem Thema [Content Security Policy](https://content-security-policy.com/) zu beschäftigen. Neben dem Scripting können hierüber hinaus auch andere Datenquellen eingeschränkt und abgeschottet werden:

* Gültiger Standard (`default-src`)
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

### 1.3 Clickjacking

Durch [Clickjacking](https://de.wikipedia.org/wiki/Clickjacking)<sup>Wiki</sup> ist es dem Angreifer möglich Clicks und Tastatureingaben für den Benutzer unbemerkt auf der eingebundenen Seite auszuführen bzw. diese Usereingaben abzufangen.

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

Unsichere, unverschlüsselte Verbindung können abgehört und verändert werden. Gerade wenn nicht bekannt ist welche Übertragungsmedien verwendet werden (offenes WLAN, etc.) ist es ohne großen Aufwand möglich übertragene Daten abzuhören. Besonders problematisch ist dies bei:

* Loginformularen (Zugangsdaten)
* der Übertragung von bedenklichen und bedeutenden Informationen (Kreditkartendaten, etc.)
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
# | redirect http to https (ignore /.well-known)                       |
# ----------------------------------------------------------------------
RewriteCond %{HTTPS} !=on
RewriteCond %{REQUEST_URI} !^/.well-known
RewriteRule ^(.*)$ https://%{HTTP_HOST}$1 [R=301,L]

# ----------------------------------------------------------------------
# | HTTP Strict Transport Security (HSTS)                              |
# ----------------------------------------------------------------------
<IfModule mod_headers.c>
    Header always set Strict-Transport-Security "max-age=16070400; includeSubDomains"
</IfModule>
```

#### 1.4.4 Hinweise

Für eine verschlüsselte Verbindung wird ein signiertes Zertifikat benötigt. Diese erhält man bei einer Zertifizierungsstelle der Wahl:

* [Let's Encrypt](https://letsencrypt.org/) (kostenlos)
* [Thawte](https://www.thawte.de/ssl/) (ab 129€ / Jahr)
* [Host Europe](https://www.hosteurope.de/SSL-Zertifikate/) (ab 2,99€ / Monat; Reseller)

Es gibt unterschiedliche Zertifizierungstypen und somit Zertifikatstypen:

* Domain Validation (DV)
* Organisation Validation (OV)
* Extended Validation (EV)

Google und andere Suchmaschinen bevorzugen bei den Ergebnissen verschlüsselte Verbindungen im Ranking. Browser weisen auf unverschlüsselte Verbindungen hin bzw. lehnen teils unsichere Verbindungen ab, wenn eine Datenübermittlung stattfinden sollte (Formular). Eine erfolgreich eingerichtete Sicherheit zum Projekt allein reicht nicht. Auch eingebundene Quellen und Bibliotheken müssen gesichert eingebunden werden, damit diese im Browser als sicher eingestuft werden. Einen vollständig sicheren Aufruf erkennt man in der Adresszeile:

<img alt="Sichere Verbindung" src="/images/secure.png">

Unsicher eingebundene Quellen erkennt man wie folgt:



### 1.5 Auflisten von Ordnerinhalten

In Bearbeitung...

#### 1.5.1 Problem

In Bearbeitung...

#### 1.5.2 Lösung

In Bearbeitung...

#### 1.5.3 Beispiel via `.htaccess`

In Bearbeitung...

#### 1.5.4 Hinweise

In Bearbeitung...

### 1.6 Versteckte Ordner

In Bearbeitung... (.git, etc.)

#### 1.6.1 Problem

In Bearbeitung...

#### 1.6.2 Lösung

In Bearbeitung...

#### 1.6.3 Beispiel via `.htaccess`

```bash
# ----------------------------------------------------------------------
# | Block access to vcs directories (Git, SVN, Mercurial               |
# ----------------------------------------------------------------------
<IfModule mod_alias.c>
    RedirectMatch 404 /\.(?:git|svn|hg)/
</IfModule>
```

#### 1.6.4 Hinweise

In Bearbeitung...

### 1.7 Sichere Cookies

In Bearbeitung... (.git, etc.)

#### 1.7.1 Problem

In Bearbeitung...

#### 1.7.2 Lösung

In Bearbeitung...

#### 1.7.3 Beispiel via `.htaccess`

```bash
# ----------------------------------------------------------------------
# | Secure Cookies                              |
# ----------------------------------------------------------------------
<IfModule mod_headers.c>
    Header edit Set-Cookie "^(.*)$" "$1; HttpOnly; Secure" env=content-type-default
    Header edit Set-Cookie "^(.*)$" "$1; Secure" env=content-type-typo3
</IfModule>
```

#### 1.7.4 Hinweise

In Bearbeitung...

### 1.8 Besonders zu schützende Ordner und Dateien (nicht öffentliche Bereiche)

Es gibt Bereiche auf der Webseite (z.B. das Backend, Infodateien, etc.), welche nicht für die Öffentlichkeit bestimmt sind. Diese sollten auch nicht öffentlich erreichbar sein und vor unberechtigtem Zugriff geschützt werden.

#### 1.8.1 Problem

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

#### 1.8.2 Lösung

Eine mögliche zusätzliche Absicherung kann der schon erwähnte **Verzeichnisschutz** sein. Weitere Möglichkeiten sind:

* Ausschließen der Auslieferung über den Webserver (HTTP-Statuscode 404)
* Auslieferung der Bereiche nur über bestimmte Erkennungsmerkmale (speziell angepasster User-Agent, etc.)

#### 1.8.3 Beispiel via `.htaccess`

##### 1.8.3.1 Create a `.htpasswd` file:

```bash
user$ htpasswd -cb /var/www/path/to/web/root/current/web/.htpasswd username password
```

##### 1.8.3.2 The `.htaccess` file

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
    RedirectMatch 404 /log
    RedirectMatch 404 /revision-infos
</If>
```

#### 1.8.4 Hinweise

In Bearbeitung...

### 1.10 Anderes

* X-Powered-By
* ServerSignature
* Header append X-Content-Type-Options "nosniff"
* Header append X-XSS-Protection "1; mode=block"
* Header append Strict-Transport-Security "max-age=16070400; includeSubDomains"
* Header edit Set-Cookie ^(.*)$ $1;Secure env=is_live

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
* [.htaccess boilerplate (apache)](https://github.com/h5bp/html5-boilerplate/blob/master/dist/.htaccess)
* [Header mit TYPO3](https://jweiland.net/index.php?id=1165&L=1)
* [.htaccess Beispiele](https://www.askapache.com/htaccess/htaccess-fresh/)

## C. Tools

* [https://securityheaders.com](https://securityheaders.com)

## D. Fußnoten

* <sup>1</sup> = z.B. der Apache Webserver mit entsprechend aktivierten Modulen (z.B. [mod_rewrite](https://httpd.apache.org/docs/current/mod/mod_rewrite.html) oder [mod_headers](http://httpd.apache.org/docs/current/mod/mod_headers.html))

## E. Autoren

* Björn Hempel <bjoern@hempel.li> - _Erste Arbeiten_ - [https://github.com/bjoern-hempel](https://github.com/bjoern-hempel)

## F. Lizenz

Dieses Tutorial steht unter der MIT-Lizenz - siehe die Datei [LICENSE.md](/LICENSE.md) für weitere Informationen.
