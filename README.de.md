# Sicherheit von Webanwendungen

Eine Anleitung um Web-Anwendungen abzusichern.

## 1. Sicherheitskonzepte via Headereinstellungen

Headereinstellungen können je nach verwendeten Webserver via seinen Webservereinstellungen, via Konfigurationsdatei `.htaccess`-Datei (NCSA kompatible Webserver<sup>1</sup>) oder direkt in der Webanwendung selbst vorgenommen werden (via Scriptsprache wie PHP, Ruby, Python, etc.). 

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

Durch [XSS](https://de.wikipedia.org/wiki/Cross-Site-Scripting)<sup>Wiki</sup> oder auch webseitenübergreifendem Skripting ist es möglich ungewollt Schadcode auf der Webseite auszuführen.

#### 1.2.1 Problem

Der ungewollt importierte und ausgespielte Schadcode ermöglicht es z.B. Session-Daten zu entwenden ([Session Hijacking](https://de.wikipedia.org/wiki/Session_Hijacking)<sup>Wiki</sup>). Ungewollter Fremdcode kann überall dort in das Webprojekt gelangen, wo Daten in das Projekt zur Auswertung importiert oder zur Datenspeicherung übertragen werden:

* Suchformular
* Eingabemasken (Kommentare, Gästebuch, etc.)
* Datenimporte (API-Anbindungen, Parsing, Datenbankimporte fremder Quellen, etc.)

Werden diese kompromitierten Daten ungeprüft an den Client (Browser) gesendet, können diese im ungünstigsten Fall zur Ausführung gebracht werden. Generell ist es eine gute Idee den Import zu überwachen und zu filtern. Durch die unzählige Anzahl an Importmöglichkeiten, die Möglichkeit den schadhaften Code in unzähligen Variante zu verschleiern, sollte man zusätzlich die Ausführungsebenen des Scriptings einschränken:

* Inline-Scripting verbieten und in externe Dateien auslagern (die Unterscheidung von eigenem Code zu schadhaften Code ist beim Inline-Scripting besonders schwierig)
* Nur vertrauenswürdige Quellen beim Nachladen der Script-Dateien erlauben

#### 1.2.2 Lösung (Content Security Policy)

Ein weiterer Lösungsansatz neben dem Filtern der importierten Dateien ist die Einschränkung der Ausführungsebenen. Hierfür bieten die Browser den [Content Security Policy](https://de.wikipedia.org/wiki/Content_Security_Policy)<sup>Wiki</sup>-Ansatz. Dieser gewünschten Regeln werden über die HTTP-Header ausgespielt.

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
* [htaccess boilerplate (apache)](https://github.com/h5bp/html5-boilerplate/blob/master/dist/.htaccess)

## C. Fußnoten

* <sup>1</sup> = z.B. der Apache Webserver mit entsprechend aktivierten Modulen (z.B. [mod_rewrite](https://httpd.apache.org/docs/current/mod/mod_rewrite.html) oder [mod_headers](http://httpd.apache.org/docs/current/mod/mod_headers.html))

## D. Autoren

* Björn Hempel <bjoern@hempel.li> - _Erste Arbeiten_ - [https://github.com/bjoern-hempel](https://github.com/bjoern-hempel)

## E. Lizenz

Dieses Tutorial steht unter der MIT-Lizenz - siehe die Datei [LICENSE.md](/LICENSE.md) für weitere Informationen.
