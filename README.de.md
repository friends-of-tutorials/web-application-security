# Sicherheit von Webanwendungen

Eine Anleitung um Web-Anwendungen abzusichern.

## 1. Sicherheitskonzepte via Headereinstellungen

Headereinstellungen können je nach verwendeten Webserver via Webservereinstellungen, via `.htaccess`-Datei (Apache) oder direkt in der Webanwendung selbst vorgenommen werden (via Scriptsprache wie PHP, Ruby, Python, etc.). 

### 1.1 Vorbetrachtungen

#### 1.1.1 via `.htaccess`

Nachfolgend Einstellungen in der `.htaccess`, um verschiedene Inhaltsaufrufe zu erkennen. Erkannt wird der Aufruf des Backends TYPO3 (`/typo3/`), von Web-Assets (Bilder, etc.) und der Rest (alles außer TYPO3 und Web-Assets):

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

Mit Hilfe der zur Verfügung stehenden "Variablen" `content-type-default`, `content-type-assets` und `content-type-typo3` werden dann in den nachfolgenden Beispielen entsprechend die Header gesetzt.

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

## C. Autoren

* Björn Hempel <bjoern@hempel.li> - _Erste Arbeiten_ - [https://github.com/bjoern-hempel](https://github.com/bjoern-hempel)

## D. Lizenz

Dieses Tutorial steht unter der MIT-Lizenz - siehe die Datei [LICENSE.md](/LICENSE.md) für weitere Informationen.
