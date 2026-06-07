# Vulnerapp

-- A Vulnerable Sample Spring Boot Application

This application uses a relatively modern stack but is still vulnerable to a set of attacks.
Featuring:

- [XSS](https://portswigger.net/web-security/cross-site-scripting)
- [SQLi](https://portswigger.net/web-security/sql-injection)
- [CSRF](https://portswigger.net/web-security/csrf)
- [SSRF](https://portswigger.net/web-security/ssrf)
- Fake Logins
- Info Exposure
- Plain Passwords
- ...

Either start it via IDE or start it with the following command (it will hang). Then visit http://localhost:8080/

```console
./gradlew bootRun
```

## Sicherheitsreflexion

### Implementierte Sicherheitsmechanismen

Die Authentifizierung läuft über Sessions mit Spring Security, das ist gut, weil dadurch wird das Login nicht mehr einfach im Browser gespeichert. Und es gibt Rollen wie `USER` und `ADMIN`, damit normale User nicht auf Admin-Funktionen zugreifen können.

CSRF-Schutz ist auch aktiv, das Frontend schickt bei POST/DELETE Requests den `XSRF-TOKEN` als Header mit. Eine fremde Webseite kann diesen Token nicht lesen, darum kann sie solche Requests nicht einfach nachmachen.

Passwörter werden mit BCrypt gehasht und es gibt einfache Passwortregeln und das ist wichtig, weil Passwörter nicht im Klartext in der Datenbank liegen sollen.

XSS wurde im Frontend gefixt, indem Blog-Inhalte als Text gerendert werden und nicht als HTML. SQL Injection wurde verhindert, indem Repository-Methoden/JPA verwendet werden statt SQL selber zusammenzubauen.

Es  gibt auch Inputvalidierung, Security-Headers, weniger genaue Fehlermeldungen und ein Limit auf falsche Loginversuche.

Die wichtigsten Sachen habe ich mit WebTestClient getestet.

### Weitere sinnvolle Sicherheitsmechanismen

Noch sinnvoll wäre ein besseres Rate Limiting, nicht nur für Login sondern auch für andere Endpunkte. In Produktion würde man das eher mit Redis oder einem Reverse Proxy machen.

Für Admins wäre auch MFA sinnvoll, zB. mit TOTP, weil Admin-Accounts mehr Schaden machen können.

Audit Logging wäre auch gut. Man könnte Logins, Loginfehler und Admin-Aktionen loggen, aber natürlich ohne Passwörter oder Tokens.

In einer echten Umgebung sollten Secrets auch richtig verwaltet werden, also über Env vars oder Secret Management. Der Remember-Me-Key müsste dort zB. ein langer zufälliger Wert sein.

### Schwierigkeiten und Probleme bei der Implementierung

Die grösste Schwierigkeit war es Sicherheit einzubauen, ohne die App komplett umzubauen, da das Frontend Vanilla-JS bleibensollte und die API ähnlich weiter funktionieren sollte.

CSRF war das Schwierigste weil nach einem Logout war der alte Token ungültig, und ein direkter neuer Login schlug im Browser mit `403` fehl. Die Lösung war dann ein eigener CSRF endpoint, den das Frontend vor Login und nach Logout aurift.

Dann war eine weitere Sache auch die Balance bei den Fehlermeldungen. Aus Sicherheitssicht sollen Fehler wenig verraten, aber aus Entwicklersicht sind genaue Fehler aber praktisch. Deshalb habe ich Details serverseitig behalten und der Client bekommt nur normale Antworten.


### Aufwand und Ertrag von Sicherheitsmassnahmen

Manche Sicherheitsmassnahmen bringen viel für wenig Aufwand, also Passwort-Hashing, Rollenprüfung, Security-Headers und weniger genaue Fehlermeldungen sind mit Spring Security/Spring Boot relativ gut machbar und bringen viel.

CSRF, Sessions und Remember-Me waren aufwändiger, weil Backend, Cookies und Frontend miteinander kommumizieren müssen.

Eine Demo-App braucht jetzt nicht die gleiche Sicherheit wie eine Bank-App,  aber Basics wie Authentifizierung, Rollen, Passwort-Hashing, CSRF und XSS-Schutz sollten fast immer drin sein.
