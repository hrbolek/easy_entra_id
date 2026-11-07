# Fake Easy Entra ID

Vývojová náhrada produkčního `easy_entra_id`. Běží jako jednoduchá reverzní
proxy před docker stackem a místo Microsoft Entra ID loginu nabídne výběr
z pevně daných fake uživatelů.

Cílem je, aby aplikace za fake vrstvou dostávala **stejný kontrakt hlaviček**
jako v produkci za `easy_entra_id` (App Service EasyAuth), takže se nemusí
v kódu nijak rozlišovat lokální a produkční prostředí.

> ⚠️ Toto je pouze debug/development nástroj. Nikdy ho nepoužívej jako
> produkční autentizační vrstvu.

## Co fake dělá

1. Zobrazí `/login` se seznamem uživatelů z `fake_users.json`.
2. Po výběru uživatele založí session v paměti procesu a do cookie
   (`FAKE_AUTH_COOKIE`) uloží pouze náhodný opaque token — žádný e-mail ani claimy.
3. Každý další požadavek proxyuje na `TARGET_SERVER` a doplní hlavičky:

```text
x-ms-client-principal        base64(JSON) ve formátu EasyAuth
x-ms-client-principal-id     oid uživatele
x-ms-client-principal-name   e-mail uživatele
x-fake-easy-entra-id         true
```

Příchozí `x-ms-client-principal*` hlavičky se před proxyováním zahazují, aby
klient nemohl podstrčit cizí identitu.

4. Vydává vlastní RS256 JWT a publikuje JWKS, takže funguje jako plnohodnotný
   vydavatel identity pro `auth_shield` (viz [Spolupráce s auth_shield](#spolupráce-s-auth_shield)).

## Soubory

| Soubor | Význam |
| --- | --- |
| `main.py` | FastAPI aplikace: login, session, JWT a proxy |
| `index.html` | React UI pro výběr uživatele (data se vkládají jako JSON) |
| `fake_users.json` | Seznam fake uživatelů |
| `Dockerfile` | Image `ghcr.io/hrbolek/easy_entra_id-fake` |
| `requirements.txt` | fastapi, uvicorn, httpx, python-multipart, PyJWT |

## Endpointy

| Metoda | Cesta | Popis |
| --- | --- | --- |
| `GET` | `/login` | Výběr fake uživatele |
| `POST` | `/login`, `/fake-select-user` | Přihlášení jako zvolený uživatel |
| `GET` | `/fake-logout` | Zrušení session a smazání cookie |
| `GET` | `/fake-users` | Seznam uživatelů jako JSON |
| `GET` | `/fake-health` | Health check + `issuer`, `audience`, `jwks_uri`, `key_id` |
| `GET` | `/.well-known/openid-configuration` | Minimální discovery dokument |
| `GET` | `/.well-known/jwks.json` | Veřejný RSA klíč pro ověření JWT |
| `POST` | `/auth/login` | Strojový login (e-mail + heslo) → JWT v těle |
| `POST` | `/auth/token` | Vydání JWT pro aktuální fake session |
| `GET` | `/auth/verify` | Ověření `Authorization: Bearer <jwt>` |
| `*` | `/{path}` | Proxy na `TARGET_SERVER` |

Nepřihlášený `GET`/`HEAD` je přesměrován na `/login?next=…`, ostatní metody
dostanou `401`.

## Konfigurace

### Základní

| Proměnná | Default | Význam |
| --- | --- | --- |
| `TARGET_SERVER` | `http://localhost:8080` | Kam se proxyuje |
| `APP_TITLE` | `Fake Easy Entra ID` | Titulek v UI |
| `FAKE_USERS_JSON` | `<adresář main.py>/fake_users.json` | Cesta k uživatelům |
| `FAKE_LOGIN_HTML_PATH` | `<adresář main.py>/index.html` | Cesta k šabloně |
| `FAKE_AUTH_COOKIE` | `fake_easy_entra_user` | Název session cookie |
| `FAKE_ALLOW_HEADER_IMPERSONATION` | `false` | Povolí `x-fake-user` hlavičku |
| `FAKE_ENABLE_MACHINE_LOGIN` | `false` | Zapne `POST /auth/login` |
| `FAKE_PASS_THROUGH_PREFIXES` | `/login,/fake-select-user,/fake-logout,/fake-users,/fake-health` | Cesty, které se neproxyují |
| `HTTP_TIMEOUT_SECONDS` | `30` | Timeout na upstream |

### JWT (pro `auth_shield`)

| Proměnná | Default | Význam |
| --- | --- | --- |
| `JWT_ISSUER` | `https://auth.dev.company.cz` | Logický issuer v tokenech |
| `JWT_AUDIENCE` | `internal-api` | Audience tokenu |
| `JWT_DISCOVERY_BASE_URL` | `http://easy-entra-fake:8000` | Základ pro `jwks_uri` |
| `JWT_PRIVATE_KEY_FILE` | `/tmp/easy-entra-id-fake/jwt-private.pem` | Perzistentní RSA klíč |
| `JWT_KEY_ID` | `fake-shield-dev-1` | `kid` v hlavičce tokenu i JWKS |
| `JWT_TOKEN_LIFETIME_SECONDS` | `900` | Platnost tokenu (1–86400) |
| `JWT_PROXY_MODE` | `bearer` | Jak předat token upstreamu: `bearer`, `header`, `both`, `none` |
| `JWT_PROXY_BEARER` | `false` | Legacy; OR s `JWT_PROXY_MODE` |
| `JWT_PROXY_IDENTITY_HEADER` | `false` | Legacy; OR s `JWT_PROXY_MODE` |

`JWT_ISSUER` a `JWT_DISCOVERY_BASE_URL` musí být absolutní HTTP(S) URL bez
trailing slash — `iss` a `jwks_uri` se na straně konzumenta porovnávají
přesnou shodou.
Klíč se při prvním startu vygeneruje (3072bit RSA) a dál se reusuje; díky tomu
tokeny přežijí restart kontejneru, pokud je klíč na perzistentním volume.

## Spolupráce s auth_shield

`auth_shield` ověřuje příchozí JWT proti registrovaným vydavatelům. Fake je
jeden z nich, takže musí splnit stejný kontrakt jako reálné Entra ID.

### Co fake poskytuje

| Vlastnost | Zdroj | Příklad |
| --- | --- | --- |
| `issuer` | `JWT_ISSUER` | `https://auth.dev.company.cz` |
| `jwks_uri` | `JWT_DISCOVERY_BASE_URL` + `/.well-known/jwks.json` | `http://fake_easy_entra_id:8000/.well-known/jwks.json` |
| `audience` | `JWT_AUDIENCE` | `internal-api` |
| podpis | RS256, `kid` = `JWT_KEY_ID` | `fake-shield-dev-1` |

`/fake-health` tyto hodnoty vrací, takže se nemusí opisovat ručně:

```bash
curl -s http://localhost:8088/fake-health | jq
```

### Jak to zapadne do `ISSUERS_JSON`

```json
{
  "fake": {
    "issuer": "https://auth.dev.company.cz",
    "jwks_uri": "http://fake_easy_entra_id:8000/.well-known/jwks.json",
    "audience": ["internal-api"]
  }
}
```

`issuer` musí přesně odpovídat claimu `iss` v tokenu — proto fake odmítne
start s trailing slash v `JWT_ISSUER`.

### Předání tokenu upstreamu

`auth_shield` čte token z `Authorization: Bearer`. Fake proto standardně
posílá token tam (`JWT_PROXY_MODE=bearer`). Volitelně lze přidat i hlavičku:

| `JWT_PROXY_MODE` | `Authorization` | `x-easy-entra-jwt` |
| --- | --- | --- |
| `bearer` (default) | ano | ne |
| `header` | ne | ano |
| `both` | ano | ano |
| `none` | ne | ne |

V režimu `none` fake posílá jen EasyAuth principal hlavičky, takže s
`auth_shield` (který vyžaduje JWT) fungovat nebude — hodí se jen pro
aplikace, které čtou `x-ms-client-principal`.

### Bezpečnostní chování

- Klientský `Authorization` se **vždy zahodí** a nahradí tokenem pro
  zvoleného uživatele. Klient nemůže podstrčit cizí token.
- Klientský `x-easy-entra-jwt` se také zahodí.
- Příchozí `x-ms-client-principal*` hlavičky se zahazují a nahrazují.
- Jeden request = jeden token, který jde do obou carrierů, pokud jsou
  zapnuté oba.

### Celý řetěz

```text
client
  -> fake_easy_entra_id        (login, výběr uživatele)
  -> auth_shield /{app}/{path} (ověří JWT, vydá Shield JWT)
  -> backend app               (vidí jen Shield JWT)
  -> auth_shield /{path}       (vymění Shield JWT za reálný)
  -> skryté API                (vidí reálný JWT)
```

V `docker-compose.fake-shield.yaml` je to nastavené takto:

```yaml
fake_easy_entra_id:
  environment:
    TARGET_SERVER: http://auth_shield:8000/whoami
    JWT_ISSUER: https://auth.dev.company.cz
    JWT_AUDIENCE: internal-api
    JWT_DISCOVERY_BASE_URL: http://fake_easy_entra_id:8000
    JWT_PROXY_MODE: bearer

auth_shield:
  environment:
    ISSUERS_JSON: >
      {"fake": {"issuer": "https://auth.dev.company.cz",
                "jwks_uri": "http://fake_easy_entra_id:8000/.well-known/jwks.json",
                "audience": ["internal-api"]}}
    SHIELD_ISSUER: https://auth-shield.dev.internal
```

### Časté chyby

| Problém | Příčina |
| --- | --- |
| Shield vrací 401 `Untrusted token issuer` | `issuer` v `ISSUERS_JSON` neodpovídá `JWT_ISSUER` |
| Shield vrací 401 `Unknown signing key` | `jwks_uri` míří jinam, nebo se změnil `JWT_KEY_ID` |
| Shield vrací 401 `Invalid token` | jiná `audience`, nebo expirovaný token |
| Shield vrací 500 `Unknown authentication contract` | fake neposílá token (`JWT_PROXY_MODE=none`) |
| Token projde, ale bez rolí | `roles` chybí v `fake_users.json` |

## Strojový login

Pro klienty, kteří neumí pracovat s cookie (skripty, CI, testy), existuje
`POST /auth/login`. Vrací JWT přímo v těle odpovědi, takže celý login je
jeden request.

Endpoint je **vypnutý**, dokud není nastaveno `FAKE_ENABLE_MACHINE_LOGIN=true`.
Bez toho vrací `404`.

### Request

```bash
curl -s -X POST http://localhost:8088/auth/login \
  -H 'content-type: application/json' \
  -d '{"email":"john.newbie@world.com","password":"john.newbie@world.com"}'
```

Podporovaný je i form-encoded (`curl -d` bez `content-type`).

### Response 200

```json
{
  "access_token": "<JWT>",
  "token_type": "Bearer",
  "expires_in": 900,
  "user": {
    "oid": "97c80a87-8206-4845-98df-2af25ed33916",
    "email": "john.newbie@world.com",
    "name": "John Newbie",
    "roles": ["student", "user"]
  }
}
```

Cookie se **nenastavuje** — token je jediný výstup.

### Chybové stavy

| Stav | Kdy |
| --- | --- |
| `404` | `FAKE_ENABLE_MACHINE_LOGIN` není `true` |
| `400` | chybí `email` nebo `password` |
| `401` | neznámý e-mail **nebo** špatné heslo (stejná odpověď) |

### Ověřování hesla

Pokud má uživatel v `fake_users.json` pole `password`, porovnává se s ním.
Jinak platí dev konvence **`password == email`**, takže endpoint funguje
i bez úprav datového souboru.

```json
{
  "email": "john.newbie@world.com",
  "password": "tajne-heslo",
  "roles": ["student", "user"]
}
```

Porovnání je konstantní v čase (`secrets.compare_digest`).

### Použití tokenu

Token je **reálný JWT od fake**, takže se posílá na `auth_shield`, ne na
backend. Cesta musí začínat `app_id` z `APPLICATIONS_JSON`.

```bash
TOKEN=$(curl -s -X POST http://localhost:8088/auth/login \
  -H 'content-type: application/json' \
  -d '{"email":"john.newbie@world.com","password":"john.newbie@world.com"}' \
  | jq -r .access_token)

curl -H "Authorization: Bearer $TOKEN" \
     http://localhost:8090/whoami/api/x
```

Shield token ověří, uloží ho do vaultu a backendu předá vlastní Shield JWT.
Stroj tedy Shield JWT nikdy nevidí a k API se dostane jen přes Shield.

## Formát `fake_users.json`

```json
[
  {
    "id": "97c80a87-8206-4845-98df-2af25ed33916",
    "oid": "97c80a87-8206-4845-98df-2af25ed33916",
    "email": "john.newbie@world.com",
    "name": "John Newbie",
    "roles": ["student", "user"],
    "scopes": ["read:profile", "read:messages"]
  }
]
```

Povinný není nic — chybějící `oid` se dopočítá z `id`/`email`, `name`
z `email`, `tenant_id` je `fake-tenant`. `roles` lze zadat i jako
čárkou oddělený string. Uživatele lze dohledat podle `id`, `oid`, `email`,
`preferred_username` nebo `unique_name`.

## Spuštění

### Docker Compose

```bash
docker compose -f docker-compose.fake.yaml up --build
```

- fake: <http://localhost:8088>
- whoami upstream: <http://localhost:8080>

Varianty s `auth_shield`:

```bash
docker compose -f docker-compose.fake-shield.yaml up --build
docker compose -f docker-compose.fake-shield.ext.yaml up --build
```

### Lokálně bez Dockeru

```bash
pip install -r fake/requirements.txt
uvicorn main:app --host 0.0.0.0 --port 8000 --app-dir fake
```

### Z publikované image

```bash
docker run --rm -p 8000:8000 \
  -e TARGET_SERVER=http://host.docker.internal:8080 \
  ghcr.io/hrbolek/easy_entra_id-fake:latest
```

## Rychlé ověření

```bash
# health
curl http://localhost:8088/fake-health

# seznam uživatelů
curl http://localhost:8088/fake-users

# přihlášení (cookie si ulož do souboru)
curl -c cookies.txt -X POST http://localhost:8088/login \
  -d "user=john.newbie@world.com" -d "next=/"

# proxy s identitou
curl -b cookies.txt http://localhost:8088/

# JWT
curl -b cookies.txt -X POST http://localhost:8088/auth/token
curl -H "Authorization: Bearer <token>" http://localhost:8088/auth/verify
```

## Omezení

- Session je jen v paměti procesu → po restartu se uživatel odhlásí.
  Podpisový klíč se ukládá do `JWT_PRIVATE_KEY_FILE`, takže tokeny přežijí
  restart jen tehdy, když je tento soubor na perzistentním volume.
- Jeden proces / worker; sdílený stav mezi replikami neexistuje.
- Proxy nepodporuje WebSocket.
- Nejde o plnohodnotné OIDC — `/auth/token` není standardní token endpoint
  s granty, vydává token pouze pro existující fake session.
