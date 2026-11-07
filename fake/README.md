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

4. Volitelně vydává vlastní RS256 JWT (`/auth/token`), aby šel lokálně testovat
   i `auth_shield` bez reálného tenanta.

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
| `GET` | `/fake-health` | Health check (`ok`, `target_server`, `users_count`) |
| `GET` | `/.well-known/openid-configuration` | Minimální discovery dokument |
| `GET` | `/.well-known/jwks.json` | Veřejný RSA klíč pro ověření JWT |
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
| `JWT_PROXY_BEARER` | `false` | Posílat token v `Authorization` |
| `JWT_PROXY_IDENTITY_HEADER` | `false` | Posílat token v `x-easy-entra-jwt` |

`JWT_ISSUER` a `JWT_DISCOVERY_BASE_URL` musí být absolutní HTTP(S) URL.
Klíč se při prvním startu vygeneruje (3072bit RSA) a dál se reusuje; díky tomu
tokeny přežijí restart kontejneru, pokud je klíč na perzistentním volume.

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
