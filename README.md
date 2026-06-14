# easy_entra_id

`easy_entra_id` je hlavní Docker image pro produkční / integrační variantu služby.

Image je publikována do GitHub Container Registry:

```text
ghcr.io/hrbolek/easy_entra_id
```

## Docker image

Hlavní image se sestavuje z Dockerfile v rootu repozitáře:

```text
.
├── Dockerfile
└── ...
```

Build context je root repozitáře:

```text
.
```

## Dostupné tagy

Workflow publikuje několik typů tagů.

### Defaultní tagy

Při pushi do větve `main`:

```text
ghcr.io/hrbolek/easy_entra_id:latest
ghcr.io/hrbolek/easy_entra_id:main
ghcr.io/hrbolek/easy_entra_id:sha-<commit>
```

Při vytvoření release tagu, například `v0.1.0`:

```text
ghcr.io/hrbolek/easy_entra_id:v0.1.0
```

### Tagy podle Python base image

Pokud workflow sestavuje více Python variant, vznikají také tagy ve tvaru:

```text
<version>-py<python-version>-<debian-suite>
```

Příklady:

```text
ghcr.io/hrbolek/easy_entra_id:v0.1.0-py3.13-bookworm
ghcr.io/hrbolek/easy_entra_id:v0.1.0-py3.14-bookworm
ghcr.io/hrbolek/easy_entra_id:v0.1.0-py3.14-trixie
```

Pro větev `main`:

```text
ghcr.io/hrbolek/easy_entra_id:main-py3.13-bookworm
ghcr.io/hrbolek/easy_entra_id:main-py3.14-bookworm
```

Pro konkrétní commit:

```text
ghcr.io/hrbolek/easy_entra_id:sha-abcdef0-py3.13-bookworm
```

## Doporučené použití

Pro stabilní nasazení používej verzovaný tag:

```bash
docker pull ghcr.io/hrbolek/easy_entra_id:v0.1.0
```

Pro vývoj / testování lze použít:

```bash
docker pull ghcr.io/hrbolek/easy_entra_id:main
```

nebo:

```bash
docker pull ghcr.io/hrbolek/easy_entra_id:latest
```

Pokud potřebuješ konkrétní Python runtime:

```bash
docker pull ghcr.io/hrbolek/easy_entra_id:v0.1.0-py3.14-bookworm
```

## Spuštění

```bash
docker run --rm -p 8000:8000 ghcr.io/hrbolek/easy_entra_id:latest
```

Aplikace je pak dostupná například na:

```text
http://localhost:8000
```

## Lokální build

```bash
docker build -t easy-entra-id .
```

Spuštění lokálně sestavené image:

```bash
docker run --rm -p 8000:8000 easy-entra-id
```

## Lokální build s konkrétní Python base image

Dockerfile může podporovat build argument `PYTHON_IMAGE`:

```dockerfile
ARG PYTHON_IMAGE=python:3.13-slim-bookworm
FROM ${PYTHON_IMAGE}
```

Pak lze sestavit například:

```bash
docker build \
  --build-arg PYTHON_IMAGE=python:3.14-slim-bookworm \
  -t easy-entra-id:py3.14-bookworm \
  .
```

## Publikace

Publikaci řeší GitHub Actions workflow.

Workflow se spouští při:

- pushi do větve `main`,
- pushi gitu s tagem ve tvaru `v*.*.*`,
- ručním spuštění přes `workflow_dispatch`.

Příklad vytvoření release tagu:

```bash
git tag -a v0.1.0 -m "Release v0.1.0"
git push origin v0.1.0
```

Po doběhnutí workflow vznikne mimo jiné:

```text
ghcr.io/hrbolek/easy_entra_id:v0.1.0
```

---

# easy_entra_id_fake

`easy_entra_id_fake` je vývojová / debug varianta služby. Slouží jako náhrada nebo simulace autentizační vrstvy pro lokální vývoj a testování.

Image je publikována do GitHub Container Registry jako samostatná image:

```text
ghcr.io/hrbolek/easy_entra_id-fake
```

## Docker image

Fake image se sestavuje z Dockerfile v adresáři `fake`:

```text
.
├── fake
│   ├── Dockerfile
│   └── ...
└── ...
```

Build context je adresář:

```text
./fake
```

Dockerfile:

```text
./fake/Dockerfile
```

## Dostupné tagy

Workflow publikuje stejné typy tagů jako pro hlavní image.

### Defaultní tagy

Při pushi do větve `main`:

```text
ghcr.io/hrbolek/easy_entra_id-fake:latest
ghcr.io/hrbolek/easy_entra_id-fake:main
ghcr.io/hrbolek/easy_entra_id-fake:sha-<commit>
```

Při vytvoření release tagu, například `v0.1.0`:

```text
ghcr.io/hrbolek/easy_entra_id-fake:v0.1.0
```

### Tagy podle Python base image

Pokud workflow sestavuje více Python variant, vznikají také tagy:

```text
ghcr.io/hrbolek/easy_entra_id-fake:v0.1.0-py3.13-bookworm
ghcr.io/hrbolek/easy_entra_id-fake:v0.1.0-py3.14-bookworm
ghcr.io/hrbolek/easy_entra_id-fake:v0.1.0-py3.14-trixie
```

Pro větev `main`:

```text
ghcr.io/hrbolek/easy_entra_id-fake:main-py3.13-bookworm
ghcr.io/hrbolek/easy_entra_id-fake:main-py3.14-bookworm
```

Pro konkrétní commit:

```text
ghcr.io/hrbolek/easy_entra_id-fake:sha-abcdef0-py3.13-bookworm
```

## Doporučené použití

Pro běžný vývoj:

```bash
docker pull ghcr.io/hrbolek/easy_entra_id-fake:latest
```

nebo konkrétní release:

```bash
docker pull ghcr.io/hrbolek/easy_entra_id-fake:v0.1.0
```

Spuštění:

```bash
docker run --rm -p 8000:8000 ghcr.io/hrbolek/easy_entra_id-fake:latest
```

## Lokální build

```bash
docker build -t easy-entra-id-fake ./fake
```

Spuštění lokálně sestavené image:

```bash
docker run --rm -p 8000:8000 easy-entra-id-fake
```

## Lokální build s konkrétní Python base image

Pokud `fake/Dockerfile` podporuje build argument `PYTHON_IMAGE`:

```dockerfile
ARG PYTHON_IMAGE=python:3.13-slim-bookworm
FROM ${PYTHON_IMAGE}
```

lze sestavit například:

```bash
docker build \
  --build-arg PYTHON_IMAGE=python:3.14-slim-bookworm \
  -t easy-entra-id-fake:py3.14-bookworm \
  ./fake
```

## Publikace

Publikaci řeší stejné GitHub Actions workflow jako pro hlavní image.

Workflow sestavuje dvě image:

```text
ghcr.io/hrbolek/easy_entra_id
ghcr.io/hrbolek/easy_entra_id-fake
```

První image používá:

```text
context: .
dockerfile: ./Dockerfile
```

Druhá image používá:

```text
context: ./fake
dockerfile: ./fake/Dockerfile
```

## Doporučené tagovací schéma

Pro produkční / stabilní release:

```text
v0.1.0
v0.2.0
v1.0.0
```

Pro Python varianty:

```text
v0.1.0-py3.13-bookworm
v0.1.0-py3.14-bookworm
v0.1.0-py3.14-trixie
```

Pro vývojovou větev:

```text
main
main-py3.13-bookworm
main-py3.14-bookworm
```

Pro přesné dohledání buildu:

```text
sha-<commit>
sha-<commit>-py3.13-bookworm
```

## Poznámka k Python verzím

Doporučená stabilní výchozí varianta:

```text
python:3.13-slim-bookworm
```

Alternativně lze testovat:

```text
python:3.14-slim-bookworm
python:3.14-slim-trixie
```

Experimentální / pre-release Python varianty by neměly dostávat tagy `latest`, `main` ani čisté release tagy typu `v0.1.0`. Měly by být publikované pouze s explicitním suffixem, například:

```text
v0.1.0-py3.15-b2-trixie
```
