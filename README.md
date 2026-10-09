# Kimi Swarm

Plugin de Kimi Code para **delegación con personas y multi-modelo**: reparte una tarea entre
subagentes especializados (`worker`, `review`, `security`, `architect`, `audit-hunter`,
`audit-verifier`) que pueden correr en un modelo distinto del orquestador. Incluye el workflow
completo de auditoría de seguridad de Cloudflare, adaptado a Kimi.

---

## Índice

- [Cómo encaja en Kimi Code](#cómo-encaja-en-kimi-code)
- [Instalación](#instalación)
- [Setup del pool de modelos](#setup-del-pool-de-modelos)
- [Uso](#uso)
- [Personas incluidas](#personas-incluidas)
- [Auditoría de seguridad completa](#auditoría-de-seguridad-completa)
- [Validadores en Python (sin Node.js)](#validadores-en-python-sin-nodejs)
- [Sandbox de ejecución](#sandbox-de-ejecución)
- [Automatización y no-interactividad](#automatización-y-no-interactividad)
- [Verificación](#verificación)
- [El límite que define el diseño](#el-límite-que-define-el-diseño)
- [Roadmap](#roadmap)

---

## Cómo encaja en Kimi Code

| Pieza | Dónde vive | Qué aporta |
| --- | --- | --- |
| Delegación | tools nativas `Agent` y `AgentSwarm` | Subagentes con contexto aislado, en paralelo y en background |
| Personas | `agents/*.md` de este plugin | worker, review, security, architect, audit-hunter, audit-verifier |
| Modelo distinto | `[secondary_model]` en `config.toml` | Pool de modelos candidatos; el orquestador elige uno por spawn |

La delegación y las personas ya existen en Kimi; el modelo por subagente se configura aparte. Este
plugin empaqueta las personas, la matriz de ruteo y los comandos, y te guía para configurar el pool.

## Instalación

En Kimi Code:

```
/plugins install /ruta/a/kimi-swarm
```

Desde GitHub (repo **público**):

```
/plugins install https://github.com/elmaxid/kimi-swarm
```

> **Repos privados**: el instalador baja por `github.com`/`codeload` **sin autenticación**, así que
> `/plugins install <url>` falla contra un repo privado. Para un repo privado: instalá desde el
> directorio local (funciona), o usá la [instalación headless](#instalación-headless).

Luego `/reload` o una sesión nueva para activarlo.

### Instalación headless

Los plugins se registran en `$KIMI_CODE_HOME/plugins/installed.json` (schema `InstalledFile v1`) con
la copia ejecutable en `plugins/managed/<id>/`. Se puede instalar sin la TUI:

```bash
KIMI_HOME="${KIMI_CODE_HOME:-$HOME/.kimi-code}"
cp -r /ruta/a/kimi-swarm "$KIMI_HOME/plugins/managed/kimi-swarm"
rm -rf "$KIMI_HOME/plugins/managed/kimi-swarm/.git"
mkdir -p "$KIMI_HOME/plugins"
cat > "$KIMI_HOME/plugins/installed.json" <<EOF
{ "version": 1, "plugins": [ { "id": "kimi-swarm",
  "root": "$KIMI_HOME/plugins/managed/kimi-swarm",
  "source": "local-path", "enabled": true,
  "installedAt": "2026-01-01T00:00:00.000Z" } ] }
EOF
```

Útil para CI y para replicar el plugin en varios equipos con un script.

### Los scripts incluidos: `install-local.py` y `uninstall-local.py`

La misma instalación headless, sin `cp`/`cat` a mano, y con vuelta atrás. Solo stdlib de Python 3.

```bash
SC=<plugin-root>/scripts
python3 $SC/install-local.py                 # copia el árbol al managed y registra en installed.json
python3 $SC/install-local.py --name otro-id  # id distinto (por defecto, el del manifest)
```

`--source` por defecto es el directorio del script, así que corré siempre el del working tree. Si
editás las fuentes, volvé a correrlo y hacé `/reload`: la CLI lee `plugins/managed/`, no tu árbol.

Para deshacer, `uninstall-local.py`:

| Opción | Qué hace |
| --- | --- |
| (sin flags) | saca la entrada de `plugins/installed.json` y deja la copia gestionada en su lugar |
| `--purge` | además borra `plugins/managed/<id>/` |
| `--remove-pool` | además quita `[secondary_model]` de `config.toml`, con un backup con timestamp antes |
| `--restore-backup FILE` | en vez de `--remove-pool`: reemplaza `config.toml` por el backup que nombres |
| `--dry-run` | imprime el plan y no cambia nada |

`--remove-pool` y `--restore-backup` son mutuamente excluyentes.

Lo que garantizan (varias rondas de revisión, con cada caso reproducido antes y después):

- El id del plugin se valida (`^[A-Za-z0-9][A-Za-z0-9._-]*$`): ni una ruta absoluta ni `../..`
  llegan a un `rmtree`. Se rechaza `plugins/managed` como symlink, y el instalador se niega si el
  origen y el destino se solapan (correrlo *desde* la copia gestionada borraría el árbol que iba a
  copiar).
- `installed.json` se valida **antes** de tocar el disco: un registro roto da un error limpio en vez
  de dejar una copia huérfana junto a una entrada vieja.
- `--remove-pool` es TOML-aware: saca la tabla, sus `[secondary_model.*]` y el bloque de comentarios
  pegado arriba (más una línea en blanco cuando no hay comentario), deja los comentarios de la tabla
  siguiente con su tabla, respeta CRLF y un BOM inicial, y **compara estructuralmente contra el
  original antes de escribir**: si algo más cambiaría, no escribe nada. Si el pool existe pero con
  claves punteadas o tabla inline, falla con un error explícito.
- `--restore-backup` no baja los permisos de `config.toml`: conserva el modo previo, o `0600` si no
  había archivo.

## Setup del pool de modelos

Las personas se instalan solas, pero **el modelo no se puede fijar en la persona**: el campo `model`
del frontmatter se ignora a propósito (verificado en el código oficial). El pool vive en
`config.toml`, así que es un paso de configuración.

La forma fácil:

```
/kimi-swarm:setup
```

El comando lee tus alias de `[models]`, propone una tabla de ruteo y edita `config.toml` con backup
previo y confirmación. La forma manual:

```toml
[secondary_model]
default_model = "litellm/kimi-k2.7-code"
[secondary_model.models]
"litellm/kimi-k2.7-code"   = "Hunter/worker: implementación, refactors, exploración."
"litellm/claude-opus-5"    = "Verifier/review: razonamiento fuerte, otra familia."
"litellm/glm-5.3"          = "Security general: familia distinta para segunda opinión."
```

Reglas que fallan fuerte al arrancar la sesión:

- Cada alias del pool debe existir en `[models]`.
- `default_model` es obligatorio si hay tabla `models`, y debe ser una de sus claves.
- `force = true` exige `default_model` y no se puede combinar con `models`.

## Uso

Ruteo automático (el agente principal lee la Skill y el system prompt y elige), o explícito:

- *"Usá swarm-review con el modelo fuerte para revisar el diff actual."*
- *"Lanzá swarm-worker para implementar X y después swarm-security sobre el resultado."*
- `/kimi-swarm:review`, `/kimi-swarm:security-audit`, `/kimi-swarm:audit`

| Comando | Qué hace |
| --- | --- |
| `/kimi-swarm:setup` | Configura el pool `[secondary_model]` en `config.toml` |
| `/kimi-swarm:review` | Review de un diff/PR con `swarm-review` (modelo fuerte) |
| `/kimi-swarm:security-audit` | Auditoría ligera de un diff/alcance con `swarm-security` |
| `/kimi-swarm:audit <repo>` | Workflow completo de 6 fases sobre un repo |

### Cómo se activa la delegación

La auto-delegación **no** es automática: con solo la tabla de ruteo, el agente principal conoce las
personas pero suele hacer el trabajo inline. Una **política imperativa** en el system prompt lo
inclina de forma fiable (eso aporta `SYSTEM.md` de este plugin). Para un flujo determinista, usá los
comandos. Detalle en `skills/kimi-swarm/SKILL.md`, sección *Automatic vs forced delegation*.

## Personas incluidas

| Persona | Tools | Rol |
| --- | --- | --- |
| `swarm-worker` | lectura + escritura + Bash | Implementar, refactorizar, correr build/tests, dejar el cambio hecho |
| `swarm-review` | solo lectura | Revisar diff/PR: severidad, regresiones, edge cases |
| `swarm-architect` | lectura + web | Diseño, trade-offs, planificación |
| `swarm-security` | solo lectura | Auditoría ligera: inyección, auth, secretos, dependencias |
| `audit-hunter` | solo lectura | Fase de cacería del workflow completo |
| `audit-verifier` | solo lectura | Fase de validación/refutación, en familia de modelo distinta |

Solo `swarm-worker` escribe. El resto es read-only y no puede lanzar más subagentes.

## Auditoría de seguridad completa

Incluye vendorizado el skill [cloudflare/security-audit-skill](https://github.com/cloudflare/security-audit-skill)
(MIT) como `skills/security-audit/`, adaptado a Kimi. Corre el workflow de seis fases:
reconocimiento → cacería guiada por cobertura → validación de candidatos → salida estructurada →
verificación independiente → reporte.

```
/kimi-swarm:audit /ruta/al/repo
```

Ruteo por fase (misma persona, distinto modelo según la fase):

| Fase | Persona | Modelo |
| --- | --- | --- |
| 1. Reconocimiento | `audit-verifier` (rol `research`) | alias **rápido** |
| 2. Cacería | `audit-hunter` | alias **rápido** |
| 3. Validación de candidatos | `audit-verifier` | **fuerte, otra familia** |
| 5. Verificación de records | `audit-verifier` | **fuerte, otra familia** |

La independencia de las fases 3 y 5 es donde el multi-modelo aporta: un modelo de otra familia
intentando **refutar** el hallazgo del cazador.

### Requisitos

- **Python 3** (presente en casi cualquier Linux) o Node.js, para los validadores de las fases 4-5.
  El plugin ya incluye el [port a Python](#validadores-en-python-sin-nodejs), así que **no necesitás
  instalar Node**.
- **Sandbox** para ejecutar código del target; sin él corre **static-only** (ver abajo).
- Ejecución larga: el workflow completo tarda. Usá `profile: quick` o un `budget` para acotarlo.

### Modo static-only

Sin sandbox OS-enforced, el skill **no ejecuta** código del target: lee fuente y registra todo lo
dependiente de ejecución como `needs_validation`. Es un modo soportado por el propio skill, no una
degradación — los hallazgos estáticos siguen siendo válidos y verificables.

## Validadores en Python (sin Node.js)

Los validadores son la única parte del skill que dependía de Node. **Ya están portados a Python 3
stdlib puro** y verificados como equivalentes al original:

| Archivo | Rol |
| --- | --- |
| `skills/security-audit/_validate_common.py` | Helpers compartidos (propiedades Unicode, semántica JS de strings/números, lectura segura) |
| `skills/security-audit/validate-findings.py` | Port de `validate-findings.cjs` |
| `skills/security-audit/validate-coverage-ledger.py` | Port de `validate-coverage-ledger.cjs` |
| `skills/security-audit/test_validators.py` | Suite de conformidad (port de los `.test.cjs`) |
| `skills/security-audit/differential_test.py` | Compara Python vs Node: exit code, stdout y stderr |

Uso:

```bash
python3 <skill-dir>/validate-findings.py <output-dir>/findings.json
python3 <skill-dir>/validate-coverage-ledger.py <output-dir>/coverage-ledger.json
```

**Verificación** (con Node efímero como oráculo, sin instalarlo en el sistema):

- Conformidad Python: **65/65** casos pasan.
- Diferencial Python vs Node: **273/273** casos con salida *byte-idéntica* (exit code, stdout y
  stderr), sobre corpus con Unicode hostil, anidamiento profundo, duplicados, symlinks, FIFOs,
  entradas no-UTF-8 y >5 MiB, más fuzzing aleatorio.
- La suite Node original sigue pasando: **65/65**.

Los `.cjs` quedan como fuente de verdad y referencia; el port no los reemplaza, los complementa.
Detalle de mantenimiento en `THIRD-PARTY.md`.

**Alternativa sin mantener un port** — Node como binario único autocontenido, fuera del sistema:

```bash
curl -fsSL https://nodejs.org/dist/v22.14.0/node-v22.14.0-linux-x64.tar.xz \
  | tar -xJ --strip-components=1 -C /opt/node-portable
/opt/node-portable/bin/node --version
```

No toca `$PATH` ni el sistema; es un directorio que podés borrar.

> Nota: en algunos entornos ya hay un Node embebido (por ejemplo el que trae un IDE). El skill lo
> detecta, pero conviene no depender de una ruta ajena al proyecto.

## Sandbox de ejecución

El skill exige aislamiento OS-enforced para ejecutar código del target (builds, tests, fuzzers,
fixtures). Los requisitos que pide:

- **Sin red externa**, solo loopback aislado si hace falta tráfico local.
- **Entorno vacío** con allowlist explícita; `HOME`, temporales y cachés locales al scratch.
- **Target read-only**; el proceso solo escribe en su `scratch/`.
- **Límites** de CPU, memoria, procesos, tamaño de archivo, disco y wall-clock.

### El runner incluido: `scripts/swarm-sandbox.py`

Implementa los tres pasos del contrato del skill (ejecutar, aislar, promover) y elige el backend
solo (`systemd` si hay systemd, si no `bwrap`). Solo stdlib de Python.

```bash
SB=<plugin-root>/scripts/swarm-sandbox.py

# 1. crear la corrida y copiar el target como fuente read-only
python3 $SB create --out-dir /opt/audit-runs/proj --target /ruta/al/proyecto
# 2. ejecutar un comando del target, confinado a su scratch
python3 $SB run --out-dir /opt/audit-runs/proj --agent-id hunter-1 -c '
  cp -r "$SWARM_SOURCE" "$TMPDIR/work" && cd "$TMPDIR/work" && npm test > "$TMPDIR/out.txt" 2>&1'

# 3. promover solo el resultado mínimo, ya terminado el sandbox
python3 $SB promote --out-dir /opt/audit-runs/proj --agent-id hunter-1 --allow out.txt
```

Variables disponibles dentro del sandbox: `$SWARM_SOURCE` (copia read-only del target),
`$SWARM_WORKDIR` (cwd por defecto = el source), `$TMPDIR`/`$HOME` (el scratch escribible).

Opciones útiles:

| Opción | Para qué |
| --- | --- |
| `--workdir scratch` | arrancar directo en el scratch, en vez del source read-only |
| `--backend systemd\|bwrap` | forzar el backend en vez de autodetectar |
| `--allow a/b.txt` | promover un archivo anidado del scratch; acepta subrutas relativas |
| `--exclude NOMBRE` | omitir un directorio o archivo del source, a cualquier profundidad |
| `--no-default-excludes` | no aplicar las exclusiones de secretos por defecto |

### Exclusiones de secretos

`create` **no copia al source** los directorios que suelen tener credenciales:
`configs`, `data`, `caddy`, `.tools`, `.git`, `.env`, `host_key`, `secret.key`,
`secrets.txt`. Al terminar, escanea el source y **avisa** si quedó algún archivo con
pinta de secreto (`*.key`, `*.pem`, `*.crt`, nombres conocidos). Un proyecto que
guarda sus secretos en otro sitio se cubre con `--exclude`.

> **`.tools/` excluido tiene un costo.** Si el proyecto trae su toolchain vendorizado
> ahí (como ttunel, que usa `.tools/go/bin/go`), el sandbox no lo verá: `go version`
> puede intentar **descargar** el toolchain y, con la red bloqueada, fallar. Para
> auditar el código estático no importa; para compilar dentro del sandbox, agregá
> `--exclude configs --exclude data --exclude caddy --exclude .git`
> (o `--no-default-excludes` más excludes acotados) y dejá `.tools` adentro.

**Garantías que verifica el runner** (medidas end-to-end, no sólo afirmadas):

- Usuario efímero (no root), `$HOME` y `$TMPDIR` apuntando al scratch.
- Red externa bloqueada; `/etc`, `/usr` y el source **read-only** (un `echo > /etc/x` falla con
  “Read-only file system”, y el source queda intacto).
- Solo se escribe en el scratch.
- `promote` rechaza symlinks, rutas absolutas, `..`, rutas con `\` o `:`, archivos > 16 MiB, y no
  sobreescribe un artefacto existente.

### Trampas al usar `systemd-run` (las encontramos probando)

Si preferís invocar `systemd-run` a mano, evitá estos tres errores que cuestan tiempo:

1. **Nada de `--out-dir` bajo `/tmp` o `/var/tmp`.** `DynamicUser` monta algo sobre `/tmp` y un
   `ReadWritePaths` bajo esa ruta falla con `226/NAMESPACE`. Usá `/opt` o `/srv`. El runner lo
   rechaza de entrada.
2. **No uses `PrivateTmp=yes`** si el scratch está bajo `/tmp`: lo oculta y la escritura falla.
   El runner no lo usa y en su lugar apunta `$TMPDIR` al scratch.
3. **No uses `-p WorkingDirectory=`.** Con usuario efímero falla con `200/CHDIR`. En su lugar el
   comando hace `cd` a `$SWARM_WORKDIR` dentro del sandbox.

Y siempre `chmod 1777` al scratch: `DynamicUser` es efímero, nunca es dueño del directorio.

### Opción B — `bubblewrap` (cualquier Linux)

`bwrap` es un sandbox por namespaces, sin daemon. Se instala con `apt-get install bubblewrap`
(~1 MB). El runner lo usa si no hay systemd, o con `--backend bwrap`.

## Automatización y no-interactividad

Cada dispatch de subagente se presenta como un pedido de aprobación salvo que coincida con una regla
*allow* o estés en modo Ask-When-Needed. Para auditorías desatendidas:

- Modo permisivo: `-y` (Ask When Needed) o `--auto` (Never Ask).
- Reglas `[[permission.rules]]` con `decision = "allow"` para las tools que la auditoría ya usa
  (`Read`, `Grep`, `Glob`, `Bash` con patrón acotado). Las reglas *allow* del agente principal se
  propagan a los subagentes, así que no vuelven a preguntar.
- El tool `Agent` está permitido por defecto.
- **No** uses `-p` junto con `-y`/`--auto`: son mutuamente excluyentes.

## Verificación

Todo lo afirmado en este README se probó end-to-end en un `KIMI_CODE_HOME` aislado, sin tocar la
config real:

- Las personas `audit-hunter` / `audit-verifier` se descubren y son delegables.
- El skill `security-audit` se registra con todos sus companions y validadores.
- El workflow real arranca: crea `run-metadata.json` con `execution_policy` correcto, scope y lista
  de companions.
- El sandbox `systemd-run` se midió (tabla de arriba).
- La auto-delegación se midió en 3 escenarios (sin política / pidiendo tool / con política imperativa).
- Los validadores Python se verificaron contra el Node original: 65/65 conformidad y 273/273
  diferencial byte-idéntico (ver [Validadores en Python](#validadores-en-python-sin-nodejs)).

## El límite que define el diseño

- El modelo **no** se ata a la persona en el archivo de agente: lo elige el orquestador por spawn
  con el parámetro `model` del tool, o se fija para **todos** con `force = true`.
- `AgentSwarm` es **homogéneo**: un solo `subagent_type` y un solo `model` por enjambre. Para correr
  personas distintas en paralelo, van varias llamadas `Agent` en un mismo mensaje.
- Los hooks no reescriben argumentos de tool, así que no pueden inyectar el `model`.
- En el engine v2 actual, `KIMI_SECONDARY_MODEL` / `KIMI_SECONDARY_EFFORT` **no se leen**; la config
  manda. `KIMI_CODE_EXPERIMENTAL_SECONDARY_MODEL` fue eliminada y el pool está siempre activo.

Por eso el binding persona→modelo es **política guiada por prompt** (la matriz de ruteo), no un
binding duro.

## Roadmap

- [x] Port a Python de los validadores (equivalencia verificada 273/273)
- [x] `scripts/swarm-sandbox.py`: runner de `systemd-run`/bwrap con create/run/promote
- [ ] Personas extra: `docs`, `perf`, `test-writer`
- [ ] `scripts/` para generar el pool automáticamente desde `[models]`
- [ ] Publicar en el marketplace *Curated* de Kimi
- [ ] README en inglés

## Licencia

MIT. Incluye el skill de Cloudflare vendorizado bajo MIT (ver `THIRD-PARTY.md`).
