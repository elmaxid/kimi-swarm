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

### Opción A — `systemd-run` (este server)

Este host tiene systemd 259 y user namespaces habilitados, así que **no hace falta instalar nada**.
Verificado en este server:

```bash
mkdir -p /opt/sbx-scratch && chmod 1777 /opt/sbx-scratch   # scratch de la ejecución

systemd-run --quiet --wait --collect \
  -p DynamicUser=yes \
  -p PrivateNetwork=yes \
  -p ProtectSystem=strict -p ProtectHome=yes -p PrivateTmp=yes \
  -p NoNewPrivileges=yes \
  -p ReadWritePaths=/opt/sbx-scratch \
  -p MemoryMax=512M -p TasksMax=64 -p RuntimeMaxSec=300 \
  /bin/sh -c 'cd /opt/sbx-scratch && <comando-del-target>'
```

Resultado medido en este host:

| Control | Resultado |
| --- | --- |
| Usuario | efímero (`run-pXXXX-iXXXXX`), no root |
| `/root` (secretos, `config.toml`) | oculto, sin acceso |
| Red externa | bloqueada |
| `/etc`, `/usr` | read-only (`ProtectSystem=strict`) |
| Escritura | solo en `ReadWritePaths` |
| `HOME` | sanitizado |

Para el flujo completo, el "runner" es un comando que el agente ejecuta vía `Bash`: copia el target a
`scratch/`, ejecuta dentro de `systemd-run` con esos límites, y solo promueve el resultado mínimo.

### Opción B — `bubblewrap` (cualquier Linux)

`bwrap` es una herramienta mínima de sandbox por namespaces, sin daemon. Se instala con
`apt-get install bubblewrap` (~1 MB):

```bash
bwrap --unshare-all --share-net=false \
  --ro-bind /usr /usr --ro-bind /lib /lib --ro-bind /lib64 /lib64 \
  --bind /scratch /scratch --tmpfs /tmp \
  --proc /proc --dev /dev --die-with-parent \
  --chdir /scratch /bin/sh -c '<comando-del-target>'
```

Útil si el server no corre systemd o querés algo sin acoplarse a él.

### Opción C — contenedor

`docker`/`podman` con `--network=none --read-only --tmpfs /tmp --memory --pids-limit
--cap-drop=ALL --user 65534`. Es lo más portable y lo más pesado; conviene si ya usás contenedores en
el puesto.

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
- [ ] `scripts/swarm-sandbox.sh`: runner de `systemd-run`/bwrap listo para usar
- [ ] Personas extra: `docs`, `perf`, `test-writer`
- [ ] `scripts/` para generar el pool automáticamente desde `[models]`
- [ ] Publicar en el marketplace *Curated* de Kimi
- [ ] README en inglés

## Licencia

MIT. Incluye el skill de Cloudflare vendorizado bajo MIT (ver `THIRD-PARTY.md`).
