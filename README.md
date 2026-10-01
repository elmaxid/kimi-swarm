# Kimi Swarm

Plugin de Kimi Code para **delegación con personas y multi-modelo**: reparte una tarea entre
subagentes especializados (`worker`, `review`, `security`, `architect`) que pueden correr en un
modelo distinto del orquestador.

Es la pieza que falta en Kimi: la delegación (`Agent` / `AgentSwarm`) y las personas (archivos de
agente) ya existen, pero **el modelo de cada subagente se configura aparte**, en el pool
`[secondary_model]`. Este plugin empaqueta las personas, la matriz de ruteo y los comandos, y te
guía para configurar el pool.

## Cómo encaja en Kimi Code

| Pieza | Dónde vive | Qué aporta |
| --- | --- | --- |
| Delegación | tools nativas `Agent` y `AgentSwarm` | Subagentes con contexto aislado, en paralelo y en background |
| Personas | `agents/*.md` de este plugin | Worker, review, security, architect |
| Modelo distinto | `[secondary_model]` en `config.toml` | Pool de modelos candidatos; el orquestador elige uno por spawn |

## Instalación

En Kimi Code:

```
/plugins install https://github.com/elmaxid/kimi-swarm
```

o desde un checkout local:

```
/plugins install /ruta/a/kimi-swarm
```

Luego `/reload` o una sesión nueva para activarlo.

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
"litellm/kimi-k2.7-code"  = "Worker: implementación, refactors, ediciones."
"litellm/claude-opus-5"   = "Review y arquitectura: razonamiento profundo."
"litellm/glm-5.3"         = "Security: familia distinta para una segunda opinión."
```

Reglas que fallan fuerte al arrancar la sesión:

- Cada alias del pool debe existir en `[models]`.
- `default_model` es obligatorio si hay tabla `models`, y debe ser una de sus claves.
- `force = true` exige `default_model` y no se puede combinar con `models`.

## Uso

Ruteo automático (el agente principal lee la Skill y el system prompt y elige), o explícito:

- *"Usá swarm-review con el modelo fuerte para revisar el diff actual."*
- *"Lanzá swarm-worker para implementar X y después swarm-security sobre el resultado."*
- `/kimi-swarm:review`, `/kimi-swarm:security-audit`

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

## Personas incluidas

| Persona | Tools | Rol |
| --- | --- | --- |
| `swarm-worker` | lectura + escritura + Bash | Implementar, refactorizar, correr build/tests, dejar el cambio hecho |
| `swarm-review` | solo lectura | Revisar diff/PR: severidad, regresiones, edge cases |
| `swarm-security` | solo lectura | Auditoría: inyección, auth, secretos, dependencias |
| `swarm-architect` | lectura + web | Diseño, trade-offs, planificación |

`swarm-review` y `swarm-security` son read-only y no pueden lanzar más subagentes.

## Roadmap (MVP)

- [ ] Validación del `$ARGUMENTS` de los comandos y mejor diff automático
- [ ] Personas extra: `docs`, `perf`, `test-writer`
- [ ] `scripts/` para generar el pool automáticamente desde `[models]`
- [ ] Publicar en el marketplace *Curated* de Kimi
- [ ] README en inglés

## Licencia

MIT
