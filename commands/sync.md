---
description: Sync missing gateway models, optionally fill absent metadata and refresh model families, with preview and confirmation
argument-hint: "[--provider ID] [--refresh-metadata] [--refresh-families] [--dry-run]"
---

Sincronizá el catálogo `[models.*]` de `config.toml` con lo que anuncia tu gateway, y —si te lo
piden— completá metadatos ausentes y actualizá las familias de `kimi-swarm.toml`. Este comando
**solo orquesta**: toda la mecánica determinista (leer el gateway, calcular el plan, escribir con
backup y validación) vive en `scripts/sync-models.py`. No edites el TOML por tu cuenta, no leas ni
imprimas credenciales, y no invoques `kimi provider add` ni `kimi provider remove`: el primero pisa
`api_key` y borra `support_efforts`, y el segundo borra el provider con todos sus alias.

## Resolver el script

El plugin corre desde la copia gestionada, no desde el working tree, así que no hardcodees rutas del
repositorio. Resolvé el directorio de scripts así:

```bash
KIMI_HOME="${KIMI_CODE_HOME:-$HOME/.kimi-code}"
SCRIPTS="$KIMI_HOME/plugins/managed/kimi-swarm/scripts"
```

Si `$SCRIPTS/sync-models.py` no existe, leé el campo `root` de la entrada `kimi-swarm` en
`$KIMI_HOME/plugins/installed.json` y usá `$root/scripts`. Si tampoco está, decíselo al usuario y
ofrecé reinstalar el plugin (`/plugins install`, o `scripts/install-local.py` desde el árbol fuente)
antes de seguir: no continúes sin el script.

## Flujo

1. **Preview siempre primero.** Corré el script en modo dry-run, que es el default y no escribe nada:

   ```bash
   python3 "$SCRIPTS/sync-models.py" --dry-run $ARGUMENTS
   ```

   El script imprime el provider, el origen (sin credenciales), el hash del plan, la tabla
   `acción | alias | campo | actual | propuesta | motivo` y un resumen con las advertencias. Guardá el
   hash: es lo que después se pasa con `--expect-plan`.

2. **Ambigüedad de provider.** Si el script falla con `several providers have a base_url` (exit 3),
   lista los candidatos que imprimió y preguntá con `AskUserQuestion` cuál es el gateway a
   sincronizar. Nunca asumas un nombre: el mismo gateway se llama `litellm` en una máquina,
   `local-gateway` en otra y `ollama-mke` en una tercera. Volvé a correr el preview con
   `--provider ID`.

3. **Alcance.** Preguntá con `AskUserQuestion` qué querés sincronizar, y volvé a correr el preview
   con las banderas elegidas si cambian:

   - `Solo agregar lo que falta (Recommended)` — altas de bloques `[models.*]` que el gateway anuncia
     y `config.toml` no tiene. No toca lo que ya existe.
   - `Completar metadatos ausentes` — además, `--refresh-metadata`: suma capacidades y efforts que
     falten en bloques existentes (nunca quita nada) y completa `max_context_size` / `default_effort`
     solo si el campo está ausente.
   - `Además refrescar familias` — suma `--refresh-families`, que sincroniza `kimi-swarm.toml`.

   Si el usuario ya pasó las banderas en `$ARGUMENTS`, respetá esa elección y preguntá solo si hay
   algo ambiguo.

4. **Mostrar el resultado.** Mostrale la tabla tal como salió (altas, uniones, campos completados,
   contradicciones informativas, exclusiones por modo, referencias del pool a alias no anunciados) y
   decile explícitamente:

   - Las **contradicciones** son informativas: el gateway desmiente un valor local (por ejemplo
     `tool_use`), el campo no es confiable y el script **no lo toca**.
   - Los **avisos** son los que hacen que la corrida sea parcial (exit 1 aunque aplique los cambios
     seguros): modelos locales que el gateway ya no anuncia (nunca se borran), niveles de effort
     desconocidos, el pool apuntando a un alias no anunciado.
   - Los **modelos excluidos** tienen `mode` no-chat (`embedding`, `image_generation`, `rerank`,
     `audio_speech`, `audio_transcription`). Un `mode` nulo o ausente sí es elegible.

5. **Confirmar.** Preguntá con `AskUserQuestion`: `Aplicar (Recommended)`, `Cambiar opciones`,
   `Cancelar`. En `Cambiar opciones`, volvé al paso 3. Nunca apliques sin confirmación explícita.

6. **Aplicar con el plan confirmado.** Repetí exactamente las mismas banderas del preview que
   mostraste (incluido `--provider ID`, que solo hace falta cuando hay varios providers con
   `base_url`) y pasá el hash tal como salió:

   ```bash
   python3 "$SCRIPTS/sync-models.py" --provider litellm --refresh-metadata --refresh-families \
     --apply --expect-plan SHA256
   ```

   Si el archivo cambió entre el preview y el apply, el script aborta con exit 5 y no pisa nada: en
   ese caso volvé al paso 1 y mostrá el plan nuevo. Un exit 1 significa que aplicó los cambios
   seguros y quedaron advertencias; un exit 6, que falló la escritura (el catálogo válido se conserva
   y las familias se restauran desde el backup).

7. **Cerrar.** Decile al usuario que corra `/reload` o abra una sesión nueva. El script deja un backup
   `config.toml.<timestamp>.bak` (y otro de `kimi-swarm.toml`) con modo `0600`; para volver atrás, el
   precedente es `uninstall-local.py --restore-backup`.

## Qué NO hace este comando

- **No crea ni edita variantes `@effort`.** Eso es de `/kimi-swarm:setup`, que es el dueño del pool
  `[secondary_model]` y de las variantes. Sync solo valida que la invariante
  `default_effort ∈ support_efforts` se sostenga en los grupos base+variantes y, si un grupo la
  incumple, omite los cambios de ese grupo y lo reporta.
- **No borra bloques de modelo.** Ausente en el gateway es "no anunciado", no "muerto".
- **No consulta ni escribe credenciales.** La `api_key` viaja solo en el header del request; nunca se
  imprime, ni se pasa por argv, ni se copia a otro archivo.

Contexto opcional del usuario: $ARGUMENTS
