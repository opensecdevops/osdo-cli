# OSDO CLI — Zero to Secure DevOps en 5 minutos

CLI oficial del framework OSDO (Open Secure DevOps), construido con [oclif](https://oclif.io/) y TypeScript. Permite gestionar pipelines de CI/CD, catálogos de componentes, presets de deployment, escáneres de seguridad y la integración con la OSDO App web — todo desde la terminal.

---

## Instalacion

### npm (global)

```bash
npm install -g @osdo/cli
```

### Homebrew (próximamente)

```bash
brew tap opensecdevops/tap
brew install osdo
```

### Desde el código fuente

```bash
git clone https://github.com/opensecdevops/osdo-cli.git
cd osdo-cli
npm install
npm run build
npm link
```

Requiere **Node.js >= 20**.

---

## Quick Start

```bash
# 1. Inicializar un proyecto OSDO en el directorio actual
osdo init

# 2. Explorar el catálogo de componentes disponibles
osdo catalog list

# 3. Ejecutar un escaneo de seguridad
osdo security scan

# 4. Certificar el entorno actual
osdo certify
```

---

## Integracion con la OSDO App

La OSDO App web ([app.opensecdevops.com](https://app.opensecdevops.com)) permite construir visualmente tus configuraciones de infraestructura y pipelines. El CLI se conecta a la App para descargar los paquetes generados y sincronizar el estado de tus deployments.

### Conectar el CLI a la App

```bash
# Iniciar sesión con tu cuenta de la OSDO App
osdo app login --url https://app.opensecdevops.com

# Verificar el estado de la conexión
osdo app status
```

### Descargar un paquete generado

```bash
# Listar paquetes disponibles y seleccionar uno interactivamente
osdo app pull

# Descargar un paquete concreto por ID
osdo app pull 42

# Especificar directorio de destino
osdo app pull 42 --dir ./infrastructure
```

### Sincronizar el estado de un deployment

```bash
# Marcar un deployment como desplegado
osdo app push --deployment-id 1 --status deployed

# Reportar un fallo con mensaje
osdo app push --deployment-id 1 --status failed --message "Error en namespace production"
```

### Cerrar sesión

```bash
osdo app logout
```

---

## Referencia de comandos

### Flags globales

| Flag | Alias | Descripcion | Default |
|------|-------|-------------|---------|
| `--verbose` | `-v` | Salida detallada | `false` |
| `--dry-run` | — | Simular sin ejecutar | `false` |
| `--output` | `-o` | Formato: `table`, `json`, `yaml` | `table` |
| `--config` | — | Archivo de configuracion alternativo | — |

### `osdo app`

| Comando | Descripcion |
|---------|-------------|
| `osdo app login` | Autenticarse con la OSDO App |
| `osdo app logout` | Cerrar sesión |
| `osdo app status` | Ver estado de la conexión |
| `osdo app pull [id]` | Descargar paquete generado por la App |
| `osdo app push` | Enviar estado de deployment a la App |

### `osdo pipeline`

| Comando | Descripcion |
|---------|-------------|
| `osdo pipeline list` | Listar pipelines configurados |
| `osdo pipeline run <name>` | Ejecutar un pipeline |
| `osdo pipeline status <name>` | Ver estado de un pipeline |

### `osdo catalog`

| Comando | Descripcion |
|---------|-------------|
| `osdo catalog list` | Listar componentes disponibles |
| `osdo catalog info <component>` | Ver detalles de un componente |
| `osdo catalog update` | Actualizar el catálogo local |

### `osdo preset`

| Comando | Descripcion |
|---------|-------------|
| `osdo preset list` | Listar presets guardados |
| `osdo preset apply <name>` | Aplicar un preset de deployment |
| `osdo preset save <name>` | Guardar configuracion como preset |

### `osdo security`

| Comando | Descripcion |
|---------|-------------|
| `osdo security scan` | Escanear vulnerabilidades en el proyecto |
| `osdo security policy` | Gestionar políticas de seguridad |
| `osdo security report` | Generar informe de cumplimiento |

### `osdo monitor`

| Comando | Descripcion |
|---------|-------------|
| `osdo monitor status` | Ver estado de la infraestructura |
| `osdo monitor alerts` | Ver alertas activas |
| `osdo monitor dashboard` | Abrir dashboard de Grafana |

---

## Configuracion

El CLI usa dos niveles de configuracion:

### Nivel proyecto — `.osdo/config.yaml`

Archivo YAML en el directorio del proyecto. Se recomienda incluirlo en el repositorio (no contiene credenciales).

```yaml
configVersion: "1.0"
defaultPlatform: kubernetes
defaultDomain: mi-empresa.com
monitoring:
  enabled: true
  namespace: monitoring
security:
  vulnScanning:
    enabled: true
    threshold: high
```

### Nivel usuario — almacen persistente del sistema

Tokens de autenticación y preferencias del usuario se almacenan de forma segura en el directorio de configuracion del sistema operativo (gestionado por el CLI). Nunca se escriben en el repositorio.

### Variables de entorno

| Variable | Descripcion |
|----------|-------------|
| `OSDO_APP_URL` | URL de la OSDO App |
| `OSDO_VERBOSE` | Activar modo verbose (`true`/`false`) |
| `OSDO_DRY_RUN` | Activar dry-run (`true`/`false`) |
| `OSDO_OUTPUT` | Formato de salida (`table`/`json`/`yaml`) |
| `OSDO_CONFIG` | Ruta a archivo de configuracion alternativo |
| `DEBUG_OSDO` | Activar logs de depuracion internos |

---

## Desarrollo

```bash
# Instalar dependencias
npm install

# Compilar TypeScript
npm run build

# Modo desarrollo (sin compilar)
npm run dev -- app status

# Tests
npm test

# Lint
npm run lint
```

### Estructura del proyecto

```
osdo-cli/
├── bin/
│   ├── run.js          # Punto de entrada produccion
│   └── dev.js          # Punto de entrada desarrollo
├── src/
│   ├── commands/       # Comandos oclif (un fichero por comando)
│   │   └── app/        # Subcomandos del topic "app"
│   ├── hooks/          # Hooks oclif (init, prerun, postrun)
│   └── lib/
│       ├── api/        # Cliente HTTP hacia la OSDO App
│       ├── config/     # Tipos y gestor de configuracion
│       └── generator/  # Motor Handlebars + prompts interactivos
├── test/               # Tests con Mocha + Chai
├── package.json
└── tsconfig.json
```

---

## Contribuir

1. Haz un fork del repositorio
2. Crea una rama para tu feature: `git checkout -b feature/mi-feature`
3. Asegúrate de que los tests pasan: `npm test`
4. Abre un Pull Request hacia `main`

Consulta [CONTRIBUTING.md](https://github.com/opensecdevops/osdo-cli/blob/main/CONTRIBUTING.md) para las guías detalladas.

---

## Licencia

MIT — ver [LICENSE](LICENSE) para los detalles completos.

Copyright (c) 2024 OpenSecDevOps Contributors
