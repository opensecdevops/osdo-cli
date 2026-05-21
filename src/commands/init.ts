import {Flags} from '@oclif/core'
import {select, input} from '@inquirer/prompts'
import {Listr} from 'listr2'
import {existsSync, mkdirSync, readFileSync, writeFileSync} from 'node:fs'
import {basename, join} from 'node:path'
import {execa} from 'execa'
import {BaseCommand} from '../lib/base-command.js'

interface PackageConfig {
  name?: string
  template?: string
  runtime?: string
  standards?: string[]
  scanners?: Record<string, boolean>
  qualityGates?: {critical?: number; high?: number; medium?: number}
}

const TEMPLATE_TYPES = ['web-api', 'microservice', 'library', 'cli', 'mobile'] as const
type TemplateType = (typeof TEMPLATE_TYPES)[number]

const TEMPLATE_DESCRIPTIONS: Record<TemplateType, string> = {
  'web-api': 'REST/GraphQL API con pipeline de seguridad completo',
  microservice: 'Microservicio en contenedor con manifiestos K8s',
  library: 'Librería reutilizable con workflow de publicación seguro',
  cli: 'Herramienta CLI con automatización de releases',
  mobile: 'App móvil con seguridad específica de plataforma',
}

export default class Init extends BaseCommand {
  static description = 'Inicializar un proyecto con Golden Path templates de OSDO'

  static examples = [
    '<%= config.bin %> init',
    '<%= config.bin %> init --template web-api --name my-api',
    '<%= config.bin %> init --template microservice --name my-service --path ./projects',
    '<%= config.bin %> init --template library --no-with-ci',
  ]

  static flags = {
    ...BaseCommand.globalFlags,
    template: Flags.string({
      char: 't',
      description: 'Tipo de template (web-api, microservice, library, cli, mobile)',
      options: [...TEMPLATE_TYPES],
    }),
    name: Flags.string({
      char: 'n',
      description: 'Nombre del proyecto',
    }),
    path: Flags.string({
      char: 'p',
      description: 'Ruta donde crear el proyecto',
      default: '.',
    }),
    interactive: Flags.boolean({
      char: 'i',
      description: 'Modo interactivo',
      default: false,
    }),
    'with-ci': Flags.boolean({
      description: 'Incluir workflows CI/CD de OSDO',
      default: true,
      allowNo: true,
    }),
    'with-precommit': Flags.boolean({
      description: 'Incluir configuración de pre-commit hooks',
      default: true,
      allowNo: true,
    }),
    'git-init': Flags.boolean({
      description: 'Inicializar repositorio git',
      default: true,
      allowNo: true,
    }),
    package: Flags.string({
      char: 'k',
      description: 'ID de paquete OSDO App — lee config desde .osdo/packages/<id>/config.json',
    }),
  }

  async run(): Promise<void> {
    const {flags} = await this.parse(Init)

    this.log('\nOSDO Project Initializer')
    this.log('═══════════════════════════════════════\n')

    // Cargar configuración desde paquete OSDO App si se especificó
    let pkgConfig: PackageConfig | undefined
    if (flags.package) {
      const pkgPath = join('.osdo', 'packages', flags.package, 'config.json')
      if (!existsSync(pkgPath)) {
        this.error(`Paquete no encontrado: ${pkgPath}. Asegúrate de que existe o ejecuta: osdo app sync`, {exit: 1})
      }

      try {
        pkgConfig = JSON.parse(readFileSync(pkgPath, 'utf8')) as PackageConfig
        this.log(`Paquete OSDO App cargado: ${flags.package}`)
        if (this.configManager.isVerbose()) {
          this.log(`  Config: ${pkgPath}`)
        }
      } catch {
        this.error(`No se pudo parsear el paquete: ${pkgPath}`, {exit: 1})
      }
    }

    let template = (pkgConfig?.template ?? flags.template) as TemplateType | undefined
    let projectName = flags.name ?? pkgConfig?.name

    // Interactive mode si no hay template o se pidió explícitamente
    if (!template || flags.interactive) {
      const selected = await select({
        message: 'Selecciona un template de proyecto:',
        choices: TEMPLATE_TYPES.map(t => ({
          name: `${t} — ${TEMPLATE_DESCRIPTIONS[t]}`,
          value: t,
        })),
      })
      template = selected as TemplateType

      if (!projectName) {
        projectName = await input({
          message: 'Nombre del proyecto:',
          default: basename(process.cwd()),
        })
      }
    }

    if (!template) {
      this.error('Se requiere --template. Usa --interactive o pasa --template <tipo>', {exit: 1})
    }

    if (!projectName) {
      projectName = basename(process.cwd())
    }

    const projectPath = flags.path === '.'
      ? projectName
      : join(flags.path, projectName)

    if (existsSync(projectPath)) {
      this.error(`El directorio "${projectPath}" ya existe`, {exit: 1})
    }

    if (this.configManager.isDryRun()) {
      this.log(`[dry-run] Crearía proyecto "${projectName}" (${template}) en: ${projectPath}`)
      return
    }

    this.log(`Creando proyecto: ${projectPath}`)
    this.log(`Template: ${template}\n`)

    // Capturar para uso en closures
    const resolvedTemplate = template
    const resolvedName = projectName

    const tasks = new Listr(
      [
        {
          title: 'Creando estructura de directorios',
          task: async () => {
            createDirectoryStructure(projectPath, resolvedTemplate)
          },
        },
        {
          title: 'Escribiendo archivos del template',
          task: async () => {
            writeTemplateFiles(projectPath, resolvedTemplate, resolvedName)
          },
        },
        {
          title: 'Generando .osdo/config.yaml',
          task: async () => {
            writeOsdoConfig(projectPath, resolvedName, resolvedTemplate, pkgConfig)
          },
        },
        {
          title: 'Creando workflow CI/CD (.github/workflows/osdo-security.yml)',
          enabled: () => flags['with-ci'],
          task: async () => {
            writeCIWorkflow(projectPath, resolvedTemplate)
          },
        },
        {
          title: 'Generando .pre-commit-config.yaml',
          enabled: () => flags['with-precommit'],
          task: async () => {
            writePreCommitConfig(projectPath)
          },
        },
        {
          title: 'Creando SECURITY.md',
          task: async () => {
            writeSecurityMd(projectPath, resolvedName)
          },
        },
        {
          title: 'Inicializando repositorio git',
          enabled: () => flags['git-init'],
          task: async (_ctx, task) => {
            try {
              await execa('git', ['init', '--initial-branch=main', projectPath])
            } catch {
              task.title = 'git init omitido — git no disponible o ya existe .git'
            }
          },
        },
      ],
      {concurrent: false},
    )

    await tasks.run()

    this.log('\n═══════════════════════════════════════')
    this.log('Proyecto inicializado correctamente!\n')
    this.log('Próximos pasos:')
    this.log(`  cd ${projectPath}`)
    this.log('  osdo scan          # Ejecutar escaneo de seguridad')
    this.log('  osdo certify       # Verificar readiness de certificación')
    if (flags['with-precommit']) {
      this.log('  pre-commit install # Instalar git hooks')
    }

    this.log('')
  }
}

// ─── Helpers de creación de estructura ─────────────────────────────────────

function createDirectoryStructure(projectPath: string, template: TemplateType): void {
  const base = [
    projectPath,
    join(projectPath, '.osdo'),
    join(projectPath, '.osdo', 'policies'),
    join(projectPath, '.github'),
    join(projectPath, '.github', 'workflows'),
  ]

  const extra: Record<TemplateType, string[]> = {
    'web-api': ['cmd', 'pkg', 'internal', 'api', 'deploy', join('deploy', 'kubernetes')],
    microservice: ['cmd', 'pkg', 'internal', 'api', 'deploy', join('deploy', 'kubernetes')],
    library: ['src', 'tests', 'docs'],
    cli: ['cmd', 'internal'],
    mobile: ['src', 'ios', 'android'],
  }

  for (const dir of [...base, ...(extra[template] ?? []).map(d => join(projectPath, d))]) {
    mkdirSync(dir, {recursive: true})
  }
}

function writeTemplateFiles(projectPath: string, template: TemplateType, projectName: string): void {
  switch (template) {
    case 'web-api':
    case 'microservice': {
      writeGoProject(projectPath, projectName)
      break
    }

    case 'library': {
      writeLibraryProject(projectPath, projectName)
      break
    }

    case 'cli': {
      writeGoProject(projectPath, projectName)
      break
    }

    case 'mobile': {
      writeMobileProject(projectPath, projectName)
      break
    }
  }

  // .gitignore común
  writeFileSync(
    join(projectPath, '.gitignore'),
    `# OSDO results (no committed)
.osdo/results/
.osdo/reports/

# IDE
.idea/
.vscode/
*.swp
*.swo

# Environment
.env
.env.local
.env.*.local

# Build artifacts
dist/
build/
/app
*.exe
*.out
node_modules/
`,
  )
}

function writeGoProject(projectPath: string, projectName: string): void {
  writeFileSync(
    join(projectPath, 'go.mod'),
    `module github.com/example/${projectName}

go 1.21

require (
\tgithub.com/spf13/cobra v1.8.0
)
`,
  )

  writeFileSync(
    join(projectPath, 'main.go'),
    `package main

import (
\t"fmt"
\t"log"
\t"net/http"
)

func main() {
\thttp.HandleFunc("/health", healthHandler)
\thttp.HandleFunc("/", rootHandler)

\tport := ":8080"
\tlog.Printf("Starting ${projectName} on %s", port)
\tlog.Fatal(http.ListenAndServe(port, nil))
}

func healthHandler(w http.ResponseWriter, r *http.Request) {
\tw.WriteHeader(http.StatusOK)
\tfmt.Fprint(w, "OK")
}

func rootHandler(w http.ResponseWriter, r *http.Request) {
\tfmt.Fprintf(w, "Hello from ${projectName}!")
}
`,
  )

  writeFileSync(
    join(projectPath, 'Dockerfile'),
    `# Build stage
FROM golang:1.21-alpine AS builder

WORKDIR /app
COPY go.mod go.sum* ./
RUN go mod download

COPY . .
RUN CGO_ENABLED=0 GOOS=linux go build -trimpath -ldflags="-s -w" -o app .

# Runtime stage — distroless para mínima superficie de ataque
FROM gcr.io/distroless/static:nonroot

WORKDIR /app
COPY --from=builder /app/app .

USER nonroot:nonroot
EXPOSE 8080

ENTRYPOINT ["./app"]
`,
  )
}

function writeLibraryProject(projectPath: string, projectName: string): void {
  writeFileSync(
    join(projectPath, 'package.json'),
    JSON.stringify(
      {
        name: projectName,
        version: '0.1.0',
        description: `Librería segura con integración OSDO`,
        type: 'module',
        main: 'dist/index.js',
        types: 'dist/index.d.ts',
        scripts: {
          build: 'tsc',
          test: 'jest',
          lint: 'eslint src/',
          'security:scan': 'osdo scan',
          prepublishOnly: 'npm run build && npm test',
        },
        keywords: [],
        author: '',
        license: 'MIT',
        devDependencies: {
          typescript: '^5.0.0',
          jest: '^29.0.0',
          '@types/jest': '^29.0.0',
          eslint: '^8.0.0',
          'eslint-plugin-security': '^2.0.0',
        },
      },
      null,
      2,
    ) + '\n',
  )

  writeFileSync(
    join(projectPath, 'src', 'index.ts'),
    `/**
 * ${projectName} — Main entry point
 */

export function hello(name: string): string {
  return \`Hello, \${name}!\`
}
`,
  )

  writeFileSync(
    join(projectPath, 'tsconfig.json'),
    JSON.stringify(
      {
        compilerOptions: {
          target: 'ES2022',
          module: 'Node16',
          moduleResolution: 'Node16',
          declaration: true,
          outDir: 'dist',
          rootDir: 'src',
          strict: true,
        },
        include: ['src/**/*.ts'],
        exclude: ['node_modules', 'dist'],
      },
      null,
      2,
    ) + '\n',
  )
}

function writeMobileProject(projectPath: string, projectName: string): void {
  writeFileSync(
    join(projectPath, 'package.json'),
    JSON.stringify(
      {
        name: projectName,
        version: '0.1.0',
        description: `App móvil segura con integración OSDO`,
        scripts: {
          start: 'react-native start',
          android: 'react-native run-android',
          ios: 'react-native run-ios',
          test: 'jest',
          'security:scan': 'osdo scan',
        },
        dependencies: {
          react: '18.2.0',
          'react-native': '0.73.0',
        },
        devDependencies: {
          '@types/react': '^18.2.0',
          '@types/react-native': '^0.73.0',
          typescript: '^5.0.0',
        },
      },
      null,
      2,
    ) + '\n',
  )
}

function writeOsdoConfig(projectPath: string, projectName: string, template: TemplateType, pkgConfig?: PackageConfig): void {
  const runtimeByTemplate: Partial<Record<TemplateType, string>> = {
    'web-api': 'go: "1.21"',
    microservice: 'go: "1.21"',
    library: 'node: "20"',
    cli: 'go: "1.21"',
    mobile: 'node: "20"',
  }

  // Respetar runtime del paquete si existe
  let runtimeLine = runtimeByTemplate[template] ?? 'node: "20"'
  if (pkgConfig?.runtime) {
    runtimeLine = pkgConfig.runtime
  }

  // Umbrales de calidad — los del paquete tienen prioridad
  const critical = pkgConfig?.qualityGates?.critical ?? 0
  const high = pkgConfig?.qualityGates?.high ?? 5
  const medium = pkgConfig?.qualityGates?.medium ?? 20

  // Estándares de seguridad — los del paquete tienen prioridad
  const standards = pkgConfig?.standards ?? ['owasp-top-10', 'slsa-level-2', 'openssf-scorecard']
  const standardsYaml = standards.map(s => `    - ${s}`).join('\n')

  // Scanners — los del paquete tienen prioridad
  const scanners = pkgConfig?.scanners ?? {}
  const containerDefault = template === 'web-api' || template === 'microservice'
  const scannerSast = scanners['sast'] !== undefined ? scanners['sast'] : true
  const scannerSca = scanners['sca'] !== undefined ? scanners['sca'] : true
  const scannerSecrets = scanners['secrets'] !== undefined ? scanners['secrets'] : true
  const scannerContainer = scanners['container'] !== undefined ? scanners['container'] : containerDefault
  const scannerIac = scanners['iac'] !== undefined ? scanners['iac'] : false
  const scannerDast = scanners['dast'] !== undefined ? scanners['dast'] : false
  const scannerSbom = scanners['sbom'] !== undefined ? scanners['sbom'] : true

  const buildCmd = template === 'library' ? 'npm run build' : template === 'mobile' ? 'npm run android' : 'go build ./...'

  const config = `# yaml-language-server: $schema=https://opensecdevops.org/schemas/config/v2.json
# OSDO Project Configuration
# Generated by: osdo init — versión 2.0
# Documentación: https://opensecdevops.com/docs/config

version: "2.0"
instance: ${projectName}

runtime:
  ${runtimeLine}

test:
  coverage:
    minimum: 80

security:
  standards:
${standardsYaml}
  fail_on: high
  quality_gates:
    critical: ${critical}
    high: ${high}
    medium: ${medium}
  scanners:
    sast: ${scannerSast}
    sca: ${scannerSca}
    secrets: ${scannerSecrets}
    container: ${scannerContainer}
    iac: ${scannerIac}
    dast: ${scannerDast}
    sbom: ${scannerSbom}

reporting:
  formats:
    - sarif
    - json
  output_dir: .osdo/results

build:
  command: ${buildCmd}
${template === 'web-api' || template === 'microservice' ? '  dockerfile: Dockerfile' : ''}
`
  writeFileSync(join(projectPath, '.osdo', 'config.yaml'), config)
}

function writeCIWorkflow(projectPath: string, template: TemplateType): void {
  const enableContainer = template === 'web-api' || template === 'microservice'

  const workflow = `name: OSDO Security Pipeline
# Generado por: osdo init — v2.0
# Documentación: https://opensecdevops.com/docs/workflows
# Arquitectura 3-capas: https://opensecdevops.com/docs/framework

on:
  push:
    branches: [main, master]
  pull_request:
    branches: [main, master]

permissions:
  contents: read
  security-events: write
  pull-requests: read

jobs:
  osdo-security:
    name: OSDO Security Framework
    uses: opensecdevops/osdo-workflows/.github/workflows/osdo-framework.yml@v2
    with:
      enable-sast: true
      enable-sca: true
      enable-secrets: true
      enable-sbom: true
      enable-policy-gate: true
      enable-container: ${enableContainer}
      enable-iac: false
      enable-dast: false
      fail-on: high
    secrets: inherit
`
  writeFileSync(join(projectPath, '.github', 'workflows', 'osdo-security.yml'), workflow)
}

function writePreCommitConfig(projectPath: string): void {
  const config = `# Pre-commit configuration — OSDO
# Instalación: pre-commit install
# Documentación: https://pre-commit.com

repos:
  # Detección de secretos
  - repo: https://github.com/gitleaks/gitleaks
    rev: v8.18.4
    hooks:
      - id: gitleaks

  # Hooks generales de higiene
  - repo: https://github.com/pre-commit/pre-commit-hooks
    rev: v4.5.0
    hooks:
      - id: trailing-whitespace
      - id: end-of-file-fixer
      - id: check-yaml
      - id: check-json
      - id: check-toml
      - id: check-added-large-files
        args: ['--maxkb=1000']
      - id: detect-private-key
      - id: no-commit-to-branch
        args: ['--branch', 'main', '--branch', 'master']

  # Commits convencionales
  - repo: https://github.com/commitizen-tools/commitizen
    rev: v3.12.0
    hooks:
      - id: commitizen
        stages: [commit-msg]

  # Dockerfile linting
  - repo: https://github.com/hadolint/hadolint
    rev: v2.12.0
    hooks:
      - id: hadolint-docker
        args: ['--ignore', 'DL3008', '--ignore', 'DL3009']
`
  writeFileSync(join(projectPath, '.pre-commit-config.yaml'), config)
}

function writeSecurityMd(projectPath: string, projectName: string): void {
  const content = `# Security Policy — ${projectName}

## Versiones soportadas

| Versión | Soporte            |
| ------- | ------------------ |
| 0.1.x   | :white_check_mark: |

## Reporte de vulnerabilidades

Si descubres una vulnerabilidad de seguridad, por favor:

1. **NO** abras un issue público.
2. Envía un reporte privado mediante **GitHub Security Advisories** (pestaña Security de este repositorio).
3. Alternativamente, envía un email a: security@example.com

Recibirás una respuesta en un plazo máximo de **72 horas**.

## Medidas de seguridad — OSDO DevSecOps

Este proyecto utiliza el framework [OSDO](https://opensecdevops.com) para seguridad continua:

| Scanner | Herramienta | Cobertura |
|---------|-------------|-----------|
| SAST | Semgrep | Código fuente, IaC |
| SCA | OSV-Scanner, Grype | Dependencias directas e indirectas |
| Secrets | Gitleaks | Git history, código, configs |
| SBOM | Syft | SPDX 2.3 + CycloneDX 1.5 |
| Container | Trivy | Imagen Docker |
| Policy | OPA/Rego | Kubernetes, Terraform |

## Escaneo local

\`\`\`bash
# Escaneo de seguridad completo
osdo scan

# Verificar readiness de certificación OWASP
osdo certify --standard owasp

# Ver cobertura de cadena de suministro
osdo certify --standard slsa
\`\`\`

## Cumplimiento

Este proyecto apunta a:
- OWASP Top 10 (2021)
- SLSA Level 2
- OpenSSF Scorecard >= 7/10
`
  writeFileSync(join(projectPath, 'SECURITY.md'), content)
}
