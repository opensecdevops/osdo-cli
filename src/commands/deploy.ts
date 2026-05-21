import {Flags} from '@oclif/core'
import {checkbox, confirm} from '@inquirer/prompts'
import {existsSync, mkdirSync, readdirSync, readFileSync, writeFileSync} from 'node:fs'
import {join, dirname} from 'node:path'
import {execa} from 'execa'
import chalk from 'chalk'
import {BaseCommand} from '../lib/base-command.js'
import {INFRA_CATALOG} from '../lib/infra-catalog.js'
import {promptForPackage} from '../lib/generator/prompter.js'
import {renderPackage} from '../lib/generator/handlebars.js'
import type {PackageConfig} from '../lib/api/client.js'
import type {Platform} from '../lib/config/types.js'
import {createDeployer, type DeploymentResult} from '../lib/deployer/index.js'

const PLATFORMS: Platform[] = ['kubernetes', 'k3s', 'docker-compose', 'docker-swarm', 'helm']

/**
 * Deploy — Despliega componentes de infraestructura DevSecOps.
 *
 * Porta la lógica de cmd/deploy.go añadiendo soporte v2 para:
 *   - Selección de componentes individuales (--components)
 *   - Presets guardados (--preset)
 *   - Selección interactiva con checkbox (--interactive)
 *   - Despliegue de paquetes OSDO desde la App (--package/-k)
 *
 * El ciclo de despliegue real se delega al motor de deployers:
 *   helm            → HelmDeployer
 *   kubernetes/k3s  → KubernetesDeployer
 *   docker-compose  → DockerComposeDeployer
 *   docker-swarm    → DockerSwarmDeployer
 */
export default class Deploy extends BaseCommand {
  static description = 'Desplegar componentes de infraestructura DevSecOps en la plataforma especificada'

  static examples = [
    '<%= config.bin %> deploy --components prometheus grafana --platform kubernetes',
    '<%= config.bin %> deploy --components vault sonarqube --namespace security --platform helm',
    '<%= config.bin %> deploy --preset production',
    '<%= config.bin %> deploy --interactive --platform k3s',
    '<%= config.bin %> deploy --package .osdo/packages/42 --platform kubernetes',
    '<%= config.bin %> deploy --dry-run --components grafana --platform docker-compose',
  ]

  static flags = {
    ...BaseCommand.globalFlags,

    platform: Flags.string({
      char: 'p',
      options: PLATFORMS,
      description: 'Plataforma de despliegue destino',
      env: 'OSDO_PLATFORM',
    }),

    components: Flags.string({
      char: 'c',
      description: 'Componentes a desplegar, separados por espacio o coma (ej: prometheus grafana vault)',
      multiple: true,
      exclusive: ['preset', 'interactive'],
    }),

    preset: Flags.string({
      description: 'Nombre de un preset guardado que define los componentes a desplegar',
      exclusive: ['components', 'interactive'],
    }),

    interactive: Flags.boolean({
      char: 'i',
      description: 'Seleccionar componentes de forma interactiva mediante un menú de casillas',
      default: false,
      exclusive: ['components', 'preset'],
    }),

    package: Flags.string({
      char: 'k',
      description:
        'Ruta a un paquete OSDO descargado con "osdo app pull" — lee config.json, ' +
        'solicita valores de forma interactiva con Handlebars y despliega los archivos generados',
      exclusive: ['components', 'preset', 'interactive'],
    }),

    namespace: Flags.string({
      char: 'n',
      description: 'Namespace o contexto de destino para el despliegue',
      default: 'osdo',
    }),

    domain: Flags.string({
      char: 'd',
      description: 'Dominio base para los servicios (ej: osdo.empresa.com)',
    }),

    force: Flags.boolean({
      description: 'Forzar el despliegue ignorando advertencias y validación de componentes',
      default: false,
    }),
  }

  async run(): Promise<void> {
    const {flags} = await this.parse(Deploy)

    const platform = (flags.platform ?? this.configManager.getDefaultPlatform()) as Platform
    const namespace = flags.namespace ?? 'osdo'

    // Rama de despliegue de paquete (v2 feature)
    if (flags.package) {
      await this.deployPackage(flags.package, platform, namespace)
      return
    }

    // Determinar componentes a desplegar
    const selectedComponents = await this.resolveComponents(flags)

    if (selectedComponents.length === 0) {
      this.error('No se seleccionó ningún componente para desplegar.', {exit: 1})
    }

    // Cabecera del plan de despliegue
    this.log(chalk.bold('\nOSDO Deploy'))
    this.log('═'.repeat(52))
    this.log(`  Plataforma:   ${chalk.cyan(platform)}`)
    this.log(`  Namespace:    ${chalk.cyan(namespace)}`)
    this.log(`  Componentes:  ${chalk.cyan(selectedComponents.join(', '))}`)
    if (flags.domain) this.log(`  Dominio:      ${chalk.cyan(flags.domain)}`)
    if (flags['dry-run']) this.log(chalk.yellow('  Modo:         DRY-RUN (sin cambios reales)'))
    this.log('')

    // Confirmación cuando se despliegan muchos componentes a la vez (salvo dry-run)
    if (selectedComponents.length >= 4 && !flags.force && !flags['dry-run']) {
      const ok = await confirm({
        message: `¿Confirmar el despliegue de ${chalk.bold(String(selectedComponents.length))} componentes en ${chalk.cyan(platform)}/${chalk.cyan(namespace)}?`,
        default: true,
      })
      if (!ok) {
        this.log('Despliegue cancelado por el usuario.')
        return
      }
    }

    // Crear deployer para la plataforma seleccionada
    const deployer = createDeployer(platform, namespace)

    // Verificar que la plataforma esté disponible
    try {
      await deployer.isReady()
    } catch (err: unknown) {
      const msg = err instanceof Error ? err.message : String(err)
      this.error(
        `Plataforma "${platform}" no disponible: ${msg}\n` +
          '  Verifica que las herramientas necesarias estén instaladas.',
        {exit: 1},
      )
    }

    // Validar nombres de componentes contra el catálogo del deployer
    try {
      deployer.validateComponents(selectedComponents)
    } catch (err: unknown) {
      const msg = err instanceof Error ? err.message : String(err)
      this.error(msg, {exit: 1})
    }

    // Ejecutar despliegue y mostrar resultados
    const result = await deployer.deploy(selectedComponents, {
      dryRun: flags['dry-run'],
      force: flags.force,
      timeoutMs: 5 * 60 * 1000,
      namespace,
      createNamespace: true,
      wait: true,
      verbose: flags.verbose,
    })

    this.printDeploymentResult(result)

    if (!result.success) {
      process.exit(1)
    }
  }

  // ── Resolución de componentes ─────────────────────────────────────────────

  private async resolveComponents(flags: {
    components?: string[]
    preset?: string
    interactive: boolean
  }): Promise<string[]> {
    // Modo preset: leer componentes del preset guardado
    if (flags.preset) {
      const preset = this.configManager.getPresets().find(p => p.name === flags.preset)
      if (!preset) {
        this.error(
          `Preset "${flags.preset}" no encontrado.\n` +
            "Usa 'osdo preset list' para ver los presets disponibles.",
          {exit: 1},
        )
      }

      this.log(`Usando preset: ${chalk.cyan(flags.preset)} → ${preset.components.join(', ')}`)
      return preset.components
    }

    // Modo interactivo: checkbox de componentes
    if (flags.interactive) {
      return this.selectInteractively()
    }

    // Modo explícito: --components (acepta múltiples flags o valores con coma)
    if (flags.components && flags.components.length > 0) {
      return flags.components
        .flatMap(c => c.split(','))
        .map(s => s.trim())
        .filter(Boolean)
    }

    this.error(
      'Especifica los componentes a desplegar con --components, --preset o --interactive.\n' +
        'Ejemplo: osdo deploy --components prometheus grafana vault --platform helm',
      {exit: 1},
    )
  }

  private async selectInteractively(): Promise<string[]> {
    this.log(chalk.bold('Selección interactiva de componentes\n'))

    const selected = await checkbox({
      message:
        'Selecciona los componentes a desplegar (Espacio = marcar, Enter = confirmar):',
      choices: INFRA_CATALOG.map(item => ({
        name: `${item.name.padEnd(22)} ${chalk.dim(`[${item.category}]`)} ${item.description}`,
        value: item.name,
        short: item.name,
      })),
      pageSize: 15,
    })

    if (selected.length === 0) {
      this.error('No se seleccionó ningún componente.', {exit: 1})
    }

    return selected
  }

  // ── Resultado del despliegue ──────────────────────────────────────────────

  /**
   * Muestra el resultado del despliegue por componente y un resumen final.
   * Incluye endpoints, credenciales de acceso y próximos pasos recomendados.
   */
  private printDeploymentResult(result: DeploymentResult): void {
    const total = result.components.length
    const succeeded = result.components.filter(c => c.success).length
    const failed = total - succeeded

    this.log(chalk.bold('Resultados del despliegue:'))
    this.log('─'.repeat(52))

    for (const comp of result.components) {
      const icon = comp.success ? chalk.green('✅') : chalk.red('❌')
      const statusLabel = comp.success ? chalk.green(comp.status) : chalk.red(comp.status)
      this.log(`  ${icon} ${chalk.bold(comp.name.padEnd(20))} ${statusLabel}`)

      if (comp.endpoints && comp.endpoints.length > 0) {
        for (const ep of comp.endpoints) {
          this.log(`       ${chalk.dim('→')} ${chalk.cyan(ep)}`)
        }
      }

      const access = result.accessInfo[comp.name]
      if (access?.credentials && Object.keys(access.credentials).length > 0) {
        const creds = Object.entries(access.credentials)
          .map(([k, v]) => `${k}: ${v}`)
          .join(' / ')
        this.log(`       ${chalk.dim('🔑')} ${chalk.dim(creds)}`)
      }

      if (comp.error) {
        this.log(`       ${chalk.red('Error:')} ${chalk.red(comp.error)}`)
      }
    }

    this.log('─'.repeat(52))

    const durationSec = (result.duration / 1000).toFixed(1)
    if (result.success) {
      this.log(
        chalk.green(`\n✓ ${succeeded}/${total} componente(s) desplegado(s) correctamente.`) +
          chalk.dim(` (${durationSec}s)`),
      )
    } else {
      this.log(
        chalk.red(`\n✗ ${failed} componente(s) fallaron.`) +
          chalk.dim(` ${succeeded}/${total} exitosos. (${durationSec}s)`),
      )
    }

    // Mostrar advertencias si las hay (p.ej. dry-run config generada)
    if (result.warnings && result.warnings.length > 0) {
      this.log('')
      for (const w of result.warnings) {
        this.log(chalk.yellow(w))
      }
    }

    // Próximos pasos
    if (succeeded > 0) {
      this.log('')
      this.log(chalk.bold('Próximos pasos recomendados:'))
      this.log(`  ${chalk.cyan('osdo status')} — Verificar el estado de los componentes`)

      const plat = result.platform
      const ns = result.namespace ?? 'osdo'

      if (plat === 'kubernetes' || plat === 'k3s') {
        this.log(`  ${chalk.cyan(`kubectl get pods -n ${ns}`)} — Ver pods desplegados`)
      }

      if (plat === 'helm') {
        this.log(`  ${chalk.cyan(`helm list -n ${ns}`)} — Ver releases de Helm`)
      }

      if (plat === 'docker-compose') {
        this.log(`  ${chalk.cyan('docker compose ps')} — Ver servicios activos`)
      }

      if (plat === 'docker-swarm') {
        this.log(`  ${chalk.cyan('docker service ls')} — Ver servicios del Swarm`)
      }

      // Información de acceso a los servicios desplegados
      const accessEntries = Object.entries(result.accessInfo)
      if (accessEntries.length > 0) {
        this.log('')
        this.log(chalk.bold('Acceso a los servicios:'))
        for (const [name, access] of accessEntries) {
          if (access.url) {
            this.log(`  ${chalk.bold(name.padEnd(20))} ${chalk.cyan(access.url)}`)
          }

          if (access.credentials && Object.keys(access.credentials).length > 0) {
            const creds = Object.entries(access.credentials)
              .map(([k, v]) => `${k}: ${chalk.cyan(v)}`)
              .join(' / ')
            this.log(`  ${''.padEnd(20)} ${chalk.dim(creds)}`)
          }

          if (access.instructions) {
            this.log(`  ${''.padEnd(20)} ${chalk.dim(access.instructions)}`)
          }
        }
      }

      this.log('')
    }
  }

  // ── Despliegue de paquete OSDO (feature v2) ───────────────────────────────

  /**
   * Flujo de despliegue de paquete:
   *   1. Lee <dir>/config.json como PackageConfig
   *   2. Lee templates de <dir>/templates/
   *   3. Solicita valores al usuario interactivamente (prompter + Handlebars)
   *   4. Renderiza los templates y escribe los archivos generados
   *   5. Despliega los archivos generados según la plataforma
   */
  private async deployPackage(packagePath: string, platform: Platform, namespace: string): Promise<void> {
    const fullPath = join(process.cwd(), packagePath)

    if (!existsSync(fullPath)) {
      this.error(`Directorio de paquete no encontrado: ${fullPath}`, {exit: 1})
    }

    const configFilePath = join(fullPath, 'config.json')
    if (!existsSync(configFilePath)) {
      this.error(
        `Archivo config.json no encontrado en: ${configFilePath}\n` +
          'Asegúrate de haber ejecutado "osdo app pull" primero.',
        {exit: 1},
      )
    }

    const packageConfig = JSON.parse(readFileSync(configFilePath, 'utf8')) as PackageConfig

    // Leer templates del directorio templates/
    const templatesDir = join(fullPath, 'templates')
    const templates: Array<{file: string; content: string}> = []

    if (existsSync(templatesDir)) {
      for (const file of readdirSync(templatesDir)) {
        const content = readFileSync(join(templatesDir, file), 'utf8')
        templates.push({file, content})
      }
    }

    // Cabecera
    this.log(chalk.bold(`\nDespliegue de paquete OSDO: ${chalk.cyan(packageConfig.name)}`))
    this.log('─'.repeat(52))
    this.log(`  Tipo:       ${packageConfig.type}`)
    this.log(`  Versión:    ${packageConfig.version}`)
    if (packageConfig.description) this.log(`  Info:       ${packageConfig.description}`)
    this.log(`  Plataforma: ${platform}`)
    this.log(`  Namespace:  ${namespace}`)
    this.log('')

    // Solicitar valores al usuario mediante el módulo generator/prompter
    const {values, activeBlocks} = await promptForPackage(packageConfig)

    // Renderizar templates con Handlebars
    const generatedFiles = renderPackage(packageConfig, templates, values, activeBlocks)

    // Escribir archivos generados en .osdo/generated/<timestamp>/
    const outputDir = join(process.cwd(), '.osdo', 'generated', String(Date.now()))
    mkdirSync(outputDir, {recursive: true})

    const writtenPaths: string[] = []
    this.log(chalk.bold('Archivos generados:'))

    for (const genFile of generatedFiles) {
      const filePath = join(outputDir, genFile.file)
      mkdirSync(dirname(filePath), {recursive: true})
      writeFileSync(filePath, genFile.content, 'utf8')
      writtenPaths.push(filePath)
      this.log(`  ${chalk.dim('→')} ${chalk.cyan(genFile.file)}  ${chalk.dim(`[${genFile.language}]`)}`)
    }

    if (this.configManager.isDryRun()) {
      this.log(chalk.yellow('\n[dry-run] Archivos generados pero no desplegados.'))
      this.log(`  Directorio de salida: ${chalk.dim(outputDir)}`)
      return
    }

    // Aplicar archivos generados
    this.log(chalk.bold('\nAplicando archivos generados...'))
    let anyFailed = false

    for (const filePath of writtenPaths) {
      const relPath = filePath.replace(outputDir + '/', '')
      this.log(`  ${chalk.dim('→')} Aplicando ${chalk.cyan(relPath)}...`)
      try {
        await this.applyGeneratedFile(filePath, platform, namespace)
        this.log(`  ${chalk.green('✅')} ${chalk.cyan(relPath)}`)
      } catch (err: unknown) {
        const msg = err instanceof Error ? err.message : String(err)
        this.log(`  ${chalk.red('❌')} ${chalk.cyan(relPath)}: ${msg}`)
        anyFailed = true
      }
    }

    if (anyFailed) {
      this.error(`Algunos archivos del paquete no pudieron desplegarse.`, {exit: 1})
    }

    this.log(chalk.green(`\n✓ Paquete "${packageConfig.name}" desplegado correctamente.`))
    this.log(`  Archivos generados en: ${chalk.dim(outputDir)}`)
  }

  private async applyGeneratedFile(filePath: string, platform: Platform, namespace: string): Promise<void> {
    const isYaml = filePath.endsWith('.yaml') || filePath.endsWith('.yml')

    switch (platform) {
      case 'kubernetes':
      case 'k3s': {
        if (isYaml) {
          try {
            await execa('kubectl', ['create', 'namespace', namespace, ...this.buildKubeconfigArgs()])
          } catch {
            // Namespace ya existe
          }

          await execa('kubectl', [
            'apply', '-f', filePath,
            '-n', namespace,
            ...this.buildKubeconfigArgs(),
          ])
        }

        break
      }

      case 'docker-compose': {
        if (isYaml) {
          await execa('docker', ['compose', '-f', filePath, 'up', '-d'])
        }

        break
      }

      case 'helm': {
        // Para paquetes tipo infrastructure renderizados como values, informar al usuario
        this.log(`  ${chalk.yellow('Helm:')} aplica el archivo manualmente:`)
        this.log(`  helm upgrade --install mi-release <chart> -f ${filePath}`)
        break
      }
    }
  }

  // ── Utilidades ────────────────────────────────────────────────────────────

  private buildKubeconfigArgs(): string[] {
    const kc = this.configManager.getKubeconfig()
    return kc ? ['--kubeconfig', kc] : []
  }
}
