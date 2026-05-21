import {Args, Flags} from '@oclif/core'
import {confirm, select} from '@inquirer/prompts'
import chalk from 'chalk'
import {BaseCommand} from '../../lib/base-command.js'
import {findInfraItem, CATEGORY_LABELS} from '../../lib/infra-catalog.js'
import type {Platform} from '../../lib/config/types.js'

const PLATFORMS: Platform[] = ['kubernetes', 'k3s', 'docker-compose', 'docker-swarm', 'helm']

/**
 * Catalog Add — Agrega un componente del catálogo al entorno actual
 * ejecutando `osdo deploy --components <nombre>` con confirmación previa.
 *
 * Equivale a la acción de "add" del catálogo en cmd/catalog.go, adaptada
 * para el catálogo de infraestructura DevSecOps de OSDO v2.
 */
export default class CatalogAdd extends BaseCommand {
  static description = 'Desplegar un componente del catálogo directamente en el entorno actual'

  static examples = [
    '<%= config.bin %> catalog add prometheus',
    '<%= config.bin %> catalog add vault --platform helm --namespace security',
    '<%= config.bin %> catalog add grafana --namespace monitoring',
  ]

  static args = {
    name: Args.string({
      description: 'Nombre del componente a desplegar',
      required: true,
    }),
  }

  static flags = {
    ...BaseCommand.globalFlags,

    platform: Flags.string({
      char: 'p',
      description: 'Plataforma de despliegue (por defecto: configuración actual)',
      options: PLATFORMS,
    }),

    namespace: Flags.string({
      char: 'n',
      description: 'Namespace de destino',
      default: 'osdo',
    }),
  }

  async run(): Promise<void> {
    const {args, flags} = await this.parse(CatalogAdd)

    // Verificar que el componente existe en el catálogo
    const item = findInfraItem(args.name)

    if (!item) {
      this.error(
        `Componente no encontrado: "${args.name}"\n` +
          "Usa 'osdo catalog list' para ver los componentes disponibles.",
        {exit: 1},
      )
    }

    const categoryLabel = CATEGORY_LABELS[item.category]

    // Mostrar resumen del componente
    this.log('')
    this.log(chalk.bold(`Componente: ${chalk.cyan(item.name)}`))
    this.log('─────────────────────────────────────────────────────────────')
    this.log(`  Descripción: ${item.description}`)
    this.log(`  Categoría:   ${categoryLabel}`)
    this.log(`  Chart Helm:  ${chalk.dim(item.chart)}`)
    this.log(`  Versión:     ${item.version}`)
    this.log('')

    // Determinar plataforma
    let platform: Platform

    if (flags.platform) {
      platform = flags.platform as Platform
    } else {
      // Preguntar si no se especificó
      const defaultPlatform = this.configManager.getDefaultPlatform()
      platform = await select<Platform>({
        message: 'Selecciona la plataforma de despliegue:',
        choices: PLATFORMS.map(p => ({
          name: p === defaultPlatform ? `${p}  ${chalk.dim('(por defecto)')}` : p,
          value: p,
        })),
        default: defaultPlatform,
      })
    }

    const namespace = flags.namespace ?? 'osdo'

    this.log(`  Plataforma:  ${chalk.cyan(platform)}`)
    this.log(`  Namespace:   ${chalk.cyan(namespace)}`)
    this.log('')

    if (flags['dry-run']) {
      this.log(chalk.yellow(`[dry-run] Ejecutaría: osdo deploy --components ${item.name} --platform ${platform} --namespace ${namespace}`))
      return
    }

    // Confirmación interactiva
    const ok = await confirm({
      message: `¿Desplegar ${chalk.bold(item.name)} en ${chalk.cyan(platform)}/${chalk.cyan(namespace)}?`,
      default: true,
    })

    if (!ok) {
      this.log('Operación cancelada.')
      return
    }

    this.log('')
    this.log(chalk.bold(`Lanzando despliegue de ${chalk.cyan(item.name)}...`))
    this.log('')

    // Delegar al comando deploy
    await this.config.runCommand('deploy', [
      '--components', item.name,
      '--platform', platform,
      '--namespace', namespace,
    ])
  }
}
