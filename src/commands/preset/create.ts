import {Args} from '@oclif/core'
import {input, select, confirm, checkbox} from '@inquirer/prompts'
import chalk from 'chalk'
import {BaseCommand} from '../../lib/base-command.js'
import {VALID_COMPONENT_NAMES} from '../../lib/infra-catalog.js'
import type {Platform, PresetConfig} from '../../lib/config/types.js'

const PLATFORMS: Platform[] = ['kubernetes', 'k3s', 'docker-compose', 'docker-swarm', 'helm']

/**
 * Preset Create — Asistente interactivo para crear un nuevo preset de configuración.
 *
 * Porta la lógica de createPreset() en cmd/preset.go con @inquirer/prompts.
 * Los presets se persisten en ~/.config/osdo/config.json mediante ConfigManager.
 *
 * El asistente recoge:
 *   - Descripción del preset
 *   - Plataforma de despliegue
 *   - Componentes a incluir (checkbox)
 *   - Namespace de destino
 *   - Timeout en segundos
 *   - Si debe usar dry-run por defecto
 */
export default class PresetCreate extends BaseCommand {
  static description = 'Crear un nuevo preset de configuración de forma interactiva'

  static examples = [
    '<%= config.bin %> preset create my-preset',
    '<%= config.bin %> preset create production',
    '<%= config.bin %> preset create dev-stack',
    '<%= config.bin %> preset create security-suite --dry-run',
  ]

  static args = {
    name: Args.string({
      description: 'Nombre del nuevo preset',
      required: true,
    }),
  }

  static flags = {
    ...BaseCommand.globalFlags,
  }

  async run(): Promise<void> {
    const {args} = await this.parse(PresetCreate)

    const presetName = args.name

    // Verificar si el preset ya existe
    const existing = this.configManager.getPresets()
    if (existing.some(p => p.name === presetName)) {
      this.error(
        `El preset "${presetName}" ya existe.\n` +
          "Usa 'osdo preset list' para ver los presets existentes o elige un nombre diferente.",
        {exit: 1},
      )
    }

    this.log(chalk.bold(`\nCreando preset: ${chalk.cyan(presetName)}`))
    this.log('══════════════════════════════════════════════════════════════\n')

    // Descripción
    const description = await input({
      message: 'Descripción del preset (opcional):',
      default: '',
    })

    // Plataforma
    const defaultPlatform = this.configManager.getDefaultPlatform()
    const platform = await select<Platform>({
      message: 'Plataforma de despliegue:',
      choices: PLATFORMS.map(p => ({
        name: p === defaultPlatform ? `${p}  ${chalk.dim('(actual)')}` : p,
        value: p,
      })),
      default: defaultPlatform,
    })

    // Componentes (checkbox con todos los del catálogo de infraestructura)
    const components = await checkbox({
      message: 'Componentes a incluir en este preset (Espacio = marcar):',
      choices: VALID_COMPONENT_NAMES.map(c => ({
        name: c,
        value: c,
      })),
      pageSize: 15,
    })

    // Namespace
    const namespace = await input({
      message: 'Namespace de Kubernetes:',
      default: 'osdo',
    })

    // Timeout
    const timeoutStr = await input({
      message: 'Timeout para el despliegue (segundos):',
      default: '600',
      validate: (val: string) => {
        const n = Number.parseInt(val, 10)
        if (Number.isNaN(n) || n <= 0) return 'Introduce un número positivo'
        return true
      },
    })

    const timeout = Number.parseInt(timeoutStr, 10)
    const resolvedTimeout = Number.isNaN(timeout) || timeout <= 0 ? 600 : timeout

    // Dry-run por defecto
    const dryRunDefault = await confirm({
      message: '¿Habilitar modo dry-run por defecto en este preset?',
      default: false,
    })

    // Construir el preset
    const preset: PresetConfig = {
      name: presetName,
      description,
      platform,
      components,
      namespace,
      timeout: resolvedTimeout,
      dryRun: dryRunDefault,
    }

    // Modo dry-run del comando: mostrar sin guardar
    if (this.configManager.isDryRun()) {
      this.log('\n[dry-run] Preset que se crearía:')
      this.log(JSON.stringify(preset, null, 2))
      return
    }

    // Guardar preset
    this.configManager.savePreset(preset)

    // Confirmación
    this.log(chalk.green(`\n✓ Preset "${chalk.bold(presetName)}" creado correctamente.\n`))
    this.log(`  Plataforma:   ${chalk.cyan(platform)}`)
    this.log(`  Componentes:  ${components.length > 0 ? chalk.cyan(components.join(', ')) : chalk.dim('(ninguno)')}`)
    this.log(`  Namespace:    ${chalk.cyan(namespace)}`)
    this.log(`  Timeout:      ${resolvedTimeout}s`)
    this.log(`  Dry-run:      ${dryRunDefault ? chalk.yellow('sí') : 'no'}`)
    this.log('')
    this.log(`Uso: ${chalk.cyan(`osdo deploy --preset ${presetName}`)}`)
    this.log('')
  }
}
