import {Args} from '@oclif/core'
import Table from 'cli-table3'
import chalk from 'chalk'
import {BaseCommand} from '../../lib/base-command.js'

/**
 * Preset Show — Muestra los detalles completos de un preset específico.
 *
 * Porta la lógica de showPreset() en cmd/preset.go.
 * Incluye todos los campos del preset y el comando de despliegue listo para usar.
 */
export default class PresetShow extends BaseCommand {
  static description = 'Mostrar los detalles completos de un preset de configuración'

  static examples = [
    '<%= config.bin %> preset show production',
    '<%= config.bin %> preset show my-preset --output json',
    '<%= config.bin %> preset show dev-stack',
  ]

  static args = {
    name: Args.string({
      description: 'Nombre del preset',
      required: true,
    }),
  }

  static flags = {
    ...BaseCommand.globalFlags,
  }

  async run(): Promise<void> {
    const {args, flags} = await this.parse(PresetShow)

    const presets = this.configManager.getPresets()
    const preset = presets.find(p => p.name === args.name)

    if (!preset) {
      this.error(
        `Preset "${args.name}" no encontrado.\n` +
          "Usa 'osdo preset list' para ver los presets disponibles.",
        {exit: 1},
      )
    }

    // Salida JSON
    if (flags.output === 'json') {
      this.log(JSON.stringify(preset, null, 2))
      return
    }

    // Cabecera
    this.log('')
    this.log(chalk.bold(`Preset: ${chalk.cyan(preset.name)}`))
    this.log('══════════════════════════════════════════════════════════════\n')

    this.log(`  Descripción:  ${preset.description || chalk.dim('(sin descripción)')}`)
    this.log(`  Plataforma:   ${chalk.cyan(preset.platform)}`)
    this.log(`  Namespace:    ${chalk.cyan(preset.namespace || 'osdo')}`)
    this.log(`  Timeout:      ${preset.timeout}s`)
    this.log(`  Dry-run:      ${preset.dryRun ? chalk.yellow('habilitado') : chalk.dim('deshabilitado')}`)
    this.log('')

    // Tabla de componentes
    if (preset.components.length > 0) {
      this.log(chalk.bold('Componentes incluidos:'))
      this.log('─────────────────────────────────────────────────────────────')

      const table = new Table({
        head: ['#', 'Componente'],
        colWidths: [6, 44],
        style: {head: ['cyan']},
      })

      for (const [i, component] of preset.components.entries()) {
        table.push([(i + 1).toString(), chalk.bold(component)])
      }

      this.log(table.toString())
      this.log('')
    } else {
      this.log(chalk.dim('  Componentes: (ninguno configurado)\n'))
    }

    // Instrucciones de uso
    this.log(chalk.bold('Uso:'))
    this.log('─────────────────────────────────────────────────────────────')
    this.log(`  ${chalk.cyan('osdo deploy')} --preset ${preset.name}`)
    if (preset.dryRun) {
      this.log(`  ${chalk.dim('# Este preset tiene dry-run habilitado por defecto')}`)
    }

    this.log('')
  }
}
