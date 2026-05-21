import Table from 'cli-table3'
import chalk from 'chalk'
import {BaseCommand} from '../../lib/base-command.js'

/**
 * Preset List — Lista todos los presets de configuración guardados.
 *
 * Porta la lógica de listPresets() en cmd/preset.go.
 * Los presets se almacenan en la configuración del usuario (~/.config/osdo)
 * mediante ConfigManager y contienen plataforma, componentes, namespace y timeout.
 */
export default class PresetList extends BaseCommand {
  static description = 'Listar los presets de configuración guardados'

  static examples = [
    '<%= config.bin %> preset list',
    '<%= config.bin %> preset list --output json',
  ]

  static flags = {
    ...BaseCommand.globalFlags,
  }

  async run(): Promise<void> {
    const {flags} = await this.parse(PresetList)

    const presets = this.configManager.getPresets()

    // Salida JSON
    if (flags.output === 'json') {
      this.log(JSON.stringify(presets, null, 2))
      return
    }

    this.log(chalk.bold('\nPresets de Configuración OSDO'))
    this.log('══════════════════════════════════════════════════════════════\n')

    if (presets.length === 0) {
      this.warn('No hay presets configurados.')
      this.log(`\n  Usa ${chalk.cyan("'osdo preset create <nombre>'")} para crear el primer preset.`)
      this.log(`  Ejemplo: osdo preset create production\n`)
      return
    }

    const table = new Table({
      head: ['Nombre', 'Descripción', 'Plataforma', 'Componentes', 'Namespace', 'Timeout'],
      colWidths: [20, 32, 16, 42, 20, 10],
      wordWrap: true,
      style: {head: ['cyan']},
    })

    for (const preset of presets) {
      const componentList = preset.components.length > 0
        ? preset.components.join(', ')
        : chalk.dim('(ninguno)')

      table.push([
        chalk.bold(preset.name),
        preset.description || chalk.dim('—'),
        chalk.cyan(preset.platform),
        componentList,
        preset.namespace || chalk.dim('—'),
        `${preset.timeout}s`,
      ])
    }

    this.log(table.toString())
    this.log(`\nTotal: ${chalk.bold(String(presets.length))} preset${presets.length !== 1 ? 's' : ''}`)
    this.log('')
    this.log(`  ${chalk.cyan('osdo preset show <nombre>')}    — Ver detalles de un preset`)
    this.log(`  ${chalk.cyan('osdo deploy --preset <nombre>')} — Desplegar usando un preset`)
    this.log('')
  }
}
