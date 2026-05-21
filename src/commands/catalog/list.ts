import {Flags} from '@oclif/core'
import Table from 'cli-table3'
import chalk from 'chalk'
import {BaseCommand} from '../../lib/base-command.js'
import {
  INFRA_CATALOG,
  CATEGORY_LABELS,
  type InfraCategory,
} from '../../lib/infra-catalog.js'

const ALL_CATEGORIES: InfraCategory[] = ['monitoring', 'security', 'cicd']

/**
 * Catalog List — Lista los componentes de infraestructura disponibles en OSDO.
 *
 * Muestra el catálogo de herramientas DevSecOps desplegables, organizado por
 * categoría. Filtrable con --category y con soporte de --output json.
 *
 * Para el catálogo de GitHub Actions/Workflows, usa la funcionalidad original
 * integrada en los pipelines de seguridad (osdo pipeline generate).
 */
export default class CatalogList extends BaseCommand {
  static description = 'Listar los componentes de infraestructura DevSecOps disponibles en el catálogo'

  static examples = [
    '<%= config.bin %> catalog list',
    '<%= config.bin %> catalog list --category security',
    '<%= config.bin %> catalog list --category monitoring',
    '<%= config.bin %> catalog list --category cicd',
    '<%= config.bin %> catalog list --output json',
  ]

  static flags = {
    ...BaseCommand.globalFlags,

    category: Flags.string({
      char: 'c',
      description: 'Filtrar por categoría (monitoring, security, cicd)',
      options: ALL_CATEGORIES,
    }),
  }

  async run(): Promise<void> {
    const {flags} = await this.parse(CatalogList)

    const categoriesToShow = flags.category
      ? [flags.category as InfraCategory]
      : ALL_CATEGORIES

    const items = INFRA_CATALOG.filter(i => categoriesToShow.includes(i.category))

    // Salida JSON
    if (flags.output === 'json') {
      const grouped: Record<string, typeof items> = {}
      for (const cat of categoriesToShow) {
        grouped[cat] = items.filter(i => i.category === cat)
      }

      this.log(JSON.stringify(grouped, null, 2))
      return
    }

    // Cabecera
    this.log(chalk.bold('\nCatálogo de Infraestructura OSDO'))
    this.log('═══════════════════════════════════════════════════════════════')
    this.log('  Componentes DevSecOps desplegables con "osdo deploy"')
    this.log('')

    let total = 0

    for (const cat of categoriesToShow) {
      const catItems = items.filter(i => i.category === cat)
      if (catItems.length === 0) continue

      const label = CATEGORY_LABELS[cat]
      this.log(chalk.bold(`${label} (${catItems.length} componente${catItems.length !== 1 ? 's' : ''})`))
      this.log('─────────────────────────────────────────────────────────────')

      const table = new Table({
        head: ['Nombre', 'Descripción', 'Chart Helm', 'Versión'],
        colWidths: [22, 44, 44, 10],
        wordWrap: true,
        style: {head: ['cyan']},
      })

      for (const item of catItems) {
        table.push([
          chalk.bold(item.name),
          item.description,
          chalk.dim(item.chart),
          item.version,
        ])
      }

      this.log(table.toString())
      this.log('')
      total += catItems.length
    }

    // Pie de página
    this.log(`Total: ${chalk.bold(String(total))} componente${total !== 1 ? 's' : ''} disponible${total !== 1 ? 's' : ''}`)
    this.log('')
    this.log(`  ${chalk.cyan('osdo catalog describe <nombre>')}  — Ver detalles e instrucciones de instalación`)
    this.log(`  ${chalk.cyan('osdo catalog add <nombre>')}        — Desplegar un componente directamente`)
    this.log(`  ${chalk.cyan('osdo deploy --interactive')}        — Selector visual de componentes`)
    this.log('')
  }
}
