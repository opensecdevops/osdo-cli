import {Args, Flags} from '@oclif/core'
import {select} from '@inquirer/prompts'
import {BaseCommand} from '../../lib/base-command.js'
import {AppApiClient} from '../../lib/api/client.js'
import {getDefaultActiveBlocks, renderPackage} from '../../lib/generator/handlebars.js'
import {promptForPackage} from '../../lib/generator/prompter.js'
import {writeGeneratedFiles} from '../../lib/generator/writer.js'
import chalk from 'chalk'

/**
 * AppPull — Descarga un paquete de la OSDO App, solicita los valores de
 * configuración interactivamente y renderiza los templates Handlebars al disco.
 *
 * Flujo:
 *   1. GET /api/cli/packages — listar paquetes del usuario
 *   2. GET /api/cli/packages/:id — obtener config.json + templates
 *   3. promptForPackage() — prompts interactivos por bloque/campo
 *   4. renderPackage() — renderizar Handlebars con los valores elegidos
 *   5. writeGeneratedFiles() — escribir archivos al directorio destino
 *   6. POST /api/cli/deployments — registrar deployment como "pending"
 */
export default class AppPull extends BaseCommand {
  static description = 'Descargar y renderizar un paquete generado por la OSDO App'
  static examples = [
    '<%= config.bin %> app pull',
    '<%= config.bin %> app pull 42',
    '<%= config.bin %> app pull 42 --dir ./infra',
    '<%= config.bin %> app pull --overwrite',
  ]

  static args = {
    packageId: Args.string({description: 'ID del paquete a descargar (opcional — se lista interactivamente)'}),
  }

  static flags = {
    ...BaseCommand.globalFlags,
    dir: Flags.string({
      char: 'd',
      description: 'Directorio de destino para los archivos generados',
      default: '.',
    }),
    overwrite: Flags.boolean({
      default: false,
      description: 'Sobreescribir archivos existentes sin preguntar',
    }),
    'skip-prompts': Flags.boolean({
      default: false,
      description: 'Usar valores por defecto de todos los campos (útil en CI)',
    }),
    'create-deployment': Flags.boolean({
      default: true,
      description: 'Registrar un deployment "pending" en la App',
      allowNo: true,
    }),
  }

  async run(): Promise<void> {
    const {args, flags} = await this.parse(AppPull)

    if (!this.configManager.isAppAuthenticated()) {
      this.error('No autenticado. Ejecuta: osdo app login', {exit: 1})
    }

    const client = new AppApiClient(
      this.configManager.getAppUrl(),
      this.configManager.getAppToken(),
    )

    // 1. Seleccionar paquete
    let packageId = args.packageId
    if (!packageId) {
      const packages = await client.packages.list()
      if (packages.length === 0) {
        this.error('No tienes paquetes disponibles en la App.', {exit: 1})
      }
      packageId = await select({
        message: 'Selecciona el paquete a descargar:',
        choices: packages.map((p) => ({
          name: `[${p.id}] ${p.name} — ${p.type === 1 ? 'Infraestructura' : 'CI/CD'}${p.version ? ` v${p.version}` : ''}`,
          value: String(p.id),
        })),
      })
    }

    // 2. Obtener detalle del paquete (config + templates)
    this.log(`\nCargando paquete #${packageId}...`)
    const detail = await client.packages.get(packageId)

    this.log(chalk.bold(`\n📦 ${detail.name}`))
    if (detail.description) this.log(`   ${detail.description}`)
    this.log(`   Tipo: ${detail.type === 1 ? 'Infraestructura' : 'CI/CD'}`)
    this.log(`   Bloques: ${detail.form.blocks.length} | Archivos: ${detail.templates.length}\n`)

    if (this.dryRun(`Renderizar paquete #${packageId} → ${flags.dir}`)) return

    // 3. Prompts interactivos (o usar defaults en modo CI)
    let values: Record<string, unknown>
    let activeBlocks: Set<string>

    if (flags['skip-prompts']) {
      activeBlocks = getDefaultActiveBlocks(detail.form.blocks)
      values = {}
      for (const block of detail.form.blocks) {
        for (const field of block.fields) {
          if (field.default !== undefined) values[field.name] = field.default
        }
      }
    } else {
      const answers = await promptForPackage(detail.form)
      values = answers.values
      activeBlocks = answers.activeBlocks
    }

    // 4. Renderizar templates con Handlebars
    this.log('\nRenderizando templates...')
    const generatedFiles = renderPackage(detail.form, detail.templates, values, activeBlocks)

    // 5. Escribir archivos al disco
    this.log(`Escribiendo ${generatedFiles.length} archivo(s) en ${flags.dir}/\n`)
    await writeGeneratedFiles(generatedFiles, flags.dir, {
      overwrite: flags.overwrite,
      dryRun: false,
      log: (msg) => this.log(msg),
    })

    // 6. Registrar deployment "pending" en la App
    if (flags['create-deployment'] && detail.version) {
      try {
        // package_version_id es el último dígito si el detail tiene version_id, si no usamos packageId
        const versionId = (detail as unknown as {version_id?: number}).version_id
        if (versionId) {
          const deployment = await client.deployments.create({
            package_version_id: versionId,
            platform: this.configManager.getDefaultPlatform(),
            metadata: {
              generated_files: generatedFiles.map(f => f.file),
              generated_at: new Date().toISOString(),
            },
          })
          this.log(chalk.dim(`\n  App: deployment #${deployment.id} registrado como "pending"`))
          this.log(chalk.dim(`  Actualiza el estado con: osdo app push --deployment-id ${deployment.id} --status deployed`))
        }
      } catch {
        this.warn('No se pudo registrar el deployment en la App (continúa sin error).')
      }
    }

    this.log(chalk.green(`\n✓ Paquete renderizado correctamente en ${flags.dir}/`))
    this.log(`  Siguiente: osdo deploy${flags.dir !== '.' ? ` --package ${flags.dir}` : ''}`)
  }
}
