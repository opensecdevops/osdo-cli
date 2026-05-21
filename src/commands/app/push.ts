import {Flags} from '@oclif/core'
import {BaseCommand} from '../../lib/base-command.js'
import {AppApiClient} from '../../lib/api/client.js'

export default class AppPush extends BaseCommand {
  static description = 'Enviar estado de deployment a la OSDO App'
  static examples = [
    '<%= config.bin %> app push --deployment-id 1 --status deployed',
    '<%= config.bin %> app push --deployment-id 1 --status failed --message "Error en namespace"',
  ]

  static flags = {
    ...BaseCommand.globalFlags,
    'deployment-id': Flags.string({
      required: true,
      description: 'ID del deployment a actualizar',
    }),
    status: Flags.string({
      required: true,
      options: ['deployed', 'failed', 'pending'],
      description: 'Nuevo estado del deployment',
    }),
    message: Flags.string({
      description: 'Mensaje descriptivo del estado',
    }),
  }

  async run(): Promise<void> {
    const {flags} = await this.parse(AppPush)

    if (!this.configManager.isAppAuthenticated()) {
      this.error('No autenticado. Ejecuta: osdo app login', {exit: 1})
    }

    this.dryRunLog(
        `Actualizar deployment ${flags['deployment-id']} → ${flags.status}`,
      )
    if (this.configManager.isDryRun())
      return

    const client = new AppApiClient(
      this.configManager.getAppUrl(),
      this.configManager.getAppToken(),
    )

    const updated = await client.deployments.updateStatus(flags['deployment-id'], {
      status: flags.status as 'deployed' | 'failed' | 'pending',
      message: flags.message,
    })

    this.log(`✓ Estado actualizado: ${updated.status}`)
    if (updated.message) this.log(`  Mensaje: ${updated.message}`)
  }
}
