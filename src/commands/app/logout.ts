import {confirm} from '@inquirer/prompts'
import {BaseCommand} from '../../lib/base-command.js'

export default class AppLogout extends BaseCommand {
  static description = 'Cerrar sesión de la OSDO App'

  static examples = [
    '<%= config.bin %> app logout',
  ]

  static flags = {
    ...BaseCommand.globalFlags,
  }

  async run(): Promise<void> {
    if (!this.configManager.isAppAuthenticated()) {
      this.log('No hay sesión activa con la OSDO App.')
      return
    }

    const appUrl = this.configManager.getAppUrl()
    const confirmed = await confirm({
      message: `¿Cerrar sesión de ${appUrl}?`,
      default: true,
    })

    if (!confirmed) {
      this.log('Operación cancelada.')
      return
    }

    this.configManager.clearAppAuth()
    this.log('✅ Sesión cerrada correctamente.')
  }
}
