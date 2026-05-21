import {BaseCommand} from '../../lib/base-command.js'
import {AppApiClient} from '../../lib/api/client.js'

export default class AppStatus extends BaseCommand {
  static description = 'Ver el estado de la conexión con la OSDO App'
  static examples = ['<%= config.bin %> app status']

  static flags = {
    ...BaseCommand.globalFlags,
  }

  async run(): Promise<void> {
    const appUrl = this.configManager.getAppUrl()
    const isAuth = this.configManager.isAppAuthenticated()

    if (!appUrl || !isAuth) {
      this.log('Estado: No conectado')
      this.log('Ejecuta "osdo app login" para conectarte a la OSDO App.')
      return
    }

    this.log(`URL de la App: ${appUrl}`)
    this.log('Verificando conexión...')

    try {
      const client = new AppApiClient(appUrl, this.configManager.getAppToken())
      const packages = await client.packages.list()
      this.log(`✓ Conectado correctamente`)
      this.log(`  Paquetes disponibles: ${packages.length}`)
    } catch (err: unknown) {
      const message = err instanceof Error ? err.message : String(err)
      this.warn(`Error de conexión: ${message}`)
      this.log('El token puede haber expirado. Ejecuta "osdo app login" de nuevo.')
    }
  }
}
