import {Flags} from '@oclif/core'
import {input, password} from '@inquirer/prompts'
import axios from 'axios'
import {BaseCommand} from '../../lib/base-command.js'

export default class AppLogin extends BaseCommand {
  static description = 'Autenticarse con la OSDO App'

  static examples = [
    '<%= config.bin %> app login --url https://app.opensecdevops.com',
    '<%= config.bin %> app login',
  ]

  static flags = {
    ...BaseCommand.globalFlags,
    url: Flags.string({
      description: 'URL de la OSDO App',
      env: 'OSDO_APP_URL',
    }),
    email: Flags.string({
      description: 'Email del usuario',
      env: 'OSDO_APP_EMAIL',
    }),
  }

  async run(): Promise<void> {
    const {flags} = await this.parse(AppLogin)

    const appUrl = flags.url
      || this.configManager.getAppUrl()
      || await input({message: 'URL de la OSDO App:'})

    if (!appUrl) {
      this.error('Se requiere la URL de la OSDO App. Usa --url o OSDO_APP_URL', {exit: 1})
    }

    const email = flags.email || await input({message: 'Email:'})
    const pass = await password({message: 'Contraseña:', mask: '*'})

    this.log(`\nConectando a ${appUrl}...`)

    try {
      const response = await axios.post<{token: string}>(`${appUrl}/api/cli/auth`, {
        email,
        password: pass,
      }, {
        timeout: 30_000,
        headers: {'Content-Type': 'application/json', 'Accept': 'application/json'},
      })

      if (!response.data.token) {
        this.error('La App no devolvió un token válido', {exit: 1})
      }

      this.configManager.setAppUrl(appUrl)
      this.configManager.setAppToken(response.data.token)

      this.log(`\n✅ Autenticado correctamente en ${appUrl}`)
      if (this.configManager.isVerbose()) {
        this.log(`   Token guardado en: ~/.config/osdo/config.json`)
      }
    } catch (error) {
      if (axios.isAxiosError(error)) {
        if (error.response?.status === 401) {
          this.error('Credenciales incorrectas. Verifica tu email y contraseña.', {exit: 1})
        } else if (error.response?.status === 422) {
          this.error('Datos de login inválidos. Verifica el formato del email.', {exit: 1})
        } else if (error.code === 'ECONNREFUSED' || error.code === 'ENOTFOUND') {
          this.error(`No se puede conectar a ${appUrl}. Verifica que la URL sea correcta.`, {exit: 1})
        }
      }

      this.error(`Error de autenticación: ${error instanceof Error ? error.message : 'Error desconocido'}`, {exit: 1})
    }
  }
}
