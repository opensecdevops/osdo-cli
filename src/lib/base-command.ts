import {Command, Flags} from '@oclif/core'
import {ConfigManager} from './config/manager.js'

/**
 * BaseCommand — Comando base del que extienden todos los comandos OSDO.
 *
 * Equivale a rootCmd (cobra) con cobra.OnInitialize(initConfig).
 * Inicializa el ConfigManager y expone globalFlags en todos los comandos.
 */
export abstract class BaseCommand extends Command {
  /**
   * Flags globales disponibles en todos los comandos OSDO.
   * Equivalente a rootCmd.PersistentFlags() en el CLI Go.
   */
  static globalFlags = {
    verbose: Flags.boolean({
      char: 'v',
      description: 'Mostrar salida detallada',
      env: 'OSDO_VERBOSE',
      default: false,
    }),
    'dry-run': Flags.boolean({
      description: 'Simular la operación sin ejecutarla realmente',
      env: 'OSDO_DRY_RUN',
      default: false,
    }),
    output: Flags.string({
      char: 'o',
      description: 'Formato de salida',
      options: ['table', 'json', 'yaml'],
      default: 'table',
      env: 'OSDO_OUTPUT',
    }),
    kubeconfig: Flags.string({
      description: 'Ruta al archivo kubeconfig de Kubernetes',
      env: 'KUBECONFIG',
    }),
    config: Flags.string({
      description: 'Ruta al archivo de configuración (por defecto: ~/.config/osdo)',
      env: 'OSDO_CONFIG',
    }),
  }

  protected configManager!: ConfigManager

  /**
   * Equivale a cobra.OnInitialize(initConfig) en root.go.
   * Se ejecuta antes del método run() de cada comando.
   */
  async init(): Promise<void> {
    await super.init()
    this.configManager = new ConfigManager()
    await this.configManager.load()

    // Aplicar flags globales al ConfigManager
    // Prioridad: flags CLI > env vars > config file > defaults
    const {flags} = await this.parse(this.constructor as typeof Command)
    if (flags.verbose) this.configManager.setVerbose(true)
    if (flags['dry-run']) this.configManager.setDryRun(true)
    if (flags.output) this.configManager.setOutput(flags.output)
    if (flags.kubeconfig) this.configManager.setKubeconfig(flags.kubeconfig as string)
  }

  async catch(error: Error): Promise<void> {
    this.error(error.message, {exit: 1})
  }

  /**
   * Verificar autenticación con OSDO App.
   * Degrada gracefully a modo standalone si no hay token.
   */
  protected checkAppAuth(required = false): boolean {
    if (this.configManager.isAppAuthenticated()) {
      return true
    }

    if (required) {
      this.error('No autenticado con la OSDO App. Ejecuta: osdo app login', {exit: 3})
    }

    this.warn('No conectado a la OSDO App — operando en modo standalone.\nEjecuta "osdo app login" para habilitar la integración.')
    return false
  }

  /**
   * Helper para modo dry-run — log y salir sin ejecutar.
   */
  protected dryRunLog(action: string): void {
    if (this.configManager.isDryRun()) {
      this.log(`[dry-run] ${action}`)
    }
  }

  /**
   * Helper para modo dry-run con retorno booleano.
   * Útil en comandos que deben salir temprano si se activa --dry-run.
   *
   * @returns true si se está en modo dry-run (el caller debe hacer return)
   */
  protected dryRun(action: string): boolean {
    if (this.configManager.isDryRun()) {
      this.log(`[dry-run] ${action}`)
      return true
    }
    return false
  }
}
