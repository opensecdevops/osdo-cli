import {Flags} from '@oclif/core'
import axios from 'axios'
import chalk from 'chalk'
import {BaseCommand} from '../../lib/base-command.js'

/**
 * MonitorAlerts — Consulta las alertas activas en Alertmanager (/api/v2/alerts).
 *
 * Si Alertmanager no está disponible (ECONNREFUSED) muestra un estado limpio
 * en lugar de fallar, ya que en muchos entornos Alertmanager es opcional.
 *
 * Resolución de URL:
 * 1. Flag --alertmanager-url
 * 2. Variable de entorno OSDO_ALERTMANAGER_URL
 * 3. URL guardada en configuración (osdo monitor setup)
 * 4. Valor por defecto: http://localhost:9093
 */
export default class MonitorAlerts extends BaseCommand {
  static description = 'Consultar alertas activas de Alertmanager'

  static examples = [
    '<%= config.bin %> monitor alerts',
    '<%= config.bin %> monitor alerts --severity critical',
    '<%= config.bin %> monitor alerts --alertmanager-url http://alertmanager:9093 --output json',
  ]

  static flags = {
    ...BaseCommand.globalFlags,
    severity: Flags.string({
      description: 'Filtrar por severidad de alerta',
      options: ['critical', 'warning', 'info'],
    }),
    'alertmanager-url': Flags.string({
      description: 'URL de Alertmanager (sobreescribe la configuración guardada)',
      env: 'OSDO_ALERTMANAGER_URL',
    }),
  }

  async run(): Promise<void> {
    const {flags} = await this.parse(MonitorAlerts)

    // Resolución de URL con fallback progresivo
    const alertmanagerUrl =
      flags['alertmanager-url'] ??
      this.configManager.getMonitoringUrls()?.alertmanagerUrl ??
      'http://localhost:9093'

    this.log(`Consultando Alertmanager en ${alertmanagerUrl}...`)

    try {
      // Llamada real a la API v2 de Alertmanager
      const response = await axios.get(`${alertmanagerUrl}/api/v2/alerts`, {
        params: flags.severity ? {filter: `severity="${flags.severity}"`} : undefined,
        timeout: 10_000,
      })

      const alerts = response.data as Array<{
        labels: Record<string, string>
        annotations: {summary?: string; description?: string}
        status: {state: string}
        startsAt: string
      }>

      // Salida JSON si se solicita
      if (flags.output === 'json') {
        this.log(JSON.stringify(alerts, null, 2))
        return
      }

      if (alerts.length === 0) {
        this.log(chalk.green('✓ No hay alertas activas.'))
        return
      }

      this.log(`\n${chalk.red('⚠')} ${alerts.length} alerta(s) activa(s):\n`)

      for (const alert of alerts) {
        const severity = alert.labels.severity ?? 'unknown'
        const name = alert.labels.alertname ?? 'Alerta desconocida'
        const summary = alert.annotations.summary ?? 'Sin descripción'
        const color =
          severity === 'critical' ? chalk.red :
          severity === 'warning'  ? chalk.yellow :
          chalk.blue

        this.log(color(`  ● ${name} [${severity.toUpperCase()}]`))
        this.log(`    ${summary}`)
        this.log(`    Desde: ${new Date(alert.startsAt).toLocaleString('es-ES')}\n`)
      }
    } catch (err: unknown) {
      const message = err instanceof Error ? err.message : String(err)

      // Degradar gracefully si Alertmanager no está disponible
      if (message.includes('ECONNREFUSED')) {
        this.warn(`Alertmanager no disponible en ${alertmanagerUrl}. Mostrando estado sin alertas.`)
        this.log(chalk.green('✓ No hay alertas activas (Alertmanager no conectado).'))
        return
      }

      this.error(`Error consultando alertas: ${message}`, {exit: 1})
    }
  }
}
