import {Flags} from '@oclif/core'
import axios from 'axios'
import {BaseCommand} from '../../lib/base-command.js'

/**
 * MonitorMetrics — Consulta la API HTTP de Prometheus (/api/v1/query)
 * y muestra los resultados de la PromQL indicada.
 *
 * La URL de Prometheus se resuelve en el siguiente orden de prioridad:
 * 1. Flag --prometheus-url
 * 2. Variable de entorno OSDO_PROMETHEUS_URL
 * 3. URL guardada en la configuración (osdo monitor setup)
 * 4. Valor por defecto: http://localhost:9090
 */
export default class MonitorMetrics extends BaseCommand {
  static description = 'Consultar métricas reales de Prometheus'

  static examples = [
    '<%= config.bin %> monitor metrics',
    '<%= config.bin %> monitor metrics --query "up" --prometheus-url http://prometheus:9090',
    '<%= config.bin %> monitor metrics --query "rate(http_requests_total[5m])" --output json',
  ]

  static flags = {
    ...BaseCommand.globalFlags,
    query: Flags.string({
      char: 'q',
      description: 'PromQL query a ejecutar',
      default: 'up',
    }),
    'prometheus-url': Flags.string({
      description: 'URL de Prometheus (sobreescribe la configuración guardada)',
      env: 'OSDO_PROMETHEUS_URL',
    }),
  }

  async run(): Promise<void> {
    const {flags} = await this.parse(MonitorMetrics)

    // Resolución de URL con fallback progresivo
    const prometheusUrl =
      flags['prometheus-url'] ??
      this.configManager.getMonitoringUrls()?.prometheusUrl ??
      'http://localhost:9090'

    this.log(`Consultando Prometheus en ${prometheusUrl}...`)

    try {
      // Llamada real a la API v1 de Prometheus
      const response = await axios.get(`${prometheusUrl}/api/v1/query`, {
        params: {query: flags.query},
        timeout: 10_000,
      })

      const {status, data} = response.data as {
        status: string
        data: {
          resultType: string
          result: Array<{
            metric: Record<string, string>
            value: [number, string]
          }>
        }
      }

      if (status !== 'success') {
        this.error(`Prometheus retornó estado: ${status}`, {exit: 1})
      }

      // Salida JSON si se solicita
      if (flags.output === 'json') {
        this.log(JSON.stringify(data, null, 2))
        return
      }

      this.log(`\nResultados para query: ${flags.query}`)
      this.log(`Tipo: ${data.resultType}\n`)

      for (const result of data.result) {
        const labels = Object.entries(result.metric)
          .map(([k, v]) => `${k}="${v}"`)
          .join(', ')
        const [timestamp, value] = result.value
        const date = new Date(timestamp * 1000).toLocaleString('es-ES')
        this.log(`  {${labels}} → ${value} (${date})`)
      }

      if (data.result.length === 0) {
        this.log('  Sin resultados para la query.')
      }
    } catch (err: unknown) {
      const message = err instanceof Error ? err.message : String(err)

      if (message.includes('ECONNREFUSED') || message.includes('timeout')) {
        this.error(
          `No se puede conectar a Prometheus en ${prometheusUrl}. Verifica que está corriendo.`,
          {exit: 1},
        )
      }

      this.error(`Error consultando métricas: ${message}`, {exit: 1})
    }
  }
}
