import {Flags} from '@oclif/core'
import axios from 'axios'
import chalk from 'chalk'
import {BaseCommand} from '../../lib/base-command.js'

interface HealthEndpoint {
  name: string
  url: string
  healthPath: string
  expectedStatus: number
  credentials?: {user: string; pass: string}
}

const DEFAULT_HEALTH_ENDPOINTS: HealthEndpoint[] = [
  {name: 'Prometheus',    url: 'http://localhost:9090', healthPath: '/-/healthy',            expectedStatus: 200},
  {name: 'Grafana',       url: 'http://localhost:3000', healthPath: '/api/health',            expectedStatus: 200},
  {name: 'Alertmanager',  url: 'http://localhost:9093', healthPath: '/-/healthy',            expectedStatus: 200},
  {name: 'Jaeger',        url: 'http://localhost:16686', healthPath: '/api/services',         expectedStatus: 200},
  {name: 'Vault',         url: 'http://localhost:8200',  healthPath: '/v1/sys/health',        expectedStatus: 200},
  {name: 'SonarQube',     url: 'http://localhost:9000',  healthPath: '/api/system/status',   expectedStatus: 200},
  {name: 'Trivy',         url: 'http://localhost:4954',  healthPath: '/healthz',              expectedStatus: 200},
]

interface HealthResult {
  name: string
  url: string
  status: 'healthy' | 'degraded' | 'unreachable' | 'disabled'
  responseTimeMs?: number
  message?: string
  version?: string
}

export default class MonitorHealth extends BaseCommand {
  static description = 'Verificar el estado de salud de los componentes OSDO desplegados'

  static examples = [
    '<%= config.bin %> monitor health',
    '<%= config.bin %> monitor health --components prometheus,grafana,vault',
    '<%= config.bin %> monitor health --format json',
    '<%= config.bin %> monitor health --timeout 5000',
  ]

  static flags = {
    ...BaseCommand.globalFlags,
    components: Flags.string({
      char: 'c',
      description: 'Componentes a verificar (separados por coma). Defecto: todos',
      helpValue: 'prometheus,grafana,vault',
    }),
    format: Flags.string({
      options: ['table', 'json'],
      default: 'table',
      description: 'Formato de salida',
    }),
    timeout: Flags.integer({
      default: 5000,
      description: 'Timeout por request en ms',
    }),
    'fail-on-unhealthy': Flags.boolean({
      default: false,
      description: 'Salir con código 1 si algún componente no está healthy',
    }),
  }

  async run(): Promise<void> {
    const {flags} = await this.parse(MonitorHealth)

    // Construir lista de endpoints a verificar
    const monitoringUrls = this.configManager.getMonitoringUrls?.() ?? {}
    const endpoints = this.buildEndpoints(flags.components, monitoringUrls)

    if (flags.format === 'table') {
      this.log(chalk.bold('\nEstado de componentes OSDO\n'))
      this.log('─'.repeat(70))
    }

    // Verificar todos en paralelo
    const results = await Promise.all(
      endpoints.map(ep => this.checkHealth(ep, flags.timeout)),
    )

    if (flags.format === 'json') {
      this.log(JSON.stringify(results, null, 2))
      return
    }

    // Renderizar tabla
    let unhealthyCount = 0
    for (const r of results) {
      const icon = r.status === 'healthy' ? chalk.green('✅') :
                   r.status === 'degraded' ? chalk.yellow('⚠️ ') :
                   r.status === 'disabled' ? chalk.gray('⬜') :
                   chalk.red('❌')

      const statusLabel =
        r.status === 'healthy'     ? chalk.green('Healthy') :
        r.status === 'degraded'    ? chalk.yellow('Degraded') :
        r.status === 'disabled'    ? chalk.gray('Deshabilitado') :
        chalk.red('No disponible')

      const timing = r.responseTimeMs !== undefined
        ? chalk.dim(` (${r.responseTimeMs}ms)`)
        : ''

      const msg = r.message ? chalk.dim(` — ${r.message}`) : ''

      this.log(`  ${icon}  ${r.name.padEnd(18)} ${statusLabel}${timing}${msg}`)

      if (r.status !== 'healthy' && r.status !== 'disabled') unhealthyCount++
    }

    this.log('─'.repeat(70))

    const healthyCount = results.filter(r => r.status === 'healthy').length
    const disabledCount = results.filter(r => r.status === 'disabled').length

    this.log(`\n  ${chalk.green(`${healthyCount} healthy`)}  |  ${chalk.gray(`${disabledCount} deshabilitados`)}  |  ${chalk.red(`${unhealthyCount} con problemas`)}`)
    this.log('')

    if (unhealthyCount > 0 && flags['fail-on-unhealthy']) {
      this.error(
        `${unhealthyCount} componente(s) no disponibles. Ejecuta 'osdo deploy' para desplegarlos.`,
        {exit: 1},
      )
    }

    if (unhealthyCount > 0) {
      this.log(chalk.dim('  💡 Tip: ejecuta osdo deploy --interactive para desplegar componentes faltantes'))
    }
  }

  private buildEndpoints(
    componentFilter: string | undefined,
    configUrls: Record<string, string>,
  ): HealthEndpoint[] {
    // Override URLs desde configuración guardada
    const endpoints = DEFAULT_HEALTH_ENDPOINTS.map(ep => {
      const key = ep.name.toLowerCase().replace(/\s/g, '')
      const configUrl = configUrls[key] ?? configUrls[`${key}-url`]
      return configUrl ? {...ep, url: configUrl} : ep
    })

    if (!componentFilter) return endpoints

    const filter = new Set(componentFilter.toLowerCase().split(',').map(s => s.trim()))
    return endpoints.filter(ep =>
      filter.has(ep.name.toLowerCase()) || filter.has(ep.name.toLowerCase().replace(/\s/g, '')),
    )
  }

  private async checkHealth(ep: HealthEndpoint, timeoutMs: number): Promise<HealthResult> {
    const start = Date.now()
    const fullUrl = `${ep.url}${ep.healthPath}`

    try {
      const response = await axios.get(fullUrl, {
        timeout: timeoutMs,
        validateStatus: () => true,  // No lanzar en 4xx/5xx
        auth: ep.credentials ? {username: ep.credentials.user, password: ep.credentials.pass} : undefined,
        headers: {'User-Agent': 'osdo-cli/2.0'},
      })

      const responseTimeMs = Date.now() - start

      if (response.status === ep.expectedStatus || response.status === 200) {
        // Extraer versión si está disponible
        const version = response.data?.version ?? response.data?.version_info?.version ?? undefined
        return {
          name: ep.name,
          url: ep.url,
          status: 'healthy',
          responseTimeMs,
          version: typeof version === 'string' ? version : undefined,
        }
      }

      return {
        name: ep.name,
        url: ep.url,
        status: 'degraded',
        responseTimeMs,
        message: `HTTP ${response.status}`,
      }
    } catch (err: unknown) {
      const isTimeout = err instanceof Error && err.message.includes('timeout')
      const isRefused = err instanceof Error && (
        err.message.includes('ECONNREFUSED') || err.message.includes('ENOTFOUND')
      )

      if (isRefused) {
        return {name: ep.name, url: ep.url, status: 'disabled', message: 'No desplegado'}
      }

      if (isTimeout) {
        return {name: ep.name, url: ep.url, status: 'unreachable', message: `Timeout (>${timeoutMs}ms)`}
      }

      const msg = err instanceof Error ? err.message.slice(0, 60) : 'Error desconocido'
      return {name: ep.name, url: ep.url, status: 'unreachable', message: msg}
    }
  }
}
