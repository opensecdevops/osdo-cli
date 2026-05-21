import {Flags} from '@oclif/core'
import {execa} from 'execa'
import chalk from 'chalk'
import Table from 'cli-table3'
import yaml from 'js-yaml'
import {BaseCommand} from '../lib/base-command.js'
import type {Platform} from '../lib/config/types.js'

// ── Tipos de respuesta de herramientas externas ──────────────────────────────

interface HelmRelease {
  name: string
  namespace: string
  revision: string
  updated: string
  status: string
  chart: string
  app_version: string
}

interface KubePodContainerStatus {
  name: string
  ready: boolean
  restartCount: number
  image: string
}

interface KubePod {
  metadata: {
    name: string
    namespace: string
    labels?: Record<string, string>
  }
  status: {
    phase: string
    conditions?: Array<{type: string; status: string}>
    containerStatuses?: KubePodContainerStatus[]
    startTime?: string
  }
}

interface KubePodsResponse {
  items: KubePod[]
}

interface DockerComposeService {
  Name: string
  Service: string
  State: string
  Status: string
  Ports?: string
  Health?: string
}

interface DockerSwarmService {
  Name: string
  Replicas: string
  Image: string
  Mode: string
  Ports?: string
}

interface StatusFlags {
  platform?: string
  component?: string
  namespace?: string
  watch?: boolean
  interval?: number
  detailed?: boolean
  'no-color'?: boolean
  output?: string
  verbose?: boolean
  'dry-run'?: boolean
  kubeconfig?: string
  config?: string
}

/**
 * Status — Verifica el estado de los componentes OSDO desplegados.
 *
 * Porta la lógica de cmd/status.go con backends de verificación reales:
 *   kubernetes/k3s/helm → helm list + kubectl get pods (--detailed)
 *   docker-compose      → docker compose ps --format json
 *   docker-swarm        → docker service ls
 *
 * Soporte de --watch para refresco continuo y --output para formatos
 * table/json/yaml (heredado del BaseCommand global --output/-o).
 */
export default class Status extends BaseCommand {
  static description = 'Verificar el estado de los componentes OSDO desplegados'

  static examples = [
    '<%= config.bin %> status',
    '<%= config.bin %> status --platform kubernetes --namespace osdo',
    '<%= config.bin %> status --component prometheus',
    '<%= config.bin %> status --watch --interval 30',
    '<%= config.bin %> status --output json',
    '<%= config.bin %> status --detailed --platform helm',
  ]

  static flags = {
    ...BaseCommand.globalFlags,

    platform: Flags.string({
      char: 'p',
      description: 'Plataforma a verificar',
      options: ['kubernetes', 'k3s', 'docker-compose', 'docker-swarm', 'helm'],
      env: 'OSDO_PLATFORM',
    }),

    component: Flags.string({
      char: 'c',
      description: 'Filtrar por un componente específico',
    }),

    namespace: Flags.string({
      char: 'n',
      description: 'Namespace de Kubernetes a verificar',
      default: 'osdo',
    }),

    watch: Flags.boolean({
      char: 'w',
      description: 'Monitorear continuamente actualizando cada --interval segundos',
      default: false,
    }),

    interval: Flags.integer({
      description: 'Intervalo de refresco en segundos (solo con --watch)',
      default: 30,
      min: 5,
      max: 300,
    }),

    detailed: Flags.boolean({
      char: 'd',
      description: 'Mostrar información detallada de pods/contenedores',
      default: false,
    }),

    'no-color': Flags.boolean({
      description: 'Deshabilitar colores en la salida',
      default: false,
    }),
  }

  async run(): Promise<void> {
    const {flags} = await this.parse(Status)

    const platform = (flags.platform ?? this.configManager.getDefaultPlatform()) as Platform
    const namespace = flags.namespace ?? 'osdo'

    if (flags.watch) {
      await this.runWatchMode(platform, namespace, flags)
    } else {
      await this.runOnce(platform, namespace, flags)
    }
  }

  // ── Modo watch ────────────────────────────────────────────────────────────

  private async runWatchMode(
    platform: Platform,
    namespace: string,
    flags: StatusFlags,
  ): Promise<void> {
    const intervalMs = (flags.interval ?? 30) * 1000

    process.on('SIGINT', () => {
      this.log('\nMonitoreo detenido.')
      // eslint-disable-next-line unicorn/no-process-exit
      process.exit(0)
    })

    // eslint-disable-next-line no-constant-condition
    while (true) {
      // Limpiar pantalla solo en modo tabla
      if (flags.output !== 'json' && flags.output !== 'yaml') {
        process.stdout.write('\u001B[2J\u001B[H')
        this.log(chalk.dim(`Actualizando... (Ctrl+C para detener | Intervalo: ${flags.interval}s)\n`))
      }

      await this.runOnce(platform, namespace, flags)
      await new Promise<void>(resolve => {
        setTimeout(resolve, intervalMs)
      })
    }
  }

  // ── Snapshot único ────────────────────────────────────────────────────────

  private async runOnce(
    platform: Platform,
    namespace: string,
    flags: StatusFlags,
  ): Promise<void> {
    const noColor = flags['no-color'] ?? false
    const component = flags.component
    const outputFormat = flags.output ?? 'table'
    const detailed = flags.detailed ?? false
    const now = new Date().toLocaleString('es-ES')

    if (outputFormat === 'table') {
      this.log(chalk.bold('\nEstado de Componentes OSDO'))
      this.log('═'.repeat(52))
      this.log(`  Plataforma:  ${chalk.cyan(platform)}`)
      this.log(`  Namespace:   ${chalk.cyan(namespace)}`)
      if (component) this.log(`  Componente:  ${chalk.cyan(component)}`)
      this.log(`  Actualizado: ${chalk.dim(now)}`)
      this.log('')
    }

    try {
      switch (platform) {
        case 'kubernetes':
        case 'k3s':
        case 'helm': {
          await this.checkKubernetes(namespace, component, outputFormat, noColor, detailed)
          break
        }

        case 'docker-compose': {
          await this.checkDockerCompose(component, outputFormat, noColor)
          break
        }

        case 'docker-swarm': {
          await this.checkDockerSwarm(component, outputFormat, noColor)
          break
        }

        default: {
          this.warn(`Plataforma "${platform}" no reconocida. Usa kubernetes, helm, docker-compose o docker-swarm.`)
        }
      }
    } catch (err: unknown) {
      const msg = err instanceof Error ? err.message : String(err)
      this.warn(`No se pudo obtener el estado: ${msg}`)
    }
  }

  // ── Kubernetes / K3s / Helm ───────────────────────────────────────────────

  private async checkKubernetes(
    namespace: string,
    component: string | undefined,
    outputFormat: string,
    noColor: boolean,
    detailed: boolean,
  ): Promise<void> {
    const kubeconfigArgs = this.buildKubeconfigArgs()
    let helmReleases: HelmRelease[] = []
    let pods: KubePod[] = []

    // helm list
    try {
      const helmArgs = [
        'list',
        '--namespace', namespace,
        '--output', 'json',
        ...kubeconfigArgs,
      ]
      if (component) helmArgs.push('--filter', component)

      const {stdout} = await execa('helm', helmArgs)
      helmReleases = JSON.parse(stdout) as HelmRelease[]
    } catch {
      // helm no instalado o sin releases — continuar con pods
    }

    // kubectl get pods (siempre útil, o si --detailed)
    if (detailed || helmReleases.length === 0) {
      try {
        const podArgs = [
          'get', 'pods',
          '--namespace', namespace,
          '--output', 'json',
          ...kubeconfigArgs,
        ]
        if (component) {
          podArgs.push('--selector', `app.kubernetes.io/name=${component}`)
        }

        const {stdout} = await execa('kubectl', podArgs)
        const parsed = JSON.parse(stdout) as KubePodsResponse
        pods = parsed.items ?? []
      } catch {
        // kubectl no disponible o sin pods
      }
    }

    if (outputFormat === 'json') {
      this.log(JSON.stringify({releases: helmReleases, pods}, null, 2))
      return
    }

    if (outputFormat === 'yaml') {
      this.log(yaml.dump({releases: helmReleases, pods}))
      return
    }

    // Tabla de releases Helm
    if (helmReleases.length > 0) {
      this.log(chalk.bold('Releases de Helm:'))
      const table = new Table({
        head: ['Release', 'Namespace', 'Chart', 'Estado', 'Versión App'],
        colWidths: [22, 14, 36, 16, 14],
      })

      for (const r of helmReleases) {
        table.push([
          r.name,
          r.namespace,
          r.chart,
          this.colorizeStatus(r.status, noColor),
          r.app_version ?? '—',
        ])
      }

      this.log(table.toString())
      this.log('')
    }

    // Tabla de pods (modo detallado)
    if (detailed && pods.length > 0) {
      this.log(chalk.bold('Pods:'))
      const podTable = new Table({
        head: ['Pod', 'Estado', 'Listo', 'Reinicios', 'Inicio'],
        colWidths: [44, 14, 8, 12, 22],
      })

      for (const pod of pods) {
        const phase = pod.status.phase ?? 'Unknown'
        const restarts = pod.status.containerStatuses?.[0]?.restartCount ?? 0
        const ready = pod.status.containerStatuses?.every(c => c.ready) ? 'Sí' : 'No'
        const startTime = pod.status.startTime
          ? new Date(pod.status.startTime).toLocaleString('es-ES')
          : '—'

        podTable.push([
          pod.metadata.name,
          this.colorizeStatus(phase, noColor),
          ready,
          String(restarts),
          startTime,
        ])
      }

      this.log(podTable.toString())
      this.log('')
    }

    if (helmReleases.length === 0 && pods.length === 0) {
      this.log(chalk.yellow('  No se encontraron componentes OSDO desplegados en este namespace.'))
      this.log(`  Usa "${chalk.cyan('osdo deploy')}" para desplegar componentes.`)
      this.log('')
    }
  }

  // ── Docker Compose ────────────────────────────────────────────────────────

  private async checkDockerCompose(
    component: string | undefined,
    outputFormat: string,
    noColor: boolean,
  ): Promise<void> {
    const args = ['compose', 'ps', '--format', 'json']
    if (component) args.push('--filter', `name=${component}`)

    const {stdout} = await execa('docker', args)

    // docker compose ps --format json emite un JSON por línea (jsonl) o un array
    const services = this.parseJsonLines<DockerComposeService>(stdout)

    if (outputFormat === 'json') {
      this.log(JSON.stringify(services, null, 2))
      return
    }

    if (outputFormat === 'yaml') {
      this.log(yaml.dump(services))
      return
    }

    if (services.length === 0) {
      this.log(chalk.yellow('  No se encontraron servicios de Docker Compose en ejecución.'))
      this.log(`  Usa "${chalk.cyan('osdo deploy --platform docker-compose')}" para levantar servicios.`)
      this.log('')
      return
    }

    this.log(chalk.bold('Servicios de Docker Compose:'))
    const table = new Table({
      head: ['Servicio', 'Estado', 'Health', 'Puertos'],
      colWidths: [28, 16, 12, 32],
    })

    for (const svc of services) {
      table.push([
        svc.Service ?? svc.Name,
        this.colorizeStatus(svc.State ?? svc.Status, noColor),
        svc.Health ?? '—',
        svc.Ports ?? '—',
      ])
    }

    this.log(table.toString())
    this.log('')
  }

  // ── Docker Swarm ──────────────────────────────────────────────────────────

  private async checkDockerSwarm(
    component: string | undefined,
    outputFormat: string,
    noColor: boolean,
  ): Promise<void> {
    // docker service ls soporta --format json en versiones recientes
    const {stdout} = await execa('docker', [
      'service', 'ls',
      '--format', '{{json .}}',
    ])

    const services = this.parseJsonLines<DockerSwarmService>(stdout)
    const filtered = component ? services.filter(s => s.Name.includes(component)) : services

    if (outputFormat === 'json') {
      this.log(JSON.stringify(filtered, null, 2))
      return
    }

    if (outputFormat === 'yaml') {
      this.log(yaml.dump(filtered))
      return
    }

    if (filtered.length === 0) {
      this.log(chalk.yellow('  No se encontraron servicios de Docker Swarm en ejecución.'))
      this.log(`  Usa "${chalk.cyan('osdo deploy --platform docker-swarm')}" para desplegar stacks.`)
      this.log('')
      return
    }

    this.log(chalk.bold('Servicios de Docker Swarm:'))
    const table = new Table({
      head: ['Servicio', 'Réplicas', 'Imagen', 'Modo', 'Puertos'],
      colWidths: [28, 12, 38, 10, 20],
    })

    for (const svc of filtered) {
      // Réplicas: "2/2" — verde si todas están listas
      const replicas = this.colorizeReplicas(svc.Replicas, noColor)
      table.push([
        svc.Name,
        replicas,
        svc.Image,
        svc.Mode,
        svc.Ports ?? '—',
      ])
    }

    this.log(table.toString())
    this.log('')
  }

  // ── Utilidades ────────────────────────────────────────────────────────────

  /**
   * Parsea texto de una o varias líneas JSON.
   * Soporta tanto array JSON como JSONL (un objeto por línea).
   */
  private parseJsonLines<T>(stdout: string): T[] {
    const text = stdout.trim()
    if (!text) return []

    // Intentar parsear como array JSON primero
    try {
      const parsed = JSON.parse(text) as T | T[]
      return Array.isArray(parsed) ? parsed : [parsed]
    } catch {
      // JSONL: una línea por objeto
      return text
        .split('\n')
        .filter(Boolean)
        .flatMap(line => {
          try {
            return [JSON.parse(line) as T]
          } catch {
            return []
          }
        })
    }
  }

  private colorizeStatus(status: string, noColor: boolean): string {
    if (noColor) return status

    const lower = status.toLowerCase()

    if (['deployed', 'running', 'active', 'healthy', 'complete', 'succeeded'].some(s => lower.includes(s))) {
      return chalk.green(status)
    }

    if (['pending', 'starting', 'waiting', 'initializing', 'terminating'].some(s => lower.includes(s))) {
      return chalk.yellow(status)
    }

    if (['failed', 'error', 'crashed', 'unhealthy', 'oomkilled', 'crashloopbackoff'].some(s => lower.includes(s))) {
      return chalk.red(status)
    }

    return chalk.gray(status)
  }

  private colorizeReplicas(replicas: string, noColor: boolean): string {
    if (noColor || !replicas) return replicas ?? '—'

    // Formato esperado: "2/2", "0/1", etc.
    const match = replicas.match(/^(\d+)\/(\d+)$/)
    if (!match) return replicas

    const [, current, desired] = match
    if (current === desired) return chalk.green(replicas)
    if (current === '0') return chalk.red(replicas)
    return chalk.yellow(replicas)
  }

  private buildKubeconfigArgs(): string[] {
    const kc = this.configManager.getKubeconfig()
    return kc ? ['--kubeconfig', kc] : []
  }
}
