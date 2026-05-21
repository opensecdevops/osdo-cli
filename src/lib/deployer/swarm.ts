/**
 * DockerSwarmDeployer — Motor de despliegue vía Docker Swarm para OSDO.
 *
 * Usa `docker service create/update` para gestionar servicios individuales
 * en un cluster Docker Swarm. No usa docker stack deploy.
 *
 * Componentes soportados (subconjunto estable en Swarm):
 * prometheus, grafana, traefik, portainer, vault
 */
import {execa} from 'execa'
import {DEFAULT_IMAGES, DEFAULT_PORTS, CHART_CATALOG} from './chart-catalog.js'
import type {
  Deployer,
  DeploymentResult,
  DeploymentOptions,
  ComponentResult,
  ComponentStatus,
  AccessInfo,
} from './types.js'

/** Subconjunto de componentes soportados en modo Swarm. */
const SWARM_SUPPORTED = ['prometheus', 'grafana', 'traefik', 'portainer', 'vault'] as const

/** Forma del array devuelto por `docker service inspect <name>` */
interface SwarmServiceInspect {
  Spec: {
    Name: string
    Mode: {
      Replicated?: {Replicas: number}
    }
  }
  ServiceStatus?: {
    RunningTasks: number
    DesiredTasks: number
  }
}

/** Comprueba si un servicio Swarm existe. Retorna true si existe. */
async function swarmServiceExists(serviceName: string): Promise<boolean> {
  try {
    await execa('docker', ['service', 'inspect', serviceName])
    return true
  } catch {
    return false
  }
}

/**
 * Implementación Docker Swarm del deployer OSDO.
 * Gestiona servicios individuales con `docker service create/update`.
 */
export class DockerSwarmDeployer implements Deployer {
  readonly platform = 'docker-swarm'

  constructor(private readonly namespace: string = 'osdo') {}

  /**
   * Verifica que Docker esté en modo Swarm activo.
   * @throws Error si Swarm no está inicializado o Docker no está disponible
   */
  async isReady(): Promise<void> {
    try {
      const result = await execa('docker', ['info', '--format', '{{.Swarm.LocalNodeState}}'])
      const state = result.stdout.trim()
      if (state !== 'active') {
        throw new Error(
          `Este nodo Docker no está en modo Swarm activo (estado: "${state}").\n` +
            '  Inicializa Swarm con: docker swarm init',
        )
      }
    } catch (err: unknown) {
      const msg = err instanceof Error ? err.message : String(err)
      // Relanzar si ya es nuestro error de Swarm inactivo
      if (msg.includes('Swarm') || msg.includes('swarm')) {
        throw new Error(msg)
      }
      throw new Error(
        `Docker Swarm no está disponible: ${msg}\n` +
          '  Asegúrate de que Docker esté instalado e inicializa Swarm con: docker swarm init',
      )
    }
  }

  /**
   * Valida que los componentes estén en el subconjunto soportado por Swarm.
   * @throws Error si algún componente no está en SWARM_SUPPORTED
   */
  validateComponents(names: string[]): void {
    const supported = new Set<string>(SWARM_SUPPORTED)
    const unknown = names.filter(n => !supported.has(n))
    if (unknown.length > 0) {
      throw new Error(
        `Componentes no soportados en Docker Swarm: ${unknown.join(', ')}\n` +
          `  Componentes disponibles en Swarm: ${SWARM_SUPPORTED.join(', ')}\n` +
          '  Para otros componentes usa --platform helm o --platform kubernetes',
      )
    }
  }

  /**
   * Despliega cada componente como un servicio Swarm individual.
   * - Si el servicio ya existe && !force → error
   * - Si el servicio ya existe && force → `docker service update --image <img> --force`
   * - Si no existe → `docker service create --name osdo-<name> --replicas 1 <image>`
   */
  async deploy(components: string[], opts: DeploymentOptions): Promise<DeploymentResult> {
    const startTime = Date.now()
    const componentResults: ComponentResult[] = []
    const accessInfo: Record<string, AccessInfo> = {}
    const errors: string[] = []

    for (const name of components) {
      const compStart = Date.now()
      const serviceName = `osdo-${name}`
      const image = DEFAULT_IMAGES[name] ?? `${name}:latest`
      const ports = DEFAULT_PORTS[name] ?? [8080]
      const chartInfo = CHART_CATALOG[name]
      const endpoints = chartInfo?.endpoints ?? ports.map(p => `http://localhost:${p}`)

      if (opts.dryRun) {
        componentResults.push({
          name,
          success: true,
          status: 'dry-run',
          endpoints,
          durationMs: Date.now() - compStart,
        })
        continue
      }

      try {
        const exists = await swarmServiceExists(serviceName)

        if (exists && !opts.force) {
          throw new Error(
            `El servicio Swarm "${serviceName}" ya existe.\n` +
              '  Usa --force para actualizar el servicio existente.',
          )
        }

        if (exists && opts.force) {
          // Actualizar servicio existente forzando redeploy
          await execa('docker', [
            'service', 'update',
            '--image', image,
            '--force',
            serviceName,
          ])
        } else {
          // Crear nuevo servicio Swarm
          const publishArgs = ports.flatMap(p => ['--publish', `published=${p},target=${p}`])
          await execa('docker', [
            'service', 'create',
            '--name', serviceName,
            '--replicas', '1',
            ...publishArgs,
            '--label', 'managed-by=osdo-cli',
            image,
          ])
        }

        componentResults.push({
          name,
          success: true,
          status: exists ? 'updated' : 'deployed',
          endpoints,
          durationMs: Date.now() - compStart,
        })
        accessInfo[name] = {
          url: endpoints[0],
          ports,
          credentials: chartInfo?.credentials,
        }
      } catch (err: unknown) {
        const errMsg = err instanceof Error ? err.message : String(err)
        errors.push(`[${name}] ${errMsg}`)
        componentResults.push({
          name,
          success: false,
          status: 'failed',
          error: errMsg,
          durationMs: Date.now() - compStart,
        })
      }
    }

    return {
      success: errors.length === 0,
      components: componentResults,
      platform: this.platform,
      namespace: opts.namespace,
      duration: Date.now() - startTime,
      accessInfo,
      errors: errors.length > 0 ? errors : undefined,
    }
  }

  /**
   * Elimina los servicios Swarm de los componentes especificados.
   */
  async undeploy(components: string[], _opts: DeploymentOptions): Promise<void> {
    for (const name of components) {
      const serviceName = `osdo-${name}`
      try {
        await execa('docker', ['service', 'rm', serviceName])
      } catch (err: unknown) {
        const msg = err instanceof Error ? err.message : String(err)
        throw new Error(`Error al eliminar servicio Swarm "${serviceName}": ${msg}`)
      }
    }
  }

  /**
   * Obtiene el estado de los servicios Swarm vía `docker service inspect`.
   */
  async getStatus(components: string[]): Promise<Record<string, ComponentStatus>> {
    const result: Record<string, ComponentStatus> = {}

    for (const name of components) {
      const serviceName = `osdo-${name}`
      try {
        const inspectResult = await execa('docker', [
          'service', 'inspect', serviceName,
          '--format', '{{json .}}',
        ])
        const parsed = JSON.parse(inspectResult.stdout) as SwarmServiceInspect
        const desired = parsed.Spec?.Mode?.Replicated?.Replicas ?? 1
        const running = parsed.ServiceStatus?.RunningTasks ?? 0
        const isReady = running >= desired && desired > 0

        result[name] = {
          name,
          status: isReady ? 'running' : 'not-ready',
          ready: isReady,
          replicas: {
            desired,
            ready: running,
            available: running,
          },
        }
      } catch {
        result[name] = {
          name,
          status: 'not-found',
          ready: false,
        }
      }
    }

    return result
  }
}
