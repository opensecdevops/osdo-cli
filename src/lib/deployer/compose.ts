/**
 * DockerComposeDeployer — Motor de despliegue vía Docker Compose para OSDO.
 *
 * Genera configuraciones Docker Compose en memoria para los componentes
 * solicitados y las pasa a `docker compose -f - up -d` vía stdin.
 * No escribe archivos en disco — todo el ciclo de vida usa stdin.
 */
import {execa} from 'execa'
import * as yaml from 'js-yaml'
import {CHART_CATALOG, DEFAULT_IMAGES, DEFAULT_PORTS} from './chart-catalog.js'
import type {
  Deployer,
  DeploymentResult,
  DeploymentOptions,
  ComponentResult,
  ComponentStatus,
  AccessInfo,
} from './types.js'

/** Componentes con imagen Docker conocida (soportados en modo Compose). */
const COMPOSE_SUPPORTED = new Set(Object.keys(DEFAULT_IMAGES))

/** Forma del JSON devuelto por `docker inspect <container>` */
interface DockerInspectEntry {
  Name: string
  State: {
    Status: string
    Running: boolean
  }
}

/** Configuración de un servicio Docker Compose en memoria. */
interface ComposeService {
  image: string
  container_name: string
  ports: string[]
  restart: string
  labels: Record<string, string>
}

/**
 * Genera el objeto de configuración Docker Compose para los componentes.
 * La configuración se pasa completamente vía stdin a `docker compose -f -`.
 */
function buildComposeConfig(components: string[]): object {
  const services: Record<string, ComposeService> = {}
  for (const name of components) {
    const image = DEFAULT_IMAGES[name] ?? `${name}:latest`
    const ports = DEFAULT_PORTS[name] ?? [8080]
    services[name] = {
      image,
      container_name: `osdo-${name}`,
      ports: ports.map(p => `${p}:${p}`),
      restart: 'unless-stopped',
      labels: {'managed-by': 'osdo-cli'},
    }
  }
  return {version: '3.8', services}
}

/**
 * Implementación Docker Compose del deployer OSDO.
 * Gestiona el ciclo de vida completo de los servicios vía stdin.
 */
export class DockerComposeDeployer implements Deployer {
  readonly platform = 'docker-compose'

  constructor(private readonly namespace: string = 'osdo') {}

  /**
   * Verifica que el daemon Docker esté accesible.
   * @throws Error si Docker no está disponible
   */
  async isReady(): Promise<void> {
    try {
      await execa('docker', ['info'])
    } catch (err: unknown) {
      const msg = err instanceof Error ? err.message : String(err)
      throw new Error(
        `Docker no está disponible o el daemon no está corriendo: ${msg}\n` +
          '  Inicia Docker Desktop o el daemon de Docker e inténtalo de nuevo.',
      )
    }
  }

  /**
   * Valida que los componentes tengan una imagen Docker conocida.
   * @throws Error si algún componente no está soportado
   */
  validateComponents(names: string[]): void {
    const unknown = names.filter(n => !COMPOSE_SUPPORTED.has(n))
    if (unknown.length > 0) {
      const available = [...COMPOSE_SUPPORTED].sort().join(', ')
      throw new Error(
        `Componentes no soportados en Docker Compose: ${unknown.join(', ')}\n` +
          `  Componentes disponibles: ${available}`,
      )
    }
  }

  /**
   * Genera una configuración Compose en memoria y la aplica vía stdin.
   * Equivale a `docker compose -f <file> up -d` sin escribir archivos.
   */
  async deploy(components: string[], opts: DeploymentOptions): Promise<DeploymentResult> {
    const startTime = Date.now()
    const componentResults: ComponentResult[] = []
    const accessInfo: Record<string, AccessInfo> = {}
    const errors: string[] = []

    const composeConfig = buildComposeConfig(components)
    const composeYaml = yaml.dump(composeConfig)

    if (opts.dryRun) {
      for (const name of components) {
        const ports = DEFAULT_PORTS[name] ?? [8080]
        const chartInfo = CHART_CATALOG[name]
        const endpoints = chartInfo?.endpoints ?? ports.map(p => `http://localhost:${p}`)
        componentResults.push({
          name,
          success: true,
          status: 'dry-run',
          endpoints,
          durationMs: 0,
        })
      }
      return {
        success: true,
        components: componentResults,
        platform: this.platform,
        namespace: opts.namespace,
        duration: Date.now() - startTime,
        accessInfo,
        warnings: [`[dry-run] Se generaría la siguiente configuración Compose:\n${composeYaml}`],
      }
    }

    try {
      // Aplicar todos los servicios en un solo `docker compose up -d` vía stdin
      await execa('docker', ['compose', '-f', '-', 'up', '-d'], {
        input: composeYaml,
      })

      for (const name of components) {
        const compStart = Date.now()
        const ports = DEFAULT_PORTS[name] ?? [8080]
        const chartInfo = CHART_CATALOG[name]
        const endpoints = chartInfo?.endpoints ?? ports.map(p => `http://localhost:${p}`)

        componentResults.push({
          name,
          success: true,
          status: 'running',
          endpoints,
          durationMs: Date.now() - compStart,
        })
        accessInfo[name] = {
          url: endpoints[0],
          ports,
          credentials: chartInfo?.credentials,
        }
      }
    } catch (err: unknown) {
      const errMsg = err instanceof Error ? err.message : String(err)
      errors.push(errMsg)
      for (const name of components) {
        componentResults.push({
          name,
          success: false,
          status: 'failed',
          error: errMsg,
          durationMs: 0,
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
   * Detiene y elimina los contenedores regenerando la misma configuración Compose vía stdin.
   */
  async undeploy(components: string[], _opts: DeploymentOptions): Promise<void> {
    const composeConfig = buildComposeConfig(components)
    const composeYaml = yaml.dump(composeConfig)
    try {
      await execa('docker', ['compose', '-f', '-', 'down'], {
        input: composeYaml,
      })
    } catch (err: unknown) {
      const msg = err instanceof Error ? err.message : String(err)
      throw new Error(`Error al detener servicios Compose: ${msg}`)
    }
  }

  /**
   * Obtiene el estado de cada contenedor vía `docker inspect osdo-<component>`.
   */
  async getStatus(components: string[]): Promise<Record<string, ComponentStatus>> {
    const result: Record<string, ComponentStatus> = {}

    for (const name of components) {
      const containerName = `osdo-${name}`
      try {
        const inspectResult = await execa('docker', ['inspect', containerName])
        const parsed = JSON.parse(inspectResult.stdout) as DockerInspectEntry[]
        const container = parsed[0]
        const running = container?.State?.Running ?? false
        const status = container?.State?.Status ?? 'unknown'

        result[name] = {
          name,
          status: running ? 'running' : status,
          ready: running,
          health: {
            status: running ? 'ok' : 'degraded',
            message: status,
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
