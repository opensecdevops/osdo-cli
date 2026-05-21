/**
 * KubernetesDeployer — Motor de despliegue directo vía kubectl para OSDO.
 *
 * Genera manifiestos Kubernetes mínimos (Deployment + Service) por componente
 * y los aplica vía `kubectl apply -f -` desde stdin.
 * Compatible con kubernetes y k3s.
 */
import {execa} from 'execa'
import {CHART_CATALOG, DEFAULT_IMAGES, DEFAULT_PORTS} from './chart-catalog.js'
import {VALID_COMPONENT_NAMES} from '../infra-catalog.js'
import type {
  Deployer,
  DeploymentResult,
  DeploymentOptions,
  ComponentResult,
  ComponentStatus,
  AccessInfo,
} from './types.js'

/** Forma del JSON devuelto por `kubectl get deployment -o json` */
interface KubeDeploymentStatus {
  status?: {
    availableReplicas?: number
    readyReplicas?: number
    replicas?: number
    conditions?: Array<{type: string; status: string; message?: string}>
  }
}

/** Genera un manifiesto YAML con Deployment + Service mínimos para un componente. */
function buildManifest(component: string, image: string, namespace: string, ports: number[]): string {
  const portItems = ports.map(p => `        - containerPort: ${p}`).join('\n')
  const servicePorts = ports.map(p => `  - port: ${p}\n    targetPort: ${p}`).join('\n')

  return `apiVersion: apps/v1
kind: Deployment
metadata:
  name: ${component}
  namespace: ${namespace}
  labels:
    app: ${component}
    app.kubernetes.io/managed-by: osdo
spec:
  replicas: 1
  selector:
    matchLabels:
      app: ${component}
  template:
    metadata:
      labels:
        app: ${component}
    spec:
      containers:
        - name: ${component}
          image: ${image}
          ports:
${portItems}
---
apiVersion: v1
kind: Service
metadata:
  name: ${component}
  namespace: ${namespace}
  labels:
    app: ${component}
    app.kubernetes.io/managed-by: osdo
spec:
  selector:
    app: ${component}
  ports:
${servicePorts}
  type: ClusterIP
`
}

/**
 * Implementación Kubernetes/K3s del deployer OSDO.
 * Genera manifiestos mínimos y los aplica vía kubectl.
 */
export class KubernetesDeployer implements Deployer {
  readonly platform = 'kubernetes'

  constructor(private readonly namespace: string = 'osdo') {}

  /**
   * Verifica que el clúster Kubernetes esté accesible.
   * @throws Error si kubectl no puede conectarse al clúster
   */
  async isReady(): Promise<void> {
    try {
      await execa('kubectl', ['cluster-info'])
    } catch (err: unknown) {
      const msg = err instanceof Error ? err.message : String(err)
      throw new Error(
        `Clúster Kubernetes no accesible: ${msg}\n` +
          '  Verifica que kubectl esté instalado y el kubeconfig sea correcto.',
      )
    }
  }

  /**
   * Valida que los componentes estén en el CHART_CATALOG o en el catálogo de infraestructura.
   * @throws Error con los componentes no reconocidos
   */
  validateComponents(names: string[]): void {
    const allKnown = new Set([...Object.keys(CHART_CATALOG), ...VALID_COMPONENT_NAMES])
    const unknown = names.filter(n => !allKnown.has(n))
    if (unknown.length > 0) {
      const available = [...allKnown].sort().join(', ')
      throw new Error(
        `Componentes no reconocidos para Kubernetes: ${unknown.join(', ')}\n` +
          `  Componentes disponibles: ${available}`,
      )
    }
  }

  /**
   * Despliega componentes generando y aplicando manifiestos Kubernetes.
   * Proceso:
   *   1. Crear namespace (si createNamespace: true)
   *   2. Generar Deployment + Service mínimos
   *   3. `kubectl apply -f -` vía stdin
   *   4. `kubectl rollout status` (si wait: true)
   */
  async deploy(components: string[], opts: DeploymentOptions): Promise<DeploymentResult> {
    const startTime = Date.now()
    const componentResults: ComponentResult[] = []
    const accessInfo: Record<string, AccessInfo> = {}
    const errors: string[] = []

    // Crear namespace si se solicita
    if (opts.createNamespace) {
      try {
        await execa('kubectl', ['create', 'namespace', opts.namespace])
      } catch {
        // El namespace ya existe — continuar
      }
    }

    for (const name of components) {
      const compStart = Date.now()
      const image = DEFAULT_IMAGES[name] ?? `${name}:latest`
      const ports = DEFAULT_PORTS[name] ?? [8080]
      const chartInfo = CHART_CATALOG[name]
      const endpoints = chartInfo?.endpoints ?? [`http://localhost:${ports[0]}`]

      try {
        const manifest = buildManifest(name, image, opts.namespace, ports)

        if (opts.dryRun) {
          // Dry-run del lado del cliente: validar sin aplicar
          await execa('kubectl', [
            'apply', '-f', '-',
            '--namespace', opts.namespace,
            '--dry-run=client',
          ], {input: manifest})

          componentResults.push({
            name,
            success: true,
            status: 'dry-run',
            endpoints,
            durationMs: Date.now() - compStart,
          })
          continue
        }

        // Aplicar manifiesto vía stdin
        await execa('kubectl', ['apply', '-f', '-', '--namespace', opts.namespace], {
          input: manifest,
        })

        // Esperar a que el Deployment esté listo
        if (opts.wait) {
          const timeoutSecs = Math.ceil(opts.timeoutMs / 1000)
          await execa('kubectl', [
            'rollout', 'status',
            `deployment/${name}`,
            '--namespace', opts.namespace,
            `--timeout=${timeoutSecs}s`,
          ])
        }

        componentResults.push({
          name,
          success: true,
          status: 'deployed',
          endpoints,
          durationMs: Date.now() - compStart,
          resources: [
            {kind: 'Deployment', name, namespace: opts.namespace, status: 'Running', ready: true},
            {kind: 'Service', name, namespace: opts.namespace, status: 'Active', ready: true},
          ],
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
   * Elimina los Deployments y Services de los componentes especificados.
   */
  async undeploy(components: string[], opts: DeploymentOptions): Promise<void> {
    for (const name of components) {
      try {
        await execa('kubectl', [
          'delete', 'deployment,service',
          '-l', `app=${name}`,
          '--namespace', opts.namespace,
        ])
      } catch (err: unknown) {
        const msg = err instanceof Error ? err.message : String(err)
        throw new Error(`Error al eliminar "${name}": ${msg}`)
      }
    }
  }

  /**
   * Obtiene el estado de los Deployments de los componentes especificados.
   */
  async getStatus(components: string[]): Promise<Record<string, ComponentStatus>> {
    const result: Record<string, ComponentStatus> = {}

    for (const name of components) {
      try {
        const statusResult = await execa('kubectl', [
          'get', 'deployment', name,
          '--namespace', this.namespace,
          '-o', 'json',
        ])
        const parsed = JSON.parse(statusResult.stdout) as KubeDeploymentStatus
        const desired = parsed.status?.replicas ?? 1
        const ready = parsed.status?.readyReplicas ?? 0
        const available = parsed.status?.availableReplicas ?? 0
        const isReady = ready >= desired && desired > 0

        result[name] = {
          name,
          status: isReady ? 'running' : 'not-ready',
          ready: isReady,
          replicas: {desired, ready, available},
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
