/**
 * HelmDeployer — Motor de despliegue vía Helm para componentes OSDO.
 *
 * Porta la lógica de cmd/deploy/helm.go a TypeScript.
 * Gestiona repositorios Helm, instala/actualiza releases y obtiene su estado.
 */
import {execa} from 'execa'
import {CHART_CATALOG} from './chart-catalog.js'
import type {
  Deployer,
  DeploymentResult,
  DeploymentOptions,
  ComponentResult,
  ComponentStatus,
  AccessInfo,
} from './types.js'

/** Forma del JSON devuelto por `helm list --output json` */
interface HelmListEntry {
  name: string
  status: string
  chart: string
  app_version: string
}

/** Forma del JSON devuelto por `helm status --output json` */
interface HelmStatusOutput {
  name: string
  info: {
    status: string
    description: string
  }
}

/**
 * Implementación Helm del deployer OSDO.
 * Usa `helm upgrade --install` para gestionar releases en Kubernetes.
 */
export class HelmDeployer implements Deployer {
  readonly platform = 'helm'

  constructor(private readonly namespace: string = 'osdo') {}

  /**
   * Verifica que Helm esté instalado y accesible en el PATH.
   * @throws Error si Helm no está disponible
   */
  async isReady(): Promise<void> {
    try {
      await execa('helm', ['version', '--short'])
    } catch (err: unknown) {
      const msg = err instanceof Error ? err.message : String(err)
      throw new Error(
        `Helm no está disponible en el sistema: ${msg}\n` +
          '  Instala Helm desde https://helm.sh/docs/intro/install/',
      )
    }
  }

  /**
   * Valida que todos los componentes existan en el CHART_CATALOG.
   * @throws Error con lista de componentes desconocidos
   */
  validateComponents(names: string[]): void {
    const unknown = names.filter(n => !(n in CHART_CATALOG))
    if (unknown.length > 0) {
      const available = Object.keys(CHART_CATALOG).join(', ')
      throw new Error(
        `Componentes no reconocidos para Helm: ${unknown.join(', ')}\n` +
          `  Componentes disponibles: ${available}`,
      )
    }
  }

  /**
   * Despliega cada componente vía `helm upgrade --install`.
   * Proceso por componente:
   *   1. helm repo add <repoName> <repo> --force-update
   *   2. helm repo update
   *   3. Verificar si el release ya existe
   *   4. helm upgrade --install (--dry-run si dryRun: true)
   */
  async deploy(components: string[], opts: DeploymentOptions): Promise<DeploymentResult> {
    const startTime = Date.now()
    const componentResults: ComponentResult[] = []
    const accessInfo: Record<string, AccessInfo> = {}
    const errors: string[] = []

    for (const name of components) {
      const compStart = Date.now()
      const chart = CHART_CATALOG[name]

      // validateComponents ya debe haberse llamado, pero doble verificación
      if (!chart) {
        const errMsg = `Chart no encontrado para "${name}"`
        errors.push(errMsg)
        componentResults.push({
          name,
          success: false,
          status: 'failed',
          error: errMsg,
          durationMs: Date.now() - compStart,
        })
        continue
      }

      const releaseName = `${opts.namespace}-${name}`

      try {
        // 1. Registrar repositorio Helm
        await execa('helm', [
          'repo', 'add',
          chart.repoName,
          chart.repo,
          '--force-update',
        ])

        // 2. Actualizar índice del repositorio
        await execa('helm', ['repo', 'update', chart.repoName])

        // 3. Verificar si el release ya existe (a menos que sea dry-run)
        if (!opts.dryRun) {
          const listResult = await execa('helm', [
            'list',
            '--namespace', opts.namespace,
            '--output', 'json',
            '--filter', `^${releaseName}$`,
          ])
          const releases = JSON.parse(listResult.stdout) as HelmListEntry[]
          const exists = releases.length > 0

          if (exists && !opts.force) {
            throw new Error(
              `El release "${releaseName}" ya está instalado en el namespace "${opts.namespace}".\n` +
                '  Usa --force para forzar la actualización.',
            )
          }
        }

        // Construir argumentos --set para los valores del chart
        const setArgs = Object.entries(chart.values).flatMap(([k, v]) => ['--set', `${k}=${v}`])
        const extraSetArgs = opts.values
          ? Object.entries(opts.values).flatMap(([k, v]) => ['--set', `${k}=${v}`])
          : []

        // Tiempo de espera en segundos
        const timeoutSecs = Math.ceil(opts.timeoutMs / 1000)

        // 4a. Modo dry-run: ejecutar simulación y retornar
        if (opts.dryRun) {
          await execa('helm', [
            'upgrade', '--install', releaseName,
            `${chart.repoName}/${chart.chart}`,
            '--namespace', opts.namespace,
            '--create-namespace',
            '--version', chart.version,
            '--dry-run',
            ...setArgs,
            ...extraSetArgs,
          ])

          componentResults.push({
            name,
            success: true,
            status: 'dry-run',
            endpoints: chart.endpoints,
            durationMs: Date.now() - compStart,
          })
          continue
        }

        // 4b. Despliegue real
        const upgradeArgs = [
          'upgrade', '--install', releaseName,
          `${chart.repoName}/${chart.chart}`,
          '--namespace', opts.namespace,
          '--version', chart.version,
          '--timeout', `${timeoutSecs}s`,
          ...setArgs,
          ...extraSetArgs,
        ]

        if (opts.createNamespace) upgradeArgs.push('--create-namespace')
        if (opts.wait) upgradeArgs.push('--wait')

        await execa('helm', upgradeArgs)

        componentResults.push({
          name,
          success: true,
          status: 'deployed',
          endpoints: chart.endpoints,
          durationMs: Date.now() - compStart,
        })

        accessInfo[name] = {
          url: chart.endpoints[0],
          credentials: chart.credentials,
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
   * Elimina los releases Helm de los componentes especificados.
   */
  async undeploy(components: string[], opts: DeploymentOptions): Promise<void> {
    for (const name of components) {
      const releaseName = `${opts.namespace}-${name}`
      try {
        await execa('helm', [
          'uninstall', releaseName,
          '--namespace', opts.namespace,
        ])
      } catch (err: unknown) {
        const msg = err instanceof Error ? err.message : String(err)
        throw new Error(`Error al desinstalar "${releaseName}": ${msg}`)
      }
    }
  }

  /**
   * Obtiene el estado de los releases Helm desplegados.
   * Ejecuta `helm status <release> --output json` por componente.
   */
  async getStatus(components: string[]): Promise<Record<string, ComponentStatus>> {
    const result: Record<string, ComponentStatus> = {}

    for (const name of components) {
      const releaseName = `${this.namespace}-${name}`
      try {
        const statusResult = await execa('helm', [
          'status', releaseName,
          '--namespace', this.namespace,
          '--output', 'json',
        ])
        const parsed = JSON.parse(statusResult.stdout) as HelmStatusOutput
        const helmStatus = parsed.info?.status ?? 'unknown'
        const ready = helmStatus === 'deployed'

        result[name] = {
          name,
          status: helmStatus,
          ready,
          health: {
            status: ready ? 'ok' : 'degraded',
            message: parsed.info?.description ?? '',
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
