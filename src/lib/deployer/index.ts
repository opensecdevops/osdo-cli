/**
 * Motor de despliegue OSDO — Punto de entrada del módulo deployer.
 *
 * Exporta todos los deployers, tipos y la función factory `createDeployer`
 * que selecciona la implementación correcta según la plataforma especificada.
 *
 * @example
 * ```typescript
 * import {createDeployer} from '../lib/deployer/index.js'
 *
 * const deployer = createDeployer('helm', 'osdo')
 * await deployer.isReady()
 * const result = await deployer.deploy(['prometheus', 'grafana'], opts)
 * ```
 */

// Tipos — usar export type para cumplir con verbatimModuleSyntax
export type {
  Deployer,
  DeploymentResult,
  DeploymentOptions,
  ComponentResult,
  ComponentStatus,
  AccessInfo,
  ResourceInfo,
} from './types.js'

// Catálogo — mezcla de valores y tipos
export {CHART_CATALOG, DEFAULT_IMAGES, DEFAULT_PORTS} from './chart-catalog.js'
export type {ChartInfo} from './chart-catalog.js'

// Implementaciones de deployer
export {HelmDeployer} from './helm.js'
export {KubernetesDeployer} from './kubernetes.js'
export {DockerComposeDeployer} from './compose.js'
export {DockerSwarmDeployer} from './swarm.js'

import {HelmDeployer} from './helm.js'
import {KubernetesDeployer} from './kubernetes.js'
import {DockerComposeDeployer} from './compose.js'
import {DockerSwarmDeployer} from './swarm.js'
import type {Deployer} from './types.js'

/**
 * Crea e inicializa el deployer correcto según la plataforma especificada.
 *
 * @param platform  Una de: 'helm', 'kubernetes', 'k3s', 'docker-compose', 'docker-swarm'
 * @param namespace Namespace o contexto de destino (por defecto: 'osdo')
 * @returns Instancia configurada del deployer correcto
 * @throws Error si la plataforma no está soportada
 *
 * @example
 *   const deployer = createDeployer('helm', 'security')
 *   await deployer.isReady()
 *   const result = await deployer.deploy(['vault', 'sonarqube'], opts)
 */
export function createDeployer(
  platform: string,
  namespace = 'osdo',
): Deployer {
  switch (platform) {
    case 'helm': {
      return new HelmDeployer(namespace)
    }

    case 'kubernetes':
    case 'k3s': {
      return new KubernetesDeployer(namespace)
    }

    case 'docker-compose': {
      return new DockerComposeDeployer(namespace)
    }

    case 'docker-swarm': {
      return new DockerSwarmDeployer(namespace)
    }

    default: {
      throw new Error(
        `Plataforma no soportada: "${platform}".\n` +
          '  Plataformas disponibles: helm, kubernetes, k3s, docker-compose, docker-swarm',
      )
    }
  }
}
