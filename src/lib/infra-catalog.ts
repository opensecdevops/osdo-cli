/**
 * OSDO Infra Catalog — Catálogo de componentes de infraestructura DevSecOps.
 *
 * Compartido entre los comandos catalog/* y deploy.
 * Define los componentes disponibles para despliegue con sus charts de Helm
 * y metadatos de categoría.
 */

export type InfraCategory = 'monitoring' | 'security' | 'cicd'

export interface InfraCatalogItem {
  name: string
  category: InfraCategory
  description: string
  /** Chart de Helm para despliegue automatizado */
  chart: string
  version: string
}

export const INFRA_CATALOG: InfraCatalogItem[] = [
  {
    name: 'prometheus',
    category: 'monitoring',
    description: 'Sistema de monitorización y alertas (Prometheus Stack completo)',
    chart: 'prometheus-community/kube-prometheus-stack',
    version: '56.0.0',
  },
  {
    name: 'grafana',
    category: 'monitoring',
    description: 'Dashboards y visualización de métricas',
    chart: 'grafana/grafana',
    version: '7.3.0',
  },
  {
    name: 'jaeger',
    category: 'monitoring',
    description: 'Rastreo distribuido (Distributed Tracing)',
    chart: 'jaegertracing/jaeger',
    version: '0.71.17',
  },
  {
    name: 'vault',
    category: 'security',
    description: 'Gestión de secretos con HashiCorp Vault',
    chart: 'hashicorp/vault',
    version: '0.27.0',
  },
  {
    name: 'sonarqube',
    category: 'security',
    description: 'Análisis estático de código (SAST)',
    chart: 'sonarqube/sonarqube',
    version: '10.4.0',
  },
  {
    name: 'defectdojo',
    category: 'security',
    description: 'Gestión de vulnerabilidades y compliance',
    chart: 'stevehipwells/defectdojo',
    version: '1.6.77',
  },
  {
    name: 'harbor',
    category: 'security',
    description: 'Registry de contenedores con escaneo de seguridad integrado',
    chart: 'harbor/harbor',
    version: '1.14.0',
  },
  {
    name: 'dependency-track',
    category: 'security',
    description: 'Gestión de SBOM y análisis de cadena de suministro',
    chart: 'evryfs/helm-charts/dependency-track',
    version: '0.6.0',
  },
  {
    name: 'gitlab',
    category: 'cicd',
    description: 'Plataforma completa de CI/CD self-hosted',
    chart: 'gitlab/gitlab',
    version: '7.8.0',
  },
  {
    name: 'jenkins',
    category: 'cicd',
    description: 'Servidor de automatización CI/CD',
    chart: 'jenkins/jenkins',
    version: '5.0.17',
  },
  {
    name: 'traefik',
    category: 'cicd',
    description: 'Ingress controller y reverse proxy',
    chart: 'traefik/traefik',
    version: '27.0.0',
  },
  {
    name: 'portainer',
    category: 'cicd',
    description: 'Gestión visual de contenedores Docker/Kubernetes',
    chart: 'portainer/portainer',
    version: '1.0.57',
  },
]

/** Etiquetas legibles por categoría */
export const CATEGORY_LABELS: Record<InfraCategory, string> = {
  monitoring: 'Monitorización',
  security: 'Seguridad',
  cicd: 'CI/CD e Infraestructura',
}

/** Lista de nombres de componentes válidos */
export const VALID_COMPONENT_NAMES: string[] = INFRA_CATALOG.map(i => i.name)

/** Mapa nombre → Helm chart para despliegue automatizado */
export const HELM_CHART_MAP: Record<string, string> = Object.fromEntries(
  INFRA_CATALOG.map(i => [i.name, i.chart]),
)

/** Busca un componente por nombre en el catálogo de infraestructura */
export function findInfraItem(name: string): InfraCatalogItem | undefined {
  return INFRA_CATALOG.find(i => i.name === name)
}

/** Devuelve los componentes filtrados por categoría */
export function filterByCategory(category: InfraCategory): InfraCatalogItem[] {
  return INFRA_CATALOG.filter(i => i.category === category)
}
