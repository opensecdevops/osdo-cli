/**
 * Catálogo de charts Helm y metadatos de despliegue para componentes OSDO.
 *
 * Porta la configuración de helm.go al motor TypeScript.
 * Incluye charts, imágenes Docker por defecto, puertos y credenciales iniciales.
 */

/** Metadatos completos de un chart Helm para un componente OSDO. */
export interface ChartInfo {
  /** URL del repositorio Helm */
  repo: string
  /** Nombre local del repositorio (para `helm repo add`) */
  repoName: string
  /** Nombre del chart dentro del repositorio */
  chart: string
  /** Versión del chart a instalar */
  version: string
  /** Valores por defecto a pasar con --set */
  values: Record<string, string>
  /** Credenciales de acceso por defecto (si aplica) */
  credentials?: Record<string, string>
  /** Endpoints de acceso al servicio */
  endpoints: string[]
}

/**
 * Catálogo de charts Helm por componente OSDO.
 * Usado por HelmDeployer para desplegar componentes vía Helm.
 */
export const CHART_CATALOG: Record<string, ChartInfo> = {
  prometheus: {
    repo: 'https://prometheus-community.github.io/helm-charts',
    repoName: 'prometheus-community',
    chart: 'kube-prometheus-stack',
    version: '55.0.0',
    values: {
      'grafana.service.type': 'NodePort',
      'prometheus.service.type': 'NodePort',
    },
    endpoints: ['http://localhost:9090'],
  },
  grafana: {
    repo: 'https://grafana.github.io/helm-charts',
    repoName: 'grafana',
    chart: 'grafana',
    version: '7.0.0',
    values: {
      adminPassword: 'admin',
      'service.type': 'NodePort',
    },
    credentials: {username: 'admin', password: 'admin'},
    endpoints: ['http://localhost:3000'],
  },
  jaeger: {
    repo: 'https://jaegertracing.github.io/helm-charts',
    repoName: 'jaegertracing',
    chart: 'jaeger',
    version: '0.71.14',
    values: {
      'provisionDataStore.cassandra': 'false',
      'allInOne.enabled': 'true',
      'storage.type': 'memory',
    },
    endpoints: ['http://localhost:16686'],
  },
  vault: {
    repo: 'https://helm.releases.hashicorp.com',
    repoName: 'hashicorp',
    chart: 'vault',
    version: '0.27.0',
    values: {
      'server.dev.enabled': 'true',
      'ui.enabled': 'true',
      'ui.serviceType': 'NodePort',
    },
    credentials: {token: 'root'},
    endpoints: ['http://localhost:8200'],
  },
  sonarqube: {
    repo: 'https://SonarSource.github.io/helm-chart-sonarqube',
    repoName: 'sonarqube',
    chart: 'sonarqube',
    version: '10.3.0',
    values: {'service.type': 'NodePort'},
    credentials: {username: 'admin', password: 'admin'},
    endpoints: ['http://localhost:9000'],
  },
  gitlab: {
    repo: 'https://charts.gitlab.io',
    repoName: 'gitlab',
    chart: 'gitlab',
    version: '7.7.0',
    values: {
      'global.edition': 'ce',
      'nginx-ingress.enabled': 'false',
      'certmanager.install': 'false',
    },
    endpoints: ['http://localhost:80'],
  },
  trivy: {
    repo: 'https://aquasecurity.github.io/helm-charts',
    repoName: 'aqua',
    chart: 'trivy',
    version: '0.7.0',
    values: {},
    endpoints: ['http://localhost:4954'],
  },
  defectdojo: {
    repo: 'https://stevehipwells.github.io/helm-chart-repo',
    repoName: 'stevehipwells',
    chart: 'defectdojo',
    version: '1.6.77',
    values: {'service.type': 'NodePort'},
    credentials: {username: 'admin', password: 'admin'},
    endpoints: ['http://localhost:8080'],
  },
  harbor: {
    repo: 'https://helm.goharbor.io',
    repoName: 'harbor',
    chart: 'harbor',
    version: '1.14.0',
    values: {
      'expose.type': 'nodePort',
      externalURL: 'https://localhost:30003',
    },
    credentials: {username: 'admin', password: 'Harbor12345'},
    endpoints: ['https://localhost:30003'],
  },
  'dependency-track': {
    repo: 'https://evryfs.github.io/helm-charts',
    repoName: 'evryfs',
    chart: 'dependency-track',
    version: '0.6.0',
    values: {
      'frontendService.type': 'NodePort',
      'apiServerService.type': 'NodePort',
    },
    endpoints: ['http://localhost:8080'],
  },
  jenkins: {
    repo: 'https://charts.jenkins.io',
    repoName: 'jenkins',
    chart: 'jenkins',
    version: '5.0.17',
    values: {'controller.service.type': 'NodePort'},
    credentials: {username: 'admin', password: 'admin'},
    endpoints: ['http://localhost:8080'],
  },
  traefik: {
    repo: 'https://traefik.github.io/charts',
    repoName: 'traefik',
    chart: 'traefik',
    version: '27.0.0',
    values: {'service.type': 'NodePort'},
    endpoints: ['http://localhost:80', 'http://localhost:8080'],
  },
  portainer: {
    repo: 'https://portainer.github.io/k8s',
    repoName: 'portainer',
    chart: 'portainer',
    version: '1.0.57',
    values: {'service.type': 'NodePort'},
    credentials: {username: 'admin', password: 'admin'},
    endpoints: ['http://localhost:9000'],
  },
}

/**
 * Imágenes Docker por defecto para cada componente OSDO.
 * Usado por KubernetesDeployer y DockerComposeDeployer para
 * generar manifiestos sin necesitar un chart de Helm.
 */
export const DEFAULT_IMAGES: Record<string, string> = {
  prometheus: 'prom/prometheus:v2.47.0',
  grafana: 'grafana/grafana:10.0.0',
  jaeger: 'jaegertracing/all-in-one:1.51',
  vault: 'vault:1.15',
  sonarqube: 'sonarqube:10.3-community',
  defectdojo: 'defectdojo/defectdojo-django:latest',
  harbor: 'goharbor/harbor-core:v2.10.0',
  'dependency-track': 'dependencytrack/bundled:4.9.0',
  gitlab: 'gitlab/gitlab-ce:latest',
  jenkins: 'jenkins/jenkins:lts',
  traefik: 'traefik:v3.0',
  portainer: 'portainer/portainer-ce:latest',
  trivy: 'aquasec/trivy:latest',
}

/**
 * Puertos de servicio por defecto para cada componente.
 * Usado para generar manifiestos Kubernetes y configuraciones Compose.
 */
export const DEFAULT_PORTS: Record<string, number[]> = {
  prometheus: [9090],
  grafana: [3000],
  jaeger: [16686, 14268, 14250],
  vault: [8200],
  sonarqube: [9000],
  defectdojo: [8080],
  harbor: [80, 443],
  'dependency-track': [8080, 8081],
  gitlab: [80, 443, 22],
  jenkins: [8080, 50000],
  traefik: [80, 443, 8080],
  portainer: [9000, 8000],
  trivy: [4954],
}
