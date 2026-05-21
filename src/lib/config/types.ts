/**
 * Tipos de configuración del CLI OSDO.
 * Port de pkg/config/types.go con adiciones para integración con OSDO App.
 */

export type Platform = 'kubernetes' | 'k3s' | 'docker-swarm' | 'docker-compose' | 'helm'

export type OutputFormat = 'table' | 'json' | 'yaml'

export interface PresetConfig {
  name: string
  description: string
  platform: Platform
  components: string[]
  namespace: string
  timeout: number
  dryRun: boolean
}

export interface MonitoringConfig {
  prometheusUrl: string
  grafanaUrl: string
  alertmanagerUrl: string
  jaegerUrl: string
}

export interface SecurityConfig {
  policyEngine: 'kyverno' | 'opa' | 'both'
  vulnerabilityScanning: boolean
  runtimeSecurity: boolean
}

export interface AppConfig {
  /** URL base de la OSDO App */
  url: string
  /** Token de autenticación Sanctum */
  token: string
}

/** Configuración persistida en ~/.config/osdo/config.json (via conf) */
export interface CLIConfig {
  configVersion: string
  defaultPlatform: Platform
  defaultDomain: string
  kubeconfig: string
  app: AppConfig
  presets: PresetConfig[]
  monitoring: MonitoringConfig
  security: SecurityConfig
}

/** Configuración de proyecto leída de .osdo/config.yaml */
export interface ProjectConfig {
  version?: string
  instance?: string
  runtime?: {
    node?: string
    python?: string
    java?: string
    go?: string
    php?: string
  }
  test?: {
    coverage?: {
      minimum?: number
    }
  }
  security?: {
    standards?: string[]
    fail_on?: 'critical' | 'high' | 'medium' | 'low'
    quality_gates?: {
      critical?: number
      high?: number
      medium?: number
    }
    scanners?: {
      sast?: boolean
      sca?: boolean
      secrets?: boolean
      container?: boolean
      iac?: boolean
      dast?: boolean
      sbom?: boolean
    }
  }
  reporting?: {
    formats?: string[]
    output_dir?: string
  }
  app?: {
    url?: string
    package?: string
  }
  build?: {
    command?: string
    dockerfile?: string
  }
}

export const VALID_COMPONENTS = [
  'prometheus',
  'grafana',
  'jaeger',
  'vault',
  'sonarqube',
  'jenkins',
  'gitlab',
  'portainer',
  'traefik',
  'alertmanager',
  'kyverno',
  'falco',
  'harbor',
  'argo-cd',
  'cert-manager',
  'dependency-track',
  'defectdojo',
] as const

export type Component = (typeof VALID_COMPONENTS)[number]

export const DEFAULT_CLI_CONFIG: CLIConfig = {
  configVersion: '2.0',
  defaultPlatform: 'kubernetes',
  defaultDomain: 'osdo.local',
  kubeconfig: '',
  app: {url: '', token: ''},
  presets: [],
  monitoring: {
    prometheusUrl: 'http://prometheus:9090',
    grafanaUrl: 'http://grafana:3000',
    alertmanagerUrl: 'http://alertmanager:9093',
    jaegerUrl: 'http://jaeger:16686',
  },
  security: {
    policyEngine: 'kyverno',
    vulnerabilityScanning: true,
    runtimeSecurity: false,
  },
}
