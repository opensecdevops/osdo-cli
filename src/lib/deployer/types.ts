/**
 * Tipos para el motor de despliegue OSDO.
 *
 * Porta los tipos del motor Go (cmd/deploy.go) a TypeScript.
 * Todos los deployers implementan la interfaz Deployer.
 */

/** Resultado completo de una operación de despliegue. */
export interface DeploymentResult {
  /** true si todos los componentes se desplegaron sin errores */
  success: boolean
  /** Resultado individual por componente */
  components: ComponentResult[]
  /** Plataforma utilizada (helm, kubernetes, docker-compose, docker-swarm) */
  platform: string
  /** Namespace o contexto de destino */
  namespace?: string
  /** Duración total en milisegundos */
  duration: number
  /** Información de acceso indexada por nombre de componente */
  accessInfo: Record<string, AccessInfo>
  /** Errores acumulados durante el despliegue */
  errors?: string[]
  /** Advertencias no fatales */
  warnings?: string[]
}

/** Resultado individual del despliegue de un componente. */
export interface ComponentResult {
  name: string
  success: boolean
  /** Estado textual: deployed, failed, dry-run, updating, etc. */
  status: string
  /** URLs de acceso al servicio */
  endpoints?: string[]
  /** Mensaje de error si success === false */
  error?: string
  /** Duración del despliegue de este componente en ms */
  durationMs: number
  /** Recursos Kubernetes/Docker creados */
  resources?: ResourceInfo[]
}

/** Información de un recurso creado durante el despliegue. */
export interface ResourceInfo {
  kind: string
  name: string
  namespace?: string
  status: string
  ready: boolean
}

/** Información de acceso a un componente desplegado. */
export interface AccessInfo {
  /** URL principal del servicio */
  url?: string
  /** Puertos expuestos */
  ports?: number[]
  /** Credenciales por defecto (username, password, token, etc.) */
  credentials?: Record<string, string>
  /** Instrucciones de acceso en texto libre */
  instructions?: string
}

/** Opciones que controlan el comportamiento de deploy/undeploy. */
export interface DeploymentOptions {
  /** Simular sin ejecutar cambios reales */
  dryRun: boolean
  /** Forzar operación aunque el componente ya exista */
  force: boolean
  /** Tiempo máximo de espera en milisegundos */
  timeoutMs: number
  /** Valores adicionales (key=val) a pasar al deployer */
  values?: Record<string, string>
  /** Namespace destino */
  namespace: string
  /** Crear el namespace si no existe */
  createNamespace: boolean
  /** Esperar a que los pods/servicios estén listos antes de retornar */
  wait: boolean
  /** Mostrar salida detallada */
  verbose: boolean
}

/** Estado actual de un componente ya desplegado. */
export interface ComponentStatus {
  name: string
  /** Estado textual: running, failed, pending, stopped, etc. */
  status: string
  ready: boolean
  replicas?: {
    desired: number
    ready: number
    available: number
  }
  health?: {
    status: string
    message: string
  }
}

/**
 * Interfaz que deben implementar todos los deployers de OSDO.
 * Cada plataforma (Helm, Kubernetes, Docker Compose, Docker Swarm)
 * proporciona su propia implementación.
 */
export interface Deployer {
  /** Identificador de la plataforma (helm, kubernetes, docker-compose, docker-swarm) */
  readonly platform: string

  /**
   * Despliega la lista de componentes en la plataforma.
   * @returns DeploymentResult con el estado de cada componente
   */
  deploy(components: string[], opts: DeploymentOptions): Promise<DeploymentResult>

  /**
   * Elimina los componentes desplegados.
   */
  undeploy(components: string[], opts: DeploymentOptions): Promise<void>

  /**
   * Obtiene el estado actual de los componentes.
   * @returns Mapa nombre → ComponentStatus
   */
  getStatus(components: string[]): Promise<Record<string, ComponentStatus>>

  /**
   * Valida que los nombres de componentes sean reconocidos por este deployer.
   * @throws Error si algún componente no es válido
   */
  validateComponents(components: string[]): void

  /**
   * Verifica que la plataforma esté disponible y operativa.
   * @throws Error si la plataforma no está disponible
   */
  isReady(): Promise<void>
}
