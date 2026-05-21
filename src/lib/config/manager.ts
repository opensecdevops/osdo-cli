import Conf from 'conf'
import {readFileSync} from 'node:fs'
import {join} from 'node:path'
import yaml from 'js-yaml'
import type {CLIConfig, OutputFormat, Platform, PresetConfig, ProjectConfig} from './types.js'
import {DEFAULT_CLI_CONFIG} from './types.js'

/**
 * ConfigManager — Gestor de configuración del CLI OSDO.
 *
 * Port de pkg/config/manager.go con soporte adicional para:
 * - Integración con OSDO App (appUrl, appToken)
 * - Project config via .osdo/config.yaml
 *
 * Jerarquía de configuración (mayor prioridad primero):
 * 1. Flags CLI (--verbose, --output, etc.)
 * 2. Variables de entorno (OSDO_*)
 * 3. Store persistido (~/.config/osdo/config.json via conf)
 * 4. Proyecto local (.osdo/config.yaml)
 * 5. Defaults
 */
export class ConfigManager {
  private store: Conf<CLIConfig>
  private projectConfig: ProjectConfig | null = null

  // Estado en memoria (runtime) — sobrescriben el store cuando se setean
  private verbose = false
  private dryRun = false
  private output: OutputFormat = 'table'
  private kubeconfig = ''

  constructor(configPath?: string) {
    this.store = new Conf<CLIConfig>({
      projectName: 'osdo',
      ...(configPath ? {cwd: configPath} : {}),
      defaults: DEFAULT_CLI_CONFIG,
    })
  }

  /**
   * Cargar configuración del proyecto desde .osdo/config.yaml
   * Si no existe, operar en modo standalone (sin proyecto OSDO).
   */
  async load(): Promise<void> {
    const projectConfigPath = join(process.cwd(), '.osdo', 'config.yaml')
    try {
      const raw = readFileSync(projectConfigPath, 'utf8')
      this.projectConfig = yaml.load(raw) as ProjectConfig
    } catch {
      // No estamos en un directorio de proyecto OSDO — modo standalone
    }
  }

  // === Config de runtime (equivalente a SetVerbose, SetDryRun en Go) ===

  setVerbose(v: boolean): void { this.verbose = v }
  isVerbose(): boolean { return this.verbose }

  setDryRun(v: boolean): void { this.dryRun = v }
  isDryRun(): boolean { return this.dryRun }

  setOutput(v: string): void { this.output = v as OutputFormat }
  getOutput(): OutputFormat { return this.output }

  setKubeconfig(v: string): void {
    this.kubeconfig = v
    this.store.set('kubeconfig', v)
  }

  getKubeconfig(): string {
    return this.kubeconfig || (this.store.get('kubeconfig') as string) || ''
  }

  // === Platform ===

  setDefaultPlatform(p: Platform): void {
    this.store.set('defaultPlatform', p)
  }

  getDefaultPlatform(): Platform {
    return (this.store.get('defaultPlatform') as Platform) || 'kubernetes'
  }

  // === OSDO App integration ===

  setAppUrl(url: string): void {
    this.store.set('app', {...(this.store.get('app') as object), url})
  }

  getAppUrl(): string {
    const app = this.store.get('app') as {url?: string; token?: string}
    return app?.url || ''
  }

  setAppToken(token: string): void {
    this.store.set('app', {...(this.store.get('app') as object), token})
  }

  getAppToken(): string {
    const app = this.store.get('app') as {url?: string; token?: string}
    return app?.token || ''
  }

  isAppAuthenticated(): boolean {
    return Boolean(this.getAppToken() && this.getAppUrl())
  }

  clearAppAuth(): void {
    this.store.set('app', {url: '', token: ''})
  }

  // === Monitoring URLs ===

  setMonitoringUrls(urls: {prometheusUrl: string; grafanaUrl: string; alertmanagerUrl: string}): void {
    const current = (this.store.get('monitoring') as unknown as Record<string, string>) ?? {}
    this.store.set('monitoring', {
      ...current,
      prometheusUrl: urls.prometheusUrl,
      grafanaUrl: urls.grafanaUrl,
      alertmanagerUrl: urls.alertmanagerUrl,
    })
  }

  getMonitoringUrls(): {prometheusUrl: string; grafanaUrl: string; alertmanagerUrl: string} | null {
    const m = this.store.get('monitoring') as {
      prometheusUrl?: string
      grafanaUrl?: string
      alertmanagerUrl?: string
    } | undefined
    if (!m?.prometheusUrl) return null
    return {
      prometheusUrl: m.prometheusUrl,
      grafanaUrl: m.grafanaUrl ?? '',
      alertmanagerUrl: m.alertmanagerUrl ?? '',
    }
  }

  // === Project config ===

  get project(): ProjectConfig | null {
    return this.projectConfig
  }

  // === Presets ===

  getPresets(): PresetConfig[] {
    return (this.store.get('presets') as PresetConfig[] | undefined) ?? []
  }

  savePreset(preset: PresetConfig): void {
    const presets = this.getPresets()
    const idx = presets.findIndex(p => p.name === preset.name)
    if (idx >= 0) {
      presets[idx] = preset
    } else {
      presets.push(preset)
    }

    this.store.set('presets', presets)
  }

  deletePreset(name: string): boolean {
    const presets = this.getPresets()
    const filtered = presets.filter(p => p.name !== name)
    if (filtered.length === presets.length) return false
    this.store.set('presets', filtered)
    return true
  }

  // === Full config access ===

  get config(): CLIConfig {
    return this.store.store as CLIConfig
  }

  save(): void {
    // conf auto-guarda, pero este método existe para compatibilidad
  }
}
