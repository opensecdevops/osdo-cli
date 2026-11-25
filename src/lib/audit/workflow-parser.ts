import {readFileSync, readdirSync, existsSync} from 'node:fs'
import {join} from 'node:path'
import yaml from 'js-yaml'
import type {SecurityControl} from './baseline.js'
import {SECURITY_CONTROLS} from './baseline.js'
import type {AuditException} from './exceptions.js'

export interface WorkflowStep {
  name?: string
  uses?: string
  run?: string
  if?: string
  with?: Record<string, unknown>
}

export interface WorkflowJob {
  name?: string
  /** Reusable workflow call a nivel de job: `jobs.<id>.uses` */
  uses?: string
  with?: Record<string, unknown>
  steps?: WorkflowStep[]
  permissions?: Record<string, string>
}

export interface ParsedWorkflow {
  file: string
  name?: string
  on?: unknown
  jobs: Record<string, WorkflowJob>
  /** Permisos a nivel de workflow (declarations al top-level) */
  permissions?: Record<string, string> | string
}

export interface ControlCoverage {
  control: SecurityControl
  /** Si el control está cubierto en alguno de los workflows */
  covered: boolean
  /** Nombre de la action/herramienta que lo cubre */
  coveredBy: string | null
  /** Si está usando la action OSDO nativa vs equivalente */
  isOsdo: boolean
  /** Archivos de workflow donde se detectó cobertura */
  files: string[]
  /** Excepción N/A aplicada a este control (si existe en .osdo/exceptions.yml) */
  exception?: AuditException
}

export interface WorkflowAuditResult {
  /** Total de workflows evaluados */
  workflowCount: number
  /** Workflows parseados */
  workflows: ParsedWorkflow[]
  /** Cobertura por control */
  coverage: ControlCoverage[]
  /**
   * Puntuación final (0-100). Con excepciones: puntos cubiertos / puntos aplicables * 100,
   * redondeada hacia abajo; los controles exceptuados no cuentan en numerador ni denominador.
   */
  score: number
  /** Puntuación bruta: puntos cubiertos / 100, sin aplicar excepciones */
  scoreWithoutExceptions: number
  /** Excepciones N/A aplicadas (vacío si no hay archivo o se usó --no-exceptions) */
  exceptions: AuditException[]
  /** Si cada workflow tiene permissions: declaradas */
  permissionsCoverage: {file: string; hasPermissions: boolean}[]
  /** Si las actions están fijadas por hash (pinned) */
  pinnedActionsReport: {file: string; unpinned: string[]; ratio: number}[]
}

/**
 * Lee y parsea todos los archivos .yml/.yaml en un directorio de workflows.
 */
export function loadWorkflowsFromDir(workflowsDir: string): ParsedWorkflow[] {
  if (!existsSync(workflowsDir)) return []

  const files = readdirSync(workflowsDir).filter(
    f => f.endsWith('.yml') || f.endsWith('.yaml'),
  )

  const parsed: ParsedWorkflow[] = []
  for (const file of files) {
    try {
      const content = readFileSync(join(workflowsDir, file), 'utf8')
      const wf = yaml.load(content) as ParsedWorkflow
      if (wf && typeof wf === 'object' && wf.jobs) {
        parsed.push({...wf, file})
      }
    } catch {
      // Ignorar archivos YAML inválidos
    }
  }

  return parsed
}

/**
 * Parsea un array de {file, content} (desde GitHub API u otras fuentes).
 */
export function parseWorkflowContents(
  files: Array<{file: string; content: string}>,
): ParsedWorkflow[] {
  const parsed: ParsedWorkflow[] = []
  for (const {file, content} of files) {
    try {
      const wf = yaml.load(content) as ParsedWorkflow
      if (wf && typeof wf === 'object' && wf.jobs) {
        parsed.push({...wf, file})
      }
    } catch {
      // Ignorar
    }
  }
  return parsed
}

/**
 * Extrae las referencias `uses:` de un workflow: los steps de cada job y,
 * como referencia equivalente, `jobs.<id>.uses` (llamadas a reusable workflows).
 */
function extractSteps(workflow: ParsedWorkflow): WorkflowStep[] {
  const steps: WorkflowStep[] = []
  for (const [jobId, job] of Object.entries(workflow.jobs ?? {})) {
    if (typeof job.uses === 'string' && job.uses.trim() !== '') {
      steps.push({name: job.name ?? jobId, uses: job.uses.trim(), with: job.with})
    }
    for (const step of job.steps ?? []) {
      steps.push(step)
    }
  }
  return steps
}

/** Ruta de reusable workflow publicada por OSDO: `opensecdevops/<repo>/.github/workflows/<slug>.yml@<ref>` */
const OSDO_REUSABLE_WORKFLOW_RE = /^opensecdevops\/[^/]+\/\.github\/workflows\/([^/@]+)\.ya?ml@/i

/**
 * Indica si un `uses:` de reusable workflow OSDO corresponde al control.
 * El slug del control es el nombre de su action OSDO (p. ej. `osdo-sast`).
 */
function isOsdoReusableWorkflowFor(control: SecurityControl, uses: string): boolean {
  if (!control.osdoAction.startsWith('opensecdevops/')) return false
  const slug = control.osdoAction.split('/').pop()?.toLowerCase()
  const match = OSDO_REUSABLE_WORKFLOW_RE.exec(uses.trim())
  return Boolean(slug && match && match[1].toLowerCase() === slug)
}

/**
 * Dada una lista de workflows parseados, evalúa la cobertura de cada control.
 */
export function evaluateCoverage(workflows: ParsedWorkflow[]): WorkflowAuditResult {
  const allSteps = workflows.flatMap(w =>
    extractSteps(w).map(s => ({...s, _file: w.file})),
  )

  // ── 1. Cobertura de controles ─────────────────────────────────────────────
  const coverage: ControlCoverage[] = SECURITY_CONTROLS.map(control => {
    const result: ControlCoverage = {
      control,
      covered: false,
      coveredBy: null,
      isOsdo: false,
      files: [],
    }

    for (const step of allSteps as (WorkflowStep & {_file: string})[]) {
      // Controles estructurales (permissions, pinned) — evaluados por separado
      if (control.id === 'permissions' || control.id === 'pinned-actions') continue

      const uses = step.uses?.toLowerCase() ?? ''
      const run = step.run?.toLowerCase() ?? ''

      // Detectar action OSDO nativa (o reusable workflow OSDO del mismo control)
      if (uses.includes(control.osdoAction.toLowerCase()) || isOsdoReusableWorkflowFor(control, step.uses ?? '')) {
        result.covered = true
        result.isOsdo = true
        result.coveredBy = step.uses ?? control.osdoAction
        if (!result.files.includes(step._file)) result.files.push(step._file)
        continue
      }

      // Detectar equivalentes de terceros
      for (const equiv of control.equivalentActions) {
        if (uses.includes(equiv.toLowerCase())) {
          result.covered = true
          result.coveredBy = step.uses ?? equiv
          if (!result.files.includes(step._file)) result.files.push(step._file)
          break
        }
      }

      // Detectar palabras clave en `run:`
      for (const kw of control.runKeywords) {
        if (run.includes(kw.toLowerCase())) {
          result.covered = true
          result.coveredBy = `run: ${kw}`
          if (!result.files.includes(step._file)) result.files.push(step._file)
          break
        }
      }
    }

    return result
  })

  // ── 2. Cobertura de permisos ──────────────────────────────────────────────
  const permissionsCoverage = workflows.map(w => {
    const hasTopLevel = Boolean(w.permissions)
    const jobLevelHas = Object.values(w.jobs ?? {}).some(j => Boolean(j.permissions))
    return {file: w.file, hasPermissions: hasTopLevel || jobLevelHas}
  })

  // Actualizar el control 'permissions' con los resultados
  const permCtrl = coverage.find(c => c.control.id === 'permissions')!
  const allHavePerms = permissionsCoverage.length > 0 && permissionsCoverage.every(p => p.hasPermissions)
  if (permCtrl) {
    permCtrl.covered = allHavePerms
    permCtrl.coveredBy = allHavePerms ? 'permissions: declaradas en todos los workflows' : null
    permCtrl.files = permissionsCoverage.filter(p => p.hasPermissions).map(p => p.file)
  }

  // ── 3. Actions fijadas por hash ───────────────────────────────────────────
  const SHA_REGEX = /^[a-f0-9]{40}$/
  const pinnedActionsReport = workflows.map(w => {
    const steps = extractSteps(w)
    const usesSteps = steps.filter(s => s.uses)
    const unpinned = usesSteps
      .filter(s => {
        const ref = s.uses?.split('@')[1] ?? ''
        return ref && !SHA_REGEX.test(ref)
      })
      .map(s => s.uses!)
      .filter((v, i, a) => a.indexOf(v) === i) // deduplicate

    const ratio = usesSteps.length === 0 ? 1 : (usesSteps.length - unpinned.length) / usesSteps.length
    return {file: w.file, unpinned, ratio}
  })

  // Actualizar el control 'pinned-actions'
  const pinnedCtrl = coverage.find(c => c.control.id === 'pinned-actions')!
  const avgPinnedRatio = pinnedActionsReport.length === 0
    ? 0
    : pinnedActionsReport.reduce((s, r) => s + r.ratio, 0) / pinnedActionsReport.length
  if (pinnedCtrl) {
    pinnedCtrl.covered = avgPinnedRatio >= 0.9 // ≥90% fijadas por hash
    pinnedCtrl.coveredBy = pinnedCtrl.covered
      ? `${Math.round(avgPinnedRatio * 100)}% de actions fijadas por hash`
      : `Solo ${Math.round(avgPinnedRatio * 100)}% fijadas (se requiere ≥90%)`
  }

  // ── 4. Score total (sin excepciones; ver applyExceptions) ─────────────────
  const score = coverage
    .filter(c => c.covered)
    .reduce((sum, c) => sum + c.control.points, 0)

  return {
    workflowCount: workflows.length,
    workflows,
    coverage,
    score,
    scoreWithoutExceptions: score,
    exceptions: [],
    permissionsCoverage,
    pinnedActionsReport,
  }
}
