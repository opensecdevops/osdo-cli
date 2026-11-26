/**
 * Excepciones explícitas para `osdo audit` (controles N/A con responsable y caducidad).
 *
 * Archivo: `.osdo/exceptions.yml` del repositorio auditado (o `--exceptions <archivo>`).
 * Formato: lista YAML de entradas con exactamente estos campos:
 *
 *   - control: sbom                  # id de SECURITY_CONTROLS (no esenciales)
 *     status: not-applicable         # único valor admitido
 *     reason: "Librería sin artefactos publicados; no genera SBOM"   # ≥ 20 caracteres
 *     owner: equipo-plataforma       # responsable de la excepción
 *     approved_by: jefe-seguridad    # quién la aprobó
 *     expires: 2027-06-30            # YYYY-MM-DD, no pasada, ≤ 365 días desde hoy
 *
 * Los controles de nivel `esencial` no pueden exceptuarse.
 */
import {existsSync, readFileSync} from 'node:fs'
import yaml from 'js-yaml'
import {SECURITY_CONTROLS} from './baseline.js'
import type {SecurityControl} from './baseline.js'
import type {WorkflowAuditResult} from './workflow-parser.js'

/** Ruta por defecto, relativa al directorio del repositorio auditado. */
export const DEFAULT_EXCEPTIONS_PATH = '.osdo/exceptions.yml'
export const MIN_REASON_LENGTH = 20
export const MAX_EXCEPTION_DAYS = 365

const FIELDS = ['control', 'status', 'reason', 'owner', 'approved_by', 'expires'] as const
type Field = typeof FIELDS[number]
const DATE_RE = /^\d{4}-\d{2}-\d{2}$/

export interface AuditException {
  control: string
  status: 'not-applicable'
  reason: string
  owner: string
  approved_by: string
  /** Fecha de caducidad, YYYY-MM-DD */
  expires: string
}

/** Error de validación del archivo de excepciones. Lleva todos los problemas encontrados. */
export class AuditExceptionsError extends Error {
  readonly problems: string[]

  constructor(filePath: string, problems: string[]) {
    super([`Archivo de excepciones inválido: ${filePath}`, ...problems.map(p => `  - ${p}`)].join('\n'))
    this.name = 'AuditExceptionsError'
    this.problems = problems
  }
}

/** Suma días a una fecha YYYY-MM-DD con aritmética UTC. */
export function addDays(isoDate: string, days: number): string {
  const date = new Date(`${isoDate}T00:00:00Z`)
  date.setUTCDate(date.getUTCDate() + days)
  return date.toISOString().slice(0, 10)
}

function isCalendarDate(value: string): boolean {
  if (!DATE_RE.test(value)) return false
  const date = new Date(`${value}T00:00:00Z`)
  return !Number.isNaN(date.getTime()) && date.toISOString().slice(0, 10) === value
}

/**
 * Valida y devuelve las excepciones de un documento YAML.
 * `today` (YYYY-MM-DD) se inyecta para que la validación de caducidad sea determinista.
 * Lanza `AuditExceptionsError` con todos los problemas si alguna entrada no es válida.
 */
export function parseExceptions(content: string, today: string, filePath = DEFAULT_EXCEPTIONS_PATH): AuditException[] {
  let doc: unknown
  try {
    // JSON_SCHEMA evita que `expires: 2027-06-30` sin comillas se convierta en Date.
    doc = yaml.load(content, {schema: yaml.JSON_SCHEMA})
  } catch (err) {
    const detail = err instanceof Error ? err.message : String(err)
    throw new AuditExceptionsError(filePath, [`YAML inválido: ${detail}`])
  }

  if (doc === undefined || doc === null) return []
  if (!Array.isArray(doc)) {
    throw new AuditExceptionsError(filePath, [
      'La raíz debe ser una lista de entradas (cada una empieza por "- control: ...")',
    ])
  }

  const controls = new Map<string, SecurityControl>(SECURITY_CONTROLS.map(c => [c.id, c]))
  const maxDate = addDays(today, MAX_EXCEPTION_DAYS)
  const problems: string[] = []
  const exceptions: AuditException[] = []
  const firstEntryByControl = new Map<string, number>()

  doc.forEach((raw: unknown, index: number) => {
    const entryNumber = index + 1
    const at = (message: string): void => {
      problems.push(`Entrada #${entryNumber}: ${message}`)
    }

    if (typeof raw !== 'object' || raw === null || Array.isArray(raw)) {
      at('debe ser un objeto con los campos control, status, reason, owner, approved_by y expires')
      return
    }

    const entry = raw as Record<string, unknown>
    for (const key of Object.keys(entry)) {
      if (!(FIELDS as readonly string[]).includes(key)) at(`campo desconocido '${key}'`)
    }

    const text = (field: Field): string | undefined => {
      const value = entry[field]
      if (value === undefined || value === null || (typeof value === 'string' && value.trim() === '')) {
        at(`falta el campo obligatorio '${field}'`)
        return undefined
      }
      if (typeof value !== 'string') {
        at(`'${field}' debe ser texto`)
        return undefined
      }
      return value.trim()
    }

    const control = text('control')
    const status = text('status')
    const reason = text('reason')
    const owner = text('owner')
    const approvedBy = text('approved_by')
    const expires = text('expires')

    if (control !== undefined) {
      const definition = controls.get(control)
      if (!definition) {
        at(`control desconocido '${control}'`)
      } else if (definition.level === 'esencial') {
        at(`el control '${control}' es esencial y no puede exceptuarse`)
      } else if (firstEntryByControl.has(control)) {
        at(`el control '${control}' ya está exceptuado en la entrada #${firstEntryByControl.get(control)}`)
      } else {
        firstEntryByControl.set(control, entryNumber)
      }
    }

    if (status !== undefined && status !== 'not-applicable') {
      at(`'status' debe ser 'not-applicable' (recibido '${status}')`)
    }

    if (reason !== undefined && reason.length < MIN_REASON_LENGTH) {
      at(`'reason' debe tener al menos ${MIN_REASON_LENGTH} caracteres (tiene ${reason.length})`)
    }

    if (expires !== undefined) {
      if (!isCalendarDate(expires)) {
        at(`'expires' debe ser una fecha válida YYYY-MM-DD (recibido '${expires}')`)
      } else if (expires < today) {
        at(`la excepción caducó el ${expires}`)
      } else if (expires > maxDate) {
        at(`'expires' (${expires}) supera el máximo de ${MAX_EXCEPTION_DAYS} días desde hoy (${maxDate})`)
      }
    }

    if (control !== undefined && status !== undefined && reason !== undefined && owner !== undefined
      && approvedBy !== undefined && expires !== undefined) {
      exceptions.push({
        control,
        status: 'not-applicable',
        reason,
        owner,
        approved_by: approvedBy,
        expires,
      })
    }
  })

  if (problems.length > 0) throw new AuditExceptionsError(filePath, problems)
  return exceptions
}

/** Lee y valida el archivo de excepciones. Lanza `AuditExceptionsError` si no existe o no es válido. */
export function loadExceptionsFile(filePath: string, today: string): AuditException[] {
  if (!existsSync(filePath)) throw new AuditExceptionsError(filePath, ['el archivo no existe'])
  return parseExceptions(readFileSync(filePath, 'utf8'), today, filePath)
}

/**
 * Aplica las excepciones a un resultado de evaluación.
 * Score = puntos cubiertos / puntos aplicables * 100, redondeado hacia abajo.
 * Los controles exceptuados se excluyen de numerador y denominador.
 * `scoreWithoutExceptions` conserva la puntuación bruta.
 */
export function applyExceptions(result: WorkflowAuditResult, exceptions: AuditException[]): WorkflowAuditResult {
  const excepted = new Map(exceptions.map(e => [e.control, e]))

  const applicablePoints = SECURITY_CONTROLS
    .filter(c => !excepted.has(c.id))
    .reduce((sum, c) => sum + c.points, 0)
  const coveredApplicablePoints = result.coverage
    .filter(c => c.covered && !excepted.has(c.control.id))
    .reduce((sum, c) => sum + c.control.points, 0)

  return {
    ...result,
    coverage: result.coverage.map(c => ({...c, exception: excepted.get(c.control.id)})),
    score: applicablePoints > 0 ? Math.floor((coveredApplicablePoints * 100) / applicablePoints) : 0,
    scoreWithoutExceptions: result.scoreWithoutExceptions,
    exceptions,
  }
}
