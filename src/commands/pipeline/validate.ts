import {Flags} from '@oclif/core'
import {existsSync, readdirSync, readFileSync} from 'node:fs'
import {join} from 'node:path'
import {BaseCommand} from '../../lib/base-command.js'

interface ValidationIssue {
  type: 'error' | 'warning' | 'info'
  message: string
}

interface FileValidation {
  file: string
  issues: ValidationIssue[]
  hasOsdoActions: boolean
  hasPermissions: boolean
  hasUnpinnedVersions: boolean
  outdatedActions: string[]
}

// Expresión regular para detectar versiones de actions OSDO
const OSDO_ACTION_PATTERN = /opensecdevops\/osdo-actions[^\s'"]+@([^\s'"]+)/g
const UNPINNED_PATTERN = /@(main|master|HEAD)\b/
const OLD_VERSION_PATTERN = /opensecdevops\/osdo-actions[^\s'"]*@([^/\s'"]+\/v1\.\d+\.\d+|v1(?:\.\d+)?(?:\.\d+)?)/g

function validateWorkflowFile(filePath: string): FileValidation {
  const content = readFileSync(filePath, 'utf8')
  const issues: ValidationIssue[] = []
  const outdatedActions: string[] = []

  // Comprobar presencia de actions OSDO
  const hasOsdoActions = content.includes('opensecdevops/osdo-actions')

  if (!hasOsdoActions) {
    issues.push({
      type: 'warning',
      message: 'No se usan actions OSDO. Considera añadir escaneos de seguridad.',
    })
  }

  // Comprobar bloque de permissions
  const hasPermissions = /^\s*permissions\s*:/m.test(content)
  if (!hasPermissions) {
    issues.push({
      type: 'error',
      message: 'Falta bloque "permissions". Añade permisos mínimos para cumplir con OIDC y GITHUB_TOKEN hardening.',
    })
  }

  // Comprobar versiones no pinneadas (usando @main, @master, @HEAD)
  const hasUnpinnedVersions = UNPINNED_PATTERN.test(content)
  if (hasUnpinnedVersions) {
    issues.push({
      type: 'error',
      message: 'Se usan versiones no pinneadas (@main, @master). Esto es un riesgo de supply chain.',
    })
  }

  // Detectar actions OSDO en v1.x (desactualizadas)
  const contentCopy = content
  let match: RegExpExecArray | null
  const oldPattern = new RegExp(OLD_VERSION_PATTERN.source, 'g')

  while ((match = oldPattern.exec(contentCopy)) !== null) {
    const actionRef = match[0]
    outdatedActions.push(actionRef)
    issues.push({
      type: 'warning',
      message: `Action desactualizada: "${actionRef}" → sugiere actualizar a v2.0.0`,
    })
  }

  // Verificar que checkout use fetch-depth: 0 para Gitleaks
  if (content.includes('osdo-secrets-scan') && !content.includes('fetch-depth: 0')) {
    issues.push({
      type: 'warning',
      message: 'osdo-secrets-scan funciona mejor con "fetch-depth: 0" en actions/checkout para escanear el historial completo.',
    })
  }

  // Verificar que haya al menos un job de SAST
  if (hasOsdoActions && !content.includes('osdo-sast')) {
    issues.push({
      type: 'warning',
      message: 'No se detecta osdo-sast. Considera añadir análisis estático.',
    })
  }

  return {
    file: filePath,
    issues,
    hasOsdoActions,
    hasPermissions,
    hasUnpinnedVersions,
    outdatedActions,
  }
}

export default class PipelineValidate extends BaseCommand {
  static description = 'Validar workflows CI/CD: versiones pinneadas, permisos y acciones OSDO'

  static examples = [
    '<%= config.bin %> pipeline validate',
    '<%= config.bin %> pipeline validate --file .github/workflows/osdo-security.yml',
    '<%= config.bin %> pipeline validate --output json',
  ]

  static flags = {
    ...BaseCommand.globalFlags,
    file: Flags.string({
      char: 'f',
      description: 'Archivo de workflow a validar (por defecto escanea todos los de .github/workflows/)',
    }),
  }

  async run(): Promise<void> {
    const {flags} = await this.parse(PipelineValidate)

    this.log('\nOSDO Pipeline Validator')
    this.log('═══════════════════════════════════════\n')

    // Determinar qué archivos validar
    const filesToValidate: string[] = []

    if (flags.file) {
      if (!existsSync(flags.file)) {
        this.error(`Archivo no encontrado: ${flags.file}`, {exit: 1})
      }

      filesToValidate.push(flags.file)
    } else {
      const workflowDir = join('.github', 'workflows')
      if (!existsSync(workflowDir)) {
        this.warn(`No existe el directorio ${workflowDir}. Genera un pipeline con: osdo pipeline generate`)
        return
      }

      const entries = readdirSync(workflowDir)
      for (const entry of entries) {
        if (entry.endsWith('.yml') || entry.endsWith('.yaml')) {
          filesToValidate.push(join(workflowDir, entry))
        }
      }

      if (filesToValidate.length === 0) {
        this.warn(`No se encontraron archivos .yml en ${workflowDir}`)
        return
      }
    }

    const validations: FileValidation[] = []

    for (const filePath of filesToValidate) {
      const result = validateWorkflowFile(filePath)
      validations.push(result)
    }

    if (flags.output === 'json') {
      this.log(JSON.stringify(validations, null, 2))
      return
    }

    // Mostrar resultados
    let totalErrors = 0
    let totalWarnings = 0

    for (const v of validations) {
      const errors = v.issues.filter(i => i.type === 'error').length
      const warnings = v.issues.filter(i => i.type === 'warning').length
      totalErrors += errors
      totalWarnings += warnings

      const statusIcon = errors > 0 ? '✗' : warnings > 0 ? '○' : '✓'
      this.log(`${statusIcon} ${v.file}`)

      if (v.hasOsdoActions) {
        this.log('  ✓ Usa actions OSDO')
      }

      if (v.hasPermissions) {
        this.log('  ✓ Bloque permissions definido')
      }

      if (!v.hasUnpinnedVersions) {
        this.log('  ✓ Actions pinneadas a versiones específicas')
      }

      for (const issue of v.issues) {
        const icon = issue.type === 'error' ? '  ✗' : issue.type === 'warning' ? '  ⚠' : '  ℹ'
        this.log(`${icon} ${issue.message}`)
      }

      this.log('')
    }

    this.log('═══════════════════════════════════════')
    this.log(`Archivos validados: ${validations.length}  |  Errores: ${totalErrors}  |  Advertencias: ${totalWarnings}`)

    if (totalErrors > 0) {
      this.error(`Validación fallida — ${totalErrors} error(es) encontrado(s)`, {exit: 1})
    }

    this.log('\nValidación superada')
  }
}
