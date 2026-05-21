import {readFileSync, readdirSync, existsSync, statSync} from 'node:fs'
import {join} from 'node:path'
import yaml from 'js-yaml'
import {SECURITY_CONTROLS} from './baseline.js'
import type {SecurityControl} from './baseline.js'
import type {WorkflowAuditResult, ControlCoverage} from './workflow-parser.js'

// ── Tipos propios de GitLab CI ────────────────────────────────────────────────

export interface GitLabImageRef {
  name: string
  entrypoint?: string[]
  pull_policy?: string
}

export interface GitLabJob {
  stage?: string
  image?: string | GitLabImageRef
  script?: string[]
  before_script?: string[]
  after_script?: string[]
  variables?: Record<string, string>
  rules?: Array<{if?: string; when?: string}>
  only?: string[] | Record<string, string[]>
  except?: string[] | Record<string, string[]>
  extends?: string | string[]
  needs?: string[]
  allow_failure?: boolean
}

export interface GitLabInclude {
  template?: string
  project?: string
  file?: string | string[]
  ref?: string
  local?: string
  remote?: string
  component?: string
}

export interface ParsedGitLabPipeline {
  file: string
  stages?: string[]
  variables?: Record<string, string>
  image?: string | GitLabImageRef
  /** include: lista de templates de seguridad y referencias externas */
  include?: GitLabInclude[] | string
  /** Todos los jobs definidos en el pipeline */
  jobs: Record<string, GitLabJob>
}

// ── Mapa de detección GitLab por control ──────────────────────────────────────

/**
 * Para cada control OSDO, patrones específicos de GitLab CI.
 * La detección busca:
 *   - images:     nombre (o substring) de la imagen Docker del job
 *   - scripts:    comandos en script:/before_script:
 *   - stages:     nombre del stage del job
 *   - templates:  include.template de gitlab-org/gitlab
 *   - variables:  variables del job que identifican integración
 */
interface GitLabControlPatterns {
  images: string[]
  scripts: string[]
  stages: string[]
  templates: string[]
  variables: string[]
}

const GITLAB_PATTERNS: Record<string, GitLabControlPatterns> = {
  secrets: {
    images: ['gitleak', 'trufflehog', 'gitguardian', 'ggshield', 'detect-secrets'],
    scripts: ['gitleaks', 'trufflehog', 'ggshield', 'detect-secrets'],
    stages: ['secret_detection', 'secret-detection', 'secrets', 'leaks'],
    templates: ['Security/Secret-Detection.gitlab-ci.yml', 'Secret-Detection.gitlab-ci.yml'],
    variables: ['SECRETS_ANALYZER_IMAGE', 'SECRET_DETECTION_'],
  },
  sast: {
    images: ['sonar-scanner-cli', 'sonarsource', 'semgrep', 'codeql', 'checkmarx', 'veracode', 'fortify'],
    scripts: ['semgrep', 'sonar-scanner', 'bandit', 'phpcs-security-audit', 'gosec', 'brakeman', 'eslint --rule', 'bearer'],
    stages: ['sast', 'static_analysis', 'static-analysis', 'code_quality', 'code-quality'],
    templates: ['Security/SAST.gitlab-ci.yml', 'SAST.gitlab-ci.yml', 'Code-Quality.gitlab-ci.yml'],
    variables: ['SAST_ANALYZER_IMAGE', 'SAST_EXCLUDED_', 'SEMGREP_', 'SONARQUBE_'],
  },
  sca: {
    images: ['snyk', 'owasp/dependency-check', 'dependency-check', 'osv-scanner', 'aquasec/grype', 'grype'],
    scripts: ['snyk test', 'snyk monitor', 'osv-scanner', 'grype', 'trivy fs', 'npm audit --audit-level=', 'bundle-audit', 'safety check', 'pip-audit', 'govulncheck', 'dependency-check.sh'],
    stages: ['sca', 'dependency_scan', 'dependency-scan', 'vulnerability_scan', 'deps'],
    templates: ['Security/Dependency-Scanning.gitlab-ci.yml', 'Dependency-Scanning.gitlab-ci.yml'],
    variables: ['DS_ANALYZER_IMAGE', 'DS_EXCLUDED_', 'SNYK_TOKEN'],
  },
  'container-scan': {
    images: ['aquasec/trivy', 'aquasecurity/trivy', 'anchore/grype', 'docker/scout', 'snyk'],
    scripts: ['trivy image', 'grype ', 'docker scout cves', 'snyk container', 'dockle'],
    stages: ['container_scanning', 'docker_scan', 'image_scan', 'container_scan'],
    templates: ['Security/Container-Scanning.gitlab-ci.yml', 'Container-Scanning.gitlab-ci.yml'],
    variables: ['CS_ANALYZER_IMAGE', 'CS_REGISTRY_', 'TRIVY_'],
  },
  sbom: {
    images: ['cyclonedx', 'syft', 'cdxgen', 'anchore/syft'],
    scripts: ['cyclonedx', 'syft', 'cdxgen', 'make-sbom', 'trivy sbom', 'composer cyclonedx', 'composer cdx'],
    stages: ['sbom', 'sbom_scan', 'sbom-scan', 'bom_generation'],
    templates: [],
    variables: ['CYCLONEDX_', 'SBOM_'],
  },
  iac: {
    images: ['hadolint', 'checkov', 'bridgecrew/checkov', 'tfsec', 'tenable/terrascan', 'checkmarx/kics'],
    scripts: ['hadolint', 'checkov', 'tfsec', 'terrascan', 'kics-scan', 'tflint', 'infracost'],
    stages: ['iac_scan', 'iac-scan', 'infrastructure_scan', 'dockerfile_lint', 'terraform_scan', 'build_test'],
    templates: ['Security/Infrastructure-as-Code.gitlab-ci.yml', 'KICS.gitlab-ci.yml'],
    variables: ['KICS_', 'CHECKOV_', 'TFSEC_'],
  },
  signing: {
    images: ['cosign', 'sigstore', 'notary'],
    scripts: ['cosign sign', 'cosign attest', 'notation sign', 'cosign verify'],
    stages: ['sign_image', 'signing', 'image_signing'],
    templates: [],
    variables: ['COSIGN_', 'SIGSTORE_'],
  },
  slsa: {
    images: ['slsa-framework', 'in-toto'],
    scripts: ['slsa-verifier', 'provenance', 'in-toto-run', 'in-toto-record'],
    stages: ['provenance', 'slsa', 'attest'],
    templates: [],
    variables: ['SLSA_', 'PROVENANCE_'],
  },
  dast: {
    images: ['owasp/zap', 'zaproxy/stable', 'zaproxy/bare', 'stackhawk', 'nuclei'],
    scripts: ['zap-baseline', 'zap-full-scan', 'zap.sh', 'hawkscan', 'nuclei -u'],
    stages: ['dast', 'dynamic_scan', 'dynamic-scan', 'penetration_test'],
    templates: [
      'Security/DAST.gitlab-ci.yml',
      'DAST.gitlab-ci.yml',
      'Security/DAST-runner-validation.gitlab-ci.yml',
    ],
    variables: ['DAST_WEBSITE', 'DAST_', 'ZAP_'],
  },
  'policy-gate': {
    images: ['openpolicyagent/opa', 'open-policy-agent', 'conftest'],
    scripts: ['conftest test', 'opa eval', 'opa run', 'kyverno', 'rego'],
    stages: ['policy', 'policy_gate', 'compliance_gate', 'opa'],
    templates: [],
    variables: ['OPA_', 'CONFTEST_', 'KYVERNO_'],
  },
  license: {
    images: ['fossa', 'licensefinder', 'pivotalengineering/licensefinder'],
    scripts: ['fossa analyze', 'fossa test', 'license-finder', 'license_finder', 'licenseclassifier'],
    stages: ['license_scan', 'license-scan', 'license_check'],
    templates: [
      'Security/License-Scanning.gitlab-ci.yml',
      'License-Scanning.gitlab-ci.yml',
      'Security/License-Management.gitlab-ci.yml',
    ],
    variables: ['LICENSE_MANAGEMENT_', 'FOSSA_API_KEY'],
  },
  scorecard: {
    images: ['ossf/scorecard', 'gcr.io/openssf'],
    scripts: ['scorecard', 'ossf/scorecard'],
    stages: ['scorecard', 'openssf'],
    templates: [],
    variables: ['SCORECARD_'],
  },
}

// ── Palabras clave de GitLab CI que NO son jobs ───────────────────────────────

const GITLAB_NON_JOB_KEYS = new Set([
  'stages', 'variables', 'include', 'image', 'services', 'before_script',
  'after_script', 'cache', 'workflow', 'default', 'pages', '.pre', '.post',
])

function isHiddenJob(key: string): boolean {
  return key.startsWith('.')
}

// ── Parsing ───────────────────────────────────────────────────────────────────

/**
 * Parsea un archivo .gitlab-ci.yml y extrae los jobs semanificados.
 */
function parseGitLabYaml(content: string, file: string): ParsedGitLabPipeline | null {
  try {
    const raw = yaml.load(content) as Record<string, unknown>
    if (!raw || typeof raw !== 'object') return null

    const jobs: Record<string, GitLabJob> = {}
    for (const [key, val] of Object.entries(raw)) {
      if (GITLAB_NON_JOB_KEYS.has(key) || isHiddenJob(key)) continue
      if (val && typeof val === 'object' && !Array.isArray(val)) {
        jobs[key] = val as GitLabJob
      }
    }

    let include = raw.include as ParsedGitLabPipeline['include'] | undefined
    if (include && !Array.isArray(include)) {
      include = [include as GitLabInclude]
    }

    return {
      file,
      stages: raw.stages as string[] | undefined,
      variables: raw.variables as Record<string, string> | undefined,
      image: raw.image as string | GitLabImageRef | undefined,
      include: include as GitLabInclude[] | undefined,
      jobs,
    }
  } catch {
    return null
  }
}

/**
 * Carga todos los archivos .gitlab-ci.yml / .gitlab-ci desde un directorio.
 * También acepta el archivo raíz si el path apunta directamente a él.
 */
export function loadGitLabPipelinesFromDir(pathOrFile: string): ParsedGitLabPipeline[] {
  if (!existsSync(pathOrFile)) return []

  // Si es un archivo directamente
  try {
    const stat = statSync(pathOrFile)
    if (stat.isFile()) {
      const content = readFileSync(pathOrFile, 'utf8')
      const parsed = parseGitLabYaml(content, pathOrFile.split('/').pop() ?? pathOrFile)
      return parsed ? [parsed] : []
    }
  } catch { /* non-critical */ }

  // Si es un directorio — buscar archivos gitlab-ci
  const candidates = ['.gitlab-ci.yml', '.gitlab-ci.yaml', 'gitlab-ci.yml']
  const results: ParsedGitLabPipeline[] = []

  for (const candidate of candidates) {
    const full = join(pathOrFile, candidate)
    if (existsSync(full)) {
      const content = readFileSync(full, 'utf8')
      const parsed = parseGitLabYaml(content, candidate)
      if (parsed) results.push(parsed)
    }
  }

  // También buscar archivos .yml dentro de un directorio ci/ o .gitlab-ci/
  for (const subdir of ['ci', '.ci', '.gitlab-ci']) {
    const subPath = join(pathOrFile, subdir)
    if (existsSync(subPath)) {
      try {
        const files = readdirSync(subPath).filter(f => f.endsWith('.yml') || f.endsWith('.yaml'))
        for (const file of files) {
          const content = readFileSync(join(subPath, file), 'utf8')
          const parsed = parseGitLabYaml(content, `${subdir}/${file}`)
          if (parsed) results.push(parsed)
        }
      } catch { /* skip */ }
    }
  }

  return results
}

export function parseGitLabPipelineContents(
  files: Array<{file: string; content: string}>,
): ParsedGitLabPipeline[] {
  return files
    .map(({file, content}) => parseGitLabYaml(content, file))
    .filter((p): p is ParsedGitLabPipeline => p !== null)
}

// ── Evaluación de cobertura ───────────────────────────────────────────────────

/**
 * Normaliza el nombre de imagen: extrae solo el nombre sin tag/digest/registry.
 */
function normalizeImage(image: string | GitLabImageRef | undefined): string {
  if (!image) return ''
  const name = typeof image === 'string' ? image : image.name ?? ''
  return name.toLowerCase()
}

/**
 * Extrae todas las líneas de comando de un job.
 */
function extractJobScripts(job: GitLabJob): string {
  return [
    ...(job.script ?? []),
    ...(job.before_script ?? []),
    ...(job.after_script ?? []),
  ].join('\n').toLowerCase()
}

/**
 * Extrae los nombres de template de todos los `include:`.
 */
function extractTemplates(pipeline: ParsedGitLabPipeline): string[] {
  const includes = Array.isArray(pipeline.include) ? pipeline.include : []
  return includes.flatMap(i => {
    const templates: string[] = []
    if (i.template) templates.push(i.template.toLowerCase())
    if (i.file) {
      const files = Array.isArray(i.file) ? i.file : [i.file]
      templates.push(...files.map(f => f.toLowerCase()))
    }
    return templates
  })
}

/**
 * Verifica si un job tiene protección de acceso (equivalente a `permissions:` en GitHub).
 * En GitLab esto se logra con `rules:`, `only:`, o `protected: true` en variables.
 */
function jobHasAccessControl(job: GitLabJob): boolean {
  return Boolean(job.rules && job.rules.length > 0) ||
    Boolean(job.only && Object.keys(job.only).length > 0)
}

/**
 * Verifica si una referencia de imagen está fijada por SHA digest.
 * Formato: image@sha256:abc123...
 */
function isImagePinnedBySha(image: string | GitLabImageRef | undefined): boolean {
  const name = normalizeImage(image)
  return name.includes('@sha256:')
}

/**
 * Dado un conjunto de pipelines GitLab, evalúa la cobertura de controles OSDO.
 * Retorna el mismo tipo `WorkflowAuditResult` que usa el auditor de GitHub,
 * para que el reporter y el comando puedan operar sin cambios.
 */
export function evaluateGitLabCoverage(pipelines: ParsedGitLabPipeline[]): WorkflowAuditResult {
  const coverage: ControlCoverage[] = SECURITY_CONTROLS.map(control => {
    const result: ControlCoverage = {
      control,
      covered: false,
      coveredBy: null,
      isOsdo: false,
      files: [],
    }

    // Controles estructurales — evaluados por separado abajo
    if (control.id === 'permissions' || control.id === 'pinned-actions') return result

    const patterns = GITLAB_PATTERNS[control.id]
    if (!patterns) return result

    for (const pipeline of pipelines) {
      // 1. Buscar en include: (plantillas de GitLab)
      const templates = extractTemplates(pipeline)
      for (const tmpl of patterns.templates) {
        if (templates.some(t => t.includes(tmpl.toLowerCase()))) {
          result.covered = true
          result.coveredBy = `include: ${tmpl}`
          if (!result.files.includes(pipeline.file)) result.files.push(pipeline.file)
        }
      }

      if (result.covered) continue

      // 2. Buscar en cada job
      for (const [jobName, job] of Object.entries(pipeline.jobs)) {
        const imageStr = normalizeImage(job.image)
        const scripts = extractJobScripts(job)
        const stage = (job.stage ?? '').toLowerCase()
        const jobVars = Object.keys(job.variables ?? {}).join(' ').toLowerCase()

        // OSDO action nativa (si el job la usa vía script)
        if (scripts.includes(control.osdoAction.toLowerCase())) {
          result.covered = true
          result.isOsdo = true
          result.coveredBy = `${jobName}: osdo-action`
          if (!result.files.includes(pipeline.file)) result.files.push(pipeline.file)
          break
        }

        // Por imagen Docker
        const imgMatch = patterns.images.find(img => imageStr.includes(img.toLowerCase()))
        if (imgMatch) {
          result.covered = true
          result.coveredBy = `${jobName} (image: ${imgMatch})`
          if (!result.files.includes(pipeline.file)) result.files.push(pipeline.file)
          break
        }

        // Por palabras clave en scripts
        const scriptMatch = patterns.scripts.find(kw => scripts.includes(kw.toLowerCase()))
        if (scriptMatch) {
          result.covered = true
          result.coveredBy = `${jobName}: ${scriptMatch}`
          if (!result.files.includes(pipeline.file)) result.files.push(pipeline.file)
          break
        }

        // Por nombre de stage
        const stageMatch = patterns.stages.find(s => stage.includes(s.toLowerCase()))
        if (stageMatch) {
          result.covered = true
          result.coveredBy = `stage: ${job.stage} (${jobName})`
          if (!result.files.includes(pipeline.file)) result.files.push(pipeline.file)
          break
        }

        // Por variables
        const varMatch = patterns.variables.find(v => jobVars.includes(v.toLowerCase()))
        if (varMatch) {
          result.covered = true
          result.coveredBy = `${jobName}: variable ${varMatch}`
          if (!result.files.includes(pipeline.file)) result.files.push(pipeline.file)
          break
        }
      }
    }

    return result
  })

  // ── Control: permissions (rules/only en jobs sensibles) ───────────────────
  const permCtrl = coverage.find(c => c.control.id === 'permissions')!
  const permissionsCoverage = pipelines.map(p => {
    const sensitiveJobs = Object.values(p.jobs).filter(j => {
      const stage = (j.stage ?? '').toLowerCase()
      return stage.includes('sign') || stage.includes('push') || stage.includes('deploy') || stage.includes('release')
    })
    const allProtected = sensitiveJobs.length === 0 ||
      sensitiveJobs.every(j => jobHasAccessControl(j))
    return {file: p.file, hasPermissions: allProtected}
  })

  if (permCtrl) {
    const allOk = permissionsCoverage.length > 0 && permissionsCoverage.every(p => p.hasPermissions)
    permCtrl.covered = allOk
    permCtrl.coveredBy = allOk
      ? 'rules:/only: declarados en jobs sensibles'
      : 'Jobs sensibles sin rules:/only: que limiten ejecución'
    permCtrl.files = permissionsCoverage.filter(p => p.hasPermissions).map(p => p.file)
  }

  // ── Control: pinned-actions (imágenes con @sha256:) ───────────────────────
  const SHA_RATIO_THRESHOLD = 0.5 // menos exigente que GitHub (muchas imágenes privadas usan latest)
  const pinnedActionsReport = pipelines.map(p => {
    const allImages = [
      p.image, // global image
      ...Object.values(p.jobs).map(j => j.image),
    ].filter(Boolean) as (string | GitLabImageRef)[]

    const pinned = allImages.filter(i => isImagePinnedBySha(i))
    const ratio = allImages.length === 0 ? 1 : pinned.length / allImages.length

    const unpinned = allImages
      .filter(i => !isImagePinnedBySha(i))
      .map(i => normalizeImage(i))
      .filter((v, idx, arr) => arr.indexOf(v) === idx) // deduplicate

    return {file: p.file, unpinned, ratio}
  })

  const pinnedCtrl = coverage.find(c => c.control.id === 'pinned-actions')!
  const avgRatio = pinnedActionsReport.length === 0
    ? 0
    : pinnedActionsReport.reduce((s, r) => s + r.ratio, 0) / pinnedActionsReport.length

  if (pinnedCtrl) {
    pinnedCtrl.covered = avgRatio >= SHA_RATIO_THRESHOLD
    pinnedCtrl.coveredBy = pinnedCtrl.covered
      ? `${Math.round(avgRatio * 100)}% de imágenes fijadas por SHA digest`
      : `Solo ${Math.round(avgRatio * 100)}% de imágenes con @sha256 (se recomienda >50%)`
  }

  // ── Score total ───────────────────────────────────────────────────────────
  const score = coverage.filter(c => c.covered).reduce((s, c) => s + c.control.points, 0)

  return {
    workflowCount: pipelines.length,
    workflows: pipelines as unknown as import('./workflow-parser.js').ParsedWorkflow[],
    coverage,
    score,
    permissionsCoverage,
    pinnedActionsReport,
  }
}
