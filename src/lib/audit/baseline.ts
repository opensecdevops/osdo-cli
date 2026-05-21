/**
 * OSDO Audit Baseline
 *
 * Define los controles de seguridad mínimos requeridos para cumplir con OSDO,
 * organizados en 3 niveles de madurez:
 *
 *   ESENCIAL     → mínimo aceptable para cualquier empresa
 *   RECOMENDADO  → estándar OSDO para equipos en crecimiento
 *   COMPLETO     → máxima cobertura DevSecOps / SLSA L3 / OpenSSF ≥8
 *
 * Cada control incluye:
 *  - La action OSDO nativa que lo cubre
 *  - Equivalentes de terceros (detectados como cobertura parcial)
 *  - Patrones en `run:` que indiquen uso de la herramienta sin action
 */

export type AuditLevel = 'esencial' | 'recomendado' | 'completo'

export interface SecurityControl {
  /** Identificador único del control */
  id: string
  /** Nombre legible */
  name: string
  /** Qué riesgo mitiga */
  description: string
  /** Nivel de madurez requerido */
  level: AuditLevel
  /** Puntos al cumplir (total 100) */
  points: number
  /** Action OSDO nativa */
  osdoAction: string
  /**
   * Patterns (substring) de `uses:` de terceros que cubren este control.
   * Si el workflow usa cualquiera de estos, se considera cubierto (aunque no sea OSDO).
   */
  equivalentActions: string[]
  /**
   * Palabras clave en `run:` que indican uso de herramienta sin action dedicada.
   */
  runKeywords: string[]
  /** Frameworks que requieren este control */
  frameworks: string[]
  /** Recomendación breve para el reporte */
  recommendation: string
}

/**
 * 16 controles organizados en 3 niveles.
 * Puntuación total: 100 pts
 *
 * Esencial (3 controles × 14pts = 42pts)
 * Recomendado (5 controles × 8pts = 40pts)
 * Completo (6 controles × 3pts = 18pts)
 */
export const SECURITY_CONTROLS: SecurityControl[] = [
  // ── ESENCIAL (mínimo absoluto) ───────────────────────────────────────────

  {
    id: 'secrets',
    name: 'Escaneo de Secretos',
    description: 'Detecta credenciales, API keys y tokens expuestos en el código',
    level: 'esencial',
    points: 14,
    osdoAction: 'opensecdevops/osdo-actions/actions/osdo-secrets-scan',
    equivalentActions: [
      'gitleaks/gitleaks-action',
      'trufflesecurity/trufflehog',
      'zricethezav/gitleaks-action',
      'secret-scanning',
      'detect-secrets',
      'gitguardian/ggshield-action',
    ],
    runKeywords: ['gitleaks', 'trufflehog', 'detect-secrets', 'ggshield'],
    frameworks: ['OWASP A09', 'OpenSSF Token-Permissions'],
    recommendation:
      'Agrega `osdo-secrets-scan@v2` al pipeline de CI para detectar secretos antes de que lleguen a producción.',
  },
  {
    id: 'sast',
    name: 'SAST (Análisis Estático)',
    description: 'Detecta vulnerabilidades en el código fuente sin ejecutarlo',
    level: 'esencial',
    points: 14,
    osdoAction: 'opensecdevops/osdo-actions/actions/osdo-sast',
    equivalentActions: [
      'github/codeql-action',
      'returntocorp/semgrep-action',
      'semgrep/semgrep-action',
      'SonarSource/sonarcloud-github-action',
      'SonarSource/sonarqube-scan-action',
      'AppThreat/joern-action',
      'snyk/actions',
    ],
    runKeywords: ['semgrep', 'codeql', 'sonar-scanner', 'bandit', 'eslint --rule', 'bearer'],
    frameworks: ['OWASP A03', 'SLSA Build L2', 'OpenSSF SAST'],
    recommendation:
      'Usa `osdo-sast@v2` (Semgrep + reglas OSDO) o habilita CodeQL en GitHub → Settings → Code Security.',
  },
  {
    id: 'sca',
    name: 'SCA (Dependencias)',
    description: 'Detecta vulnerabilidades conocidas en librerías de terceros',
    level: 'esencial',
    points: 14,
    osdoAction: 'opensecdevops/osdo-actions/actions/osdo-sca',
    equivalentActions: [
      'snyk/actions',
      'aquasecurity/trivy-action',
      'anchore/grype-action',
      'ossindex/ossi-maven-plugin',
      'dependency-review-action',
      'github/dependency-review',
      'ossf/scorecard-action',
      'osv-scanner',
    ],
    runKeywords: ['snyk test', 'osv-scanner', 'grype', 'trivy fs', 'npm audit', 'pip-audit', 'govulncheck'],
    frameworks: ['OWASP A06', 'OpenSSF Vulnerabilities', 'SLSA Deps'],
    recommendation:
      'Agrega `osdo-sca@v2` o habilita Dependabot security updates + `github/dependency-review-action` en PRs.',
  },

  // ── RECOMENDADO (estándar OSDO) ───────────────────────────────────────────

  {
    id: 'container-scan',
    name: 'Escaneo de Contenedores',
    description: 'Detecta vulnerabilidades en imágenes Docker/OCI',
    level: 'recomendado',
    points: 8,
    osdoAction: 'opensecdevops/osdo-actions/actions/osdo-container-scan',
    equivalentActions: [
      'aquasecurity/trivy-action',
      'anchore/grype-action',
      'docker/scout-action',
      'aquasecurity/trivy',
      'snyk/actions/docker',
      'anchore/scan-action',
    ],
    runKeywords: ['trivy image', 'grype', 'docker scout', 'snyk container', 'dockle'],
    frameworks: ['OWASP A05', 'CIS Docker', 'SLSA Build L3'],
    recommendation:
      'Si construyes imágenes Docker, agrega `osdo-container-scan@v2` para escanear antes de publicar al registry.',
  },
  {
    id: 'sbom',
    name: 'Generación de SBOM',
    description: 'Genera inventario de componentes de software (SPDX/CycloneDX)',
    level: 'recomendado',
    points: 8,
    osdoAction: 'opensecdevops/osdo-actions/actions/osdo-sbom',
    equivalentActions: [
      'anchore/sbom-action',
      'CycloneDX/gh-dotnet-generate-sbom',
      'CycloneDX/gh-node-module-generate-bom',
      'sigstore/cosign-installer',
      'advanced-security/sbom-generator',
    ],
    runKeywords: ['syft', 'cyclonedx', 'spdx', 'sbom', 'trivy sbom'],
    frameworks: ['SLSA L2', 'OpenSSF SBOM', 'NTIA'],
    recommendation:
      'El SBOM es requerido para SLSA L2+. Usa `osdo-sbom@v2` para generar SPDX + CycloneDX en cada release.',
  },
  {
    id: 'iac',
    name: 'IaC Security (Infra as Code)',
    description: 'Detecta malas configuraciones en Terraform, Kubernetes, Dockerfiles',
    level: 'recomendado',
    points: 8,
    osdoAction: 'opensecdevops/osdo-actions/actions/osdo-iac-scan',
    equivalentActions: [
      'bridgecrewio/checkov-action',
      'aquasecurity/tfsec-action',
      'aquasecurity/trivy-action',
      'snyk/actions/iac',
      'tenable/terrascan-action',
      'hadolint/hadolint-action',
      'luke142367/hadolint-action',
    ],
    runKeywords: ['checkov', 'tfsec', 'terrascan', 'hadolint', 'kics', 'tflint'],
    frameworks: ['OWASP A05', 'CIS Benchmarks', 'NIST CM-2'],
    recommendation:
      'Si usas IaC (Terraform, Helm, Kubernetes), agrega `osdo-iac-scan@v2` o `bridgecrewio/checkov-action`.',
  },
  {
    id: 'permissions',
    name: 'Permisos Mínimos en Workflows',
    description: 'El workflow declara `permissions:` con alcance reducido (GITHUB_TOKEN)',
    level: 'recomendado',
    points: 8,
    osdoAction: 'N/A — configuración estructural del workflow',
    equivalentActions: [],
    runKeywords: [],
    frameworks: ['OpenSSF Token-Permissions', 'SLSA Build L3'],
    recommendation:
      'Agrega `permissions: read-all` o permisos específicos al inicio de cada workflow.\n  Ver: https://docs.github.com/actions/using-workflows/workflow-syntax-for-github-actions#permissions',
  },
  {
    id: 'pinned-actions',
    name: 'Actions Fijadas por Hash',
    description: 'Todas las `uses:` están fijadas por hash SHA1, no por tags mutables',
    level: 'recomendado',
    points: 8,
    osdoAction: 'N/A — buena práctica del workflow',
    equivalentActions: [],
    runKeywords: [],
    frameworks: ['OpenSSF Pinned-Dependencies', 'SLSA Build Integrity'],
    recommendation:
      'Fija las actions por hash: `uses: actions/checkout@v4` → `uses: actions/checkout@11bd71901bbe5b1630ceea73d27597364c9af683`\n  Herramienta: https://github.com/step-security/harden-runner',
  },

  // ── COMPLETO (OSDO Full / SLSA L3 / OpenSSF ≥8) ──────────────────────────

  {
    id: 'signing',
    name: 'Firma de Artefactos',
    description: 'Firma imágenes y binarios con Cosign/Sigstore',
    level: 'completo',
    points: 3,
    osdoAction: 'opensecdevops/osdo-actions/actions/osdo-signing',
    equivalentActions: [
      'sigstore/cosign-installer',
      'sigstore/gh-action-sigstore-python',
      'docker/metadata-action',
    ],
    runKeywords: ['cosign sign', 'cosign attest', 'sigstore'],
    frameworks: ['SLSA L3', 'OpenSSF Signed-Releases', 'Supply Chain'],
    recommendation:
      'Firma imágenes y releases con Cosign. Usa `osdo-signing@v2` o instala cosign + `cosign sign` en el job de release.',
  },
  {
    id: 'slsa',
    name: 'SLSA Provenance (L3)',
    description: 'Genera attestations de procedencia del build (cadena de custodia)',
    level: 'completo',
    points: 3,
    osdoAction: 'opensecdevops/osdo-actions/actions/osdo-slsa-provenance',
    equivalentActions: [
      'slsa-framework/slsa-github-generator',
      'actions/attest-build-provenance',
      'in-toto/github-action',
    ],
    runKeywords: ['slsa-verifier', 'provenance', 'attest-build-provenance'],
    frameworks: ['SLSA L3', 'OpenSSF SLSA', 'Supply Chain'],
    recommendation:
      'Usa `slsa-framework/slsa-github-generator` o `osdo-slsa-provenance@v2` para generar provenance automáticamente en releases.',
  },
  {
    id: 'dast',
    name: 'DAST (Escaneo Dinámico)',
    description: 'Pruebas de seguridad sobre la aplicación en ejecución',
    level: 'completo',
    points: 3,
    osdoAction: 'opensecdevops/osdo-actions/actions/osdo-dast-scan',
    equivalentActions: [
      'zaproxy/action-full-scan',
      'zaproxy/action-baseline',
      'stackhawk/action-hawkscan',
      'OWASP/owasp-zap-action',
    ],
    runKeywords: ['zap', 'hawkscan', 'nuclei', 'nikto', 'wapiti'],
    frameworks: ['OWASP A01-A10', 'PCI-DSS 6.3'],
    recommendation:
      'Agrega `zaproxy/action-baseline` o `osdo-dast-scan@v2` en un job que levante el entorno de staging.',
  },
  {
    id: 'policy-gate',
    name: 'Policy Gate (OPA/Kyverno)',
    description: 'Verifica cumplimiento de políticas de seguridad como condición de CI',
    level: 'completo',
    points: 3,
    osdoAction: 'opensecdevops/osdo-actions/actions/osdo-policy-gate',
    equivalentActions: [
      'open-policy-agent/conftest-action',
      'anderseknert/go-opa',
      'kyverno/action',
    ],
    runKeywords: ['conftest', 'opa eval', 'kyverno', 'rego'],
    frameworks: ['NIST SP 800-53', 'OpenSSF Policy'],
    recommendation:
      'Define políticas OPA en `.osdo/policies/*.rego` y usa `osdo-policy-gate@v2` o `conftest` para validarlas en CI.',
  },
  {
    id: 'license',
    name: 'Cumplimiento de Licencias',
    description: 'Verifica que las dependencias usen licencias permitidas por la empresa',
    level: 'completo',
    points: 3,
    osdoAction: 'opensecdevops/osdo-actions/actions/osdo-license-scan',
    equivalentActions: [
      'fossa-contrib/fossa-action',
      'pivotal/LicenseFinder',
      'google/licenseclassifier',
    ],
    runKeywords: ['fossa', 'license-checker', 'licensefinder', 'licensecheck'],
    frameworks: ['OSS Compliance', 'SBOM Policy'],
    recommendation:
      'Usa `osdo-license-scan@v2` o `fossa-contrib/fossa-action` para garantizar compliance de licencias en cada PR.',
  },

  {
    id: 'scorecard',
    name: 'OpenSSF Scorecard',
    description: 'Evalúa prácticas de seguridad del repositorio con OpenSSF Scorecard',
    level: 'completo',
    points: 3,
    osdoAction: 'N/A — workflow propio recomendado',
    equivalentActions: ['ossf/scorecard-action'],
    runKeywords: ['scorecard'],
    frameworks: ['OpenSSF', 'CNCF', 'SLSA'],
    recommendation:
      'Agrega el workflow de OpenSSF Scorecard: https://github.com/ossf/scorecard-action\n  Target: 8.0/10 para badge OpenSSF.',
  },
]

/** Controles esenciales (mínimo absoluto para cualquier empresa) */
export const ESSENTIAL_CONTROLS = SECURITY_CONTROLS.filter(c => c.level === 'esencial')

/** Todos los controles hasta nivel recomendado */
export const RECOMMENDED_CONTROLS = SECURITY_CONTROLS.filter(
  c => c.level === 'esencial' || c.level === 'recomendado',
)

/** Puntuación máxima posible */
export const MAX_SCORE = SECURITY_CONTROLS.reduce((sum, c) => sum + c.points, 0)

/**
 * Calcula el nivel de madurez OSDO según la puntuación:
 *
 *   0-29:  Nivel 0 — Sin DevSecOps
 *   30-49: Nivel 1 — Inicial
 *   50-69: Nivel 2 — Básico (Esencial cubierto)
 *   70-84: Nivel 3 — Establecido (Recomendado cubierto)
 *   85-99: Nivel 4 — Avanzado
 *   100:   Nivel 5 — OSDO Completo
 */
export function scoreToLevel(score: number): {level: number; label: string; emoji: string} {
  if (score >= 100) return {level: 5, label: 'OSDO Completo', emoji: '🏆'}
  if (score >= 85) return {level: 4, label: 'Avanzado', emoji: '🚀'}
  if (score >= 70) return {level: 3, label: 'Establecido', emoji: '✅'}
  if (score >= 50) return {level: 2, label: 'Básico', emoji: '📈'}
  if (score >= 30) return {level: 1, label: 'Inicial', emoji: '🌱'}
  return {level: 0, label: 'Sin DevSecOps', emoji: '🔴'}
}
