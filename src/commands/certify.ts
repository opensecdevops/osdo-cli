import {Flags} from '@oclif/core'
import chalk from 'chalk'
import {existsSync, mkdirSync, readdirSync, writeFileSync, type Dirent} from 'node:fs'
import {join, resolve} from 'node:path'
import Table from 'cli-table3'
import {BaseCommand} from '../lib/base-command.js'

// ──────────────────────────────────────────────────────────────────────────────
// Tipos
// ──────────────────────────────────────────────────────────────────────────────

type CheckStatus = 'PASS' | 'FAIL' | 'MANUAL'
type CheckSeverity = 'CRITICAL' | 'HIGH' | 'MEDIUM' | 'LOW'

interface ComplianceCheck {
  id: string
  name: string
  category: string
  severity: CheckSeverity
  description: string
  scanner: string
  status: CheckStatus
  remediation?: string
}

interface CertificationResult {
  id: Standard
  standard: string
  timestamp: Date
  score: number
  passed: number
  failed: number
  manual: number
  checks: ComplianceCheck[]
  gapAnalysis: string[]
}

interface ScanContext {
  hasSAST: boolean
  hasSCA: boolean
  hasSecrets: boolean
  hasSBOM: boolean
  hasOsdoConfig: boolean
  hasWorkflow: boolean
  hasSecurityMd: boolean
  hasCodeOfConduct: boolean
  hasLicense: boolean
  hasChangelog: boolean
  hasDependabot: boolean
  hasFuzzing: boolean
  hasIaC: boolean
  hasBuildSBOM: boolean
  hasSLSAProvenance: boolean
  hasMobileScan: boolean
  hasSmartContractScan: boolean
  path: string
}

type Standard = 'owasp' | 'slsa' | 'openssf' | 'soc2' | 'iso27001' | 'owasp-mobile' | 'smart-contract'

// ──────────────────────────────────────────────────────────────────────────────
// Construcción del contexto de escaneo
// ──────────────────────────────────────────────────────────────────────────────

function buildScanContext(rootPath: string): ScanContext {
  const p = (rel: string) => join(rootPath, rel)

  return {
    hasSAST: existsSync(p('.osdo/results/sast/semgrep.json')),
    hasSCA: existsSync(p('.osdo/results/sca/osv.json')) || existsSync(p('.osdo/results/sca')),
    hasSecrets: existsSync(p('.osdo/results/secrets/gitleaks.json')),
    hasSBOM: existsSync(p('.osdo/results/sbom')),
    hasBuildSBOM: existsSync(p('.osdo/results/build')),
    hasSLSAProvenance: existsSync(p('.osdo/results/slsa')),
    hasOsdoConfig: existsSync(p('.osdo/config.yaml')),
    hasWorkflow: existsSync(p('.github/workflows/osdo-security.yml')),
    hasSecurityMd: existsSync(p('SECURITY.md')) || existsSync(p('docs/security.md')),
    hasCodeOfConduct: existsSync(p('CODE_OF_CONDUCT.md')),
    hasLicense: existsSync(p('LICENSE')) || existsSync(p('LICENSE.md')) || existsSync(p('LICENSE.txt')),
    hasChangelog: existsSync(p('CHANGELOG.md')) || existsSync(p('CHANGELOG')),
    hasDependabot: existsSync(p('.github/dependabot.yml')),
    hasFuzzing: existsSync(p('fuzz')) || existsSync(p('.osdo/results/fuzz')),
    hasIaC: existsSync(p('.osdo/results/iac')) || existsSync(p('terraform')) || existsSync(p('infra')),
    hasMobileScan: existsSync(p('.osdo/results/mobile')),
    hasSmartContractScan: existsSync(p('.osdo/results/smart-contract')),
    path: rootPath,
  }
}

// ──────────────────────────────────────────────────────────────────────────────
// Verificaciones por estándar
// ──────────────────────────────────────────────────────────────────────────────

function buildOWASPChecks(ctx: ScanContext): ComplianceCheck[] {
  return [
    {
      id: 'A01', name: 'Control de Acceso', category: 'A01:Broken Access Control',
      severity: 'CRITICAL', description: 'SAST verifica vulnerabilidades de control de acceso',
      scanner: 'osdo-sast', status: ctx.hasSAST ? 'PASS' : 'FAIL',
      remediation: "Ejecuta 'osdo scan --type sast' y revisa hallazgos de autorización",
    },
    {
      id: 'A02', name: 'Fallos Criptográficos', category: 'A02:Cryptographic Failures',
      severity: 'HIGH', description: 'Secrets scanner + SAST detectan criptografía débil y secretos expuestos',
      scanner: 'osdo-sast + osdo-secrets-scan', status: ctx.hasSecrets && ctx.hasSAST ? 'PASS' : 'FAIL',
      remediation: "Ejecuta 'osdo scan --type secrets' para detectar secretos expuestos",
    },
    {
      id: 'A03', name: 'Prevención de Inyección', category: 'A03:Injection',
      severity: 'CRITICAL', description: 'SAST (Semgrep) detecta SQL/NoSQL/Command injection',
      scanner: 'osdo-sast', status: ctx.hasSAST ? 'PASS' : 'FAIL',
      remediation: "Ejecuta 'osdo scan --type sast' y revisa reglas de injection",
    },
    {
      id: 'A04', name: 'Diseño Inseguro', category: 'A04:Insecure Design',
      severity: 'HIGH', description: 'SECURITY.md y revisión de diseño de seguridad',
      scanner: 'osdo-compliance-check', status: ctx.hasSecurityMd ? 'MANUAL' : 'FAIL',
      remediation: "Crea SECURITY.md con 'osdo init' o documenta el modelo de amenazas",
    },
    {
      id: 'A05', name: 'Configuración Incorrecta', category: 'A05:Security Misconfiguration',
      severity: 'HIGH', description: 'IaC scanning + configuración OSDO',
      scanner: 'osdo-iac-scan + osdo-policy-gate',
      status: ctx.hasOsdoConfig && ctx.hasWorkflow ? 'PASS' : 'FAIL',
      remediation: "Ejecuta 'osdo init' para crear la configuración OSDO",
    },
    {
      id: 'A06', name: 'Componentes Vulnerables', category: 'A06:Vulnerable Components',
      severity: 'CRITICAL', description: 'SCA detecta dependencias con CVEs conocidos',
      scanner: 'osdo-sca', status: ctx.hasSCA ? 'PASS' : 'FAIL',
      remediation: "Ejecuta 'osdo scan --type sca' para analizar dependencias",
    },
    {
      id: 'A07', name: 'Fallos de Autenticación', category: 'A07:Auth Failures',
      severity: 'CRITICAL', description: 'SAST verifica implementación de autenticación',
      scanner: 'osdo-sast', status: ctx.hasSAST ? 'PASS' : 'FAIL',
      remediation: "Ejecuta 'osdo scan --type sast' y revisa reglas de autenticación",
    },
    {
      id: 'A08', name: 'Integridad de Software', category: 'A08:Data Integrity Failures',
      severity: 'HIGH', description: 'SBOM genera inventario de componentes para verificar integridad',
      scanner: 'osdo-sbom', status: ctx.hasSBOM || ctx.hasWorkflow ? 'PASS' : 'FAIL',
      remediation: "El workflow CI incluye osdo-sbom. Ejecuta 'osdo pipeline generate'",
    },
    {
      id: 'A09', name: 'Registro de Seguridad', category: 'A09:Security Logging',
      severity: 'MEDIUM', description: 'Verificación de configuración de logging y monitorización',
      scanner: 'osdo-policy-gate', status: ctx.hasOsdoConfig ? 'MANUAL' : 'FAIL',
      remediation: 'Configura logging en .osdo/config.yaml y aplica políticas de monitoring',
    },
    {
      id: 'A10', name: 'SSRF', category: 'A10:SSRF',
      severity: 'HIGH', description: 'SAST (Semgrep) detecta patrones SSRF',
      scanner: 'osdo-sast', status: ctx.hasSAST ? 'PASS' : 'FAIL',
      remediation: "Ejecuta 'osdo scan --type sast' y revisa reglas SSRF",
    },
  ]
}

function buildSLSAChecks(ctx: ScanContext): ComplianceCheck[] {
  const hasSLSAWf = existsSync(join(ctx.path, '.github/workflows/osdo-release.yml')) ||
                    existsSync(join(ctx.path, '.github/workflows/osdo-supply-chain.yml'))
  const hasGit = existsSync(join(ctx.path, '.git'))

  return [
    {
      id: 'L1-1', name: 'Proceso de Build Documentado', category: 'SLSA Level 1',
      severity: 'LOW', description: 'Workflow de build documentado',
      scanner: 'osdo-compliance-check', status: ctx.hasWorkflow ? 'PASS' : 'FAIL',
      remediation: "Ejecuta 'osdo init' para crear workflows de GitHub Actions",
    },
    {
      id: 'L1-2', name: 'Procedencia Generada', category: 'SLSA Level 1',
      severity: 'MEDIUM', description: 'Provenance generado en el build',
      scanner: 'osdo-slsa-provenance', status: hasSLSAWf ? 'PASS' : 'FAIL',
      remediation: "Añade osdo-actions/osdo-slsa-provenance@v2 al workflow de release",
    },
    {
      id: 'L2-1', name: 'Control de Versiones', category: 'SLSA Level 2',
      severity: 'MEDIUM', description: 'Código en control de versiones',
      scanner: 'osdo-compliance-check', status: hasGit ? 'PASS' : 'FAIL',
      remediation: 'Inicializa un repositorio Git: git init',
    },
    {
      id: 'L2-2', name: 'Servicio de Build Alojado', category: 'SLSA Level 2',
      severity: 'MEDIUM', description: 'Build en servicio alojado (GitHub Actions)',
      scanner: 'osdo-compliance-check', status: ctx.hasWorkflow ? 'PASS' : 'FAIL',
      remediation: "Configura GitHub Actions con 'osdo init'",
    },
    {
      id: 'L2-3', name: 'Procedencia Autenticada', category: 'SLSA Level 2',
      severity: 'HIGH', description: 'Provenance autenticado',
      scanner: 'osdo-slsa-provenance', status: hasSLSAWf ? 'PASS' : 'FAIL',
      remediation: "Añade opensecdevops/osdo-actions/osdo-slsa-provenance@v2",
    },
    {
      id: 'L3-1', name: 'Procedencia No Falsificable', category: 'SLSA Level 3',
      severity: 'HIGH', description: 'Provenance no falsificable',
      scanner: 'osdo-slsa-provenance', status: ctx.hasSLSAProvenance ? 'PASS' : 'FAIL',
      remediation: "Usa osdo-slsa-provenance con slsa-level: '3'",
    },
    {
      id: 'L3-2', name: 'Entorno de Build Aislado', category: 'SLSA Level 3',
      severity: 'HIGH', description: 'Entorno de build aislado',
      scanner: 'osdo-compliance-check', status: ctx.hasWorkflow ? 'MANUAL' : 'FAIL',
      remediation: 'Verificar que los runners no tienen acceso a secretos innecesarios',
    },
    {
      id: 'L3-3', name: 'Artefactos Firmados', category: 'SLSA Level 3',
      severity: 'CRITICAL', description: 'Artefactos firmados con Cosign/Sigstore',
      scanner: 'osdo-signing', status: ctx.hasBuildSBOM || ctx.hasSLSAProvenance ? 'PASS' : 'FAIL',
      remediation: "Añade cosign o osdo-slsa-provenance al pipeline de release",
    },
  ]
}

function buildOpenSSFChecks(ctx: ScanContext): ComplianceCheck[] {
  return [
    {
      id: 'OSS-1', name: 'Revisión de Código', category: 'Proceso',
      severity: 'HIGH', description: 'Pull requests revisados antes de hacer merge',
      scanner: 'osdo-compliance-check', status: ctx.hasWorkflow ? 'MANUAL' : 'FAIL',
      remediation: 'Habilitar branch protection con revisiones requeridas en GitHub',
    },
    {
      id: 'OSS-2', name: 'Protección de Ramas', category: 'Proceso',
      severity: 'HIGH', description: 'Ramas principales protegidas contra push directo',
      scanner: 'osdo-compliance-check', status: 'MANUAL',
      remediation: 'Configurar branch protection rules en el repositorio de GitHub',
    },
    {
      id: 'OSS-3', name: 'Actualiz. Dependencias', category: 'Dependencias',
      severity: 'MEDIUM', description: 'Dependencias actualizadas automáticamente',
      scanner: 'osdo-sca', status: ctx.hasDependabot ? 'PASS' : 'FAIL',
      remediation: "Crea .github/dependabot.yml para habilitar Dependabot",
    },
    {
      id: 'OSS-4', name: 'Fuzzing', category: 'Testing',
      severity: 'MEDIUM', description: 'Pruebas de fuzzing implementadas',
      scanner: 'osdo-fuzz', status: ctx.hasFuzzing ? 'PASS' : 'FAIL',
      remediation: "Añade fuzzing con opensecdevops/osdo-actions/osdo-fuzz@v2",
    },
    {
      id: 'OSS-5', name: 'SAST', category: 'Seguridad',
      severity: 'HIGH', description: 'Análisis estático de seguridad configurado',
      scanner: 'osdo-sast', status: ctx.hasSAST ? 'PASS' : 'FAIL',
      remediation: "Ejecuta 'osdo scan --type sast'",
    },
    {
      id: 'OSS-6', name: 'Política de Seguridad', category: 'Seguridad',
      severity: 'MEDIUM', description: 'SECURITY.md con política de divulgación responsable',
      scanner: 'osdo-compliance-check', status: ctx.hasSecurityMd ? 'PASS' : 'FAIL',
      remediation: "Ejecuta 'osdo init' para crear SECURITY.md",
    },
    {
      id: 'OSS-7', name: 'Releases Firmados', category: 'Cadena de Suministro',
      severity: 'HIGH', description: 'Releases firmados con Sigstore o GPG',
      scanner: 'osdo-signing', status: ctx.hasSLSAProvenance ? 'PASS' : 'FAIL',
      remediation: "Configura cosign o osdo-slsa-provenance en el pipeline de release",
    },
    {
      id: 'OSS-8', name: 'Permisos de Token', category: 'Seguridad',
      severity: 'MEDIUM', description: 'Permisos mínimos configurados en workflows',
      scanner: 'osdo-policy-gate', status: ctx.hasWorkflow ? 'MANUAL' : 'FAIL',
      remediation: "Añade bloque 'permissions:' con permisos mínimos en cada workflow",
    },
    {
      id: 'OSS-9', name: 'Vulnerabilidades', category: 'Seguridad',
      severity: 'HIGH', description: 'Sin vulnerabilidades conocidas sin parchear',
      scanner: 'osdo-sca', status: ctx.hasSAST && ctx.hasSCA ? 'PASS' : 'FAIL',
      remediation: "Ejecuta 'osdo scan' completo y remedia los hallazgos",
    },
    {
      id: 'OSS-10', name: 'Licencia', category: 'Legal',
      severity: 'LOW', description: 'Licencia de código abierto presente',
      scanner: 'osdo-license-scan', status: ctx.hasLicense ? 'PASS' : 'FAIL',
      remediation: 'Añade un archivo LICENSE al repositorio',
    },
  ]
}

function buildSOC2Checks(ctx: ScanContext): ComplianceCheck[] {
  const base: CheckStatus = ctx.hasSecurityMd && ctx.hasWorkflow ? 'PASS' : 'FAIL'
  return [
    {
      id: 'CC1', name: 'Entorno de Control', category: 'Criterio Común',
      severity: 'HIGH', description: 'Controles de gobernanza y políticas de seguridad',
      scanner: 'osdo-compliance-check', status: ctx.hasSecurityMd ? 'PASS' : 'FAIL',
      remediation: 'Documenta las políticas de seguridad en SECURITY.md',
    },
    {
      id: 'CC2', name: 'Comunicación', category: 'Criterio Común',
      severity: 'MEDIUM', description: 'Comunicación de controles de seguridad',
      scanner: 'osdo-compliance-check', status: ctx.hasSecurityMd ? 'PASS' : 'FAIL',
      remediation: 'Documenta y comunica controles de seguridad a stakeholders',
    },
    {
      id: 'CC3', name: 'Evaluación de Riesgos', category: 'Criterio Común',
      severity: 'HIGH', description: 'Proceso de identificación y evaluación de riesgos',
      scanner: 'osdo-compliance-check', status: 'MANUAL',
      remediation: 'Implementa un proceso formal de evaluación de riesgos',
    },
    {
      id: 'CC4', name: 'Monitorización', category: 'Criterio Común',
      severity: 'MEDIUM', description: 'Monitorización continua de controles de seguridad',
      scanner: 'osdo-compliance-check', status: ctx.hasWorkflow ? 'PASS' : 'FAIL',
      remediation: 'Configura alertas y monitorización continua',
    },
    {
      id: 'CC5', name: 'Actividades de Control', category: 'Criterio Común',
      severity: 'HIGH', description: 'Controles operativos documentados y aplicados',
      scanner: 'osdo-compliance-check', status: base,
      remediation: "Ejecuta 'osdo init' para implementar controles automatizados",
    },
    {
      id: 'CC6', name: 'Control de Acceso Lógico', category: 'Seguridad',
      severity: 'CRITICAL', description: 'Controles de acceso lógico y físico',
      scanner: 'osdo-sast', status: ctx.hasWorkflow ? 'PASS' : 'FAIL',
      remediation: 'Implementa autenticación multifactor y control de acceso por roles',
    },
    {
      id: 'CC7', name: 'Operaciones del Sistema', category: 'Seguridad',
      severity: 'HIGH', description: 'Gestión de cambios y respuesta a incidentes',
      scanner: 'osdo-compliance-check', status: ctx.hasOsdoConfig ? 'PASS' : 'MANUAL',
      remediation: 'Documenta procedimientos de respuesta a incidentes',
    },
    {
      id: 'CC8', name: 'Gestión de Cambios', category: 'Seguridad',
      severity: 'HIGH', description: 'Proceso formal de gestión de cambios',
      scanner: 'osdo-compliance-check', status: ctx.hasWorkflow ? 'PASS' : 'FAIL',
      remediation: 'Implementa revisión de código obligatoria mediante PRs',
    },
    {
      id: 'CC9', name: 'Mitigación de Riesgos', category: 'Seguridad',
      severity: 'HIGH', description: 'Controles para mitigar riesgos identificados',
      scanner: 'osdo-sast + osdo-sca', status: base,
      remediation: "Ejecuta 'osdo scan' y remedia los hallazgos críticos",
    },
  ]
}

function buildISO27001Checks(ctx: ScanContext): ComplianceCheck[] {
  return [
    {
      id: 'A.5', name: 'Políticas de Seguridad', category: 'Organizacional',
      severity: 'HIGH', description: 'Políticas de seguridad de la información documentadas',
      scanner: 'osdo-compliance-check', status: ctx.hasSecurityMd ? 'PASS' : 'FAIL',
      remediation: "Crea SECURITY.md con política de seguridad completa",
    },
    {
      id: 'A.6', name: 'Organización de Seguridad', category: 'Organizacional',
      severity: 'MEDIUM', description: 'Roles y responsabilidades de seguridad definidos',
      scanner: 'osdo-compliance-check', status: 'MANUAL',
      remediation: 'Define roles de seguridad y responsabilidades en la documentación del proyecto',
    },
    {
      id: 'A.7', name: 'Seguridad de RRHH', category: 'RRHH',
      severity: 'MEDIUM', description: 'Controles de seguridad en contratación y cese',
      scanner: 'osdo-compliance-check', status: 'MANUAL',
      remediation: 'Implementa controles de seguridad en procesos de RRHH',
    },
    {
      id: 'A.8', name: 'Gestión de Activos', category: 'Activos',
      severity: 'HIGH', description: 'Inventario de activos de información',
      scanner: 'osdo-sca + osdo-sbom', status: ctx.hasSCA || ctx.hasSBOM ? 'PASS' : 'FAIL',
      remediation: "Ejecuta 'osdo scan --type sca' para generar inventario de dependencias",
    },
    {
      id: 'A.9', name: 'Control de Acceso', category: 'Técnico',
      severity: 'CRITICAL', description: 'Controles de acceso a sistemas y aplicaciones',
      scanner: 'osdo-sast + osdo-policy-gate', status: ctx.hasWorkflow ? 'PASS' : 'FAIL',
      remediation: 'Implementa principio de mínimo privilegio en CI/CD',
    },
    {
      id: 'A.10', name: 'Criptografía', category: 'Técnico',
      severity: 'HIGH', description: 'Uso apropiado de controles criptográficos',
      scanner: 'osdo-sast + osdo-secrets-scan', status: ctx.hasSecrets && ctx.hasSAST ? 'PASS' : 'FAIL',
      remediation: "Configura escaneo de secretos con 'osdo scan --type secrets'",
    },
    {
      id: 'A.12', name: 'Seguridad Operacional', category: 'Técnico',
      severity: 'HIGH', description: 'Procedimientos operacionales documentados',
      scanner: 'osdo-compliance-check', status: ctx.hasWorkflow ? 'PASS' : 'MANUAL',
      remediation: 'Documenta runbooks y procedimientos operacionales',
    },
    {
      id: 'A.14', name: 'Seguridad en el Desarrollo', category: 'Desarrollo',
      severity: 'HIGH', description: 'Seguridad integrada en el ciclo de vida del desarrollo',
      scanner: 'osdo-sast + osdo-sca', status: ctx.hasSAST && ctx.hasWorkflow ? 'PASS' : 'FAIL',
      remediation: "Ejecuta 'osdo init' para integrar seguridad en el SDLC",
    },
  ]
}

function buildOWASPMobileChecks(ctx: ScanContext): ComplianceCheck[] {
  return [
    {id: 'M1', name: 'Credenciales Incorrectas', category: 'M1: Improper Credential Usage', severity: 'CRITICAL', description: 'Detección de credenciales hardcoded', scanner: 'osdo-secrets-scan', status: ctx.hasSecrets ? 'PASS' : 'FAIL', remediation: "Ejecuta 'osdo scan --type secrets'"},
    {id: 'M2', name: 'Cadena de Suministro', category: 'M2: Inadequate Supply Chain Security', severity: 'HIGH', description: 'SCA de dependencias móviles', scanner: 'osdo-sca', status: ctx.hasSCA ? 'PASS' : 'FAIL', remediation: "Ejecuta 'osdo scan --type sca'"},
    {id: 'M3', name: 'Autenticación Insegura', category: 'M3: Insecure Authentication', severity: 'CRITICAL', description: 'SAST en flujos de autenticación', scanner: 'osdo-sast', status: ctx.hasSAST ? 'PASS' : 'FAIL', remediation: "Ejecuta 'osdo scan --type sast'"},
    {id: 'M4', name: 'Validación de Input', category: 'M4: Insufficient Input Validation', severity: 'HIGH', description: 'SAST verifica validación de inputs', scanner: 'osdo-sast', status: ctx.hasSAST ? 'PASS' : 'FAIL', remediation: "Ejecuta 'osdo scan --type sast'"},
    {id: 'M5', name: 'Comunicación Insegura', category: 'M5: Insecure Communication', severity: 'HIGH', description: 'Verificación de SSL pinning y TLS', scanner: 'osdo-mobile-scan', status: ctx.hasMobileScan ? 'PASS' : 'FAIL', remediation: "Configura osdo-mobile-scan en el pipeline"},
    {id: 'M6', name: 'Controles de Privacidad', category: 'M6: Inadequate Privacy Controls', severity: 'HIGH', description: 'Análisis de permisos y PII', scanner: 'osdo-mobile-scan', status: ctx.hasMobileScan ? 'PASS' : 'FAIL', remediation: "Configura osdo-mobile-scan con check-pii-exposure: true"},
    {id: 'M7', name: 'Protecciones Binarias', category: 'M7: Insufficient Binary Protections', severity: 'MEDIUM', description: 'Verificación de ofuscación', scanner: 'osdo-mobile-scan', status: ctx.hasMobileScan ? 'PASS' : 'FAIL', remediation: "Configura osdo-mobile-scan con check-obfuscation: true"},
    {id: 'M8', name: 'Config. Incorrecta', category: 'M8: Security Misconfiguration', severity: 'HIGH', description: 'Configuración de la app móvil', scanner: 'osdo-iac-scan', status: ctx.hasOsdoConfig ? 'PASS' : 'FAIL', remediation: "Ejecuta 'osdo init' para crear la configuración OSDO"},
    {id: 'M9', name: 'Almacenamiento Inseguro', category: 'M9: Insecure Data Storage', severity: 'CRITICAL', description: 'SAST detecta almacenamiento inseguro', scanner: 'osdo-sast + osdo-mobile-scan', status: ctx.hasSAST && ctx.hasMobileScan ? 'PASS' : 'FAIL', remediation: "Ejecuta 'osdo scan --type sast' y configura osdo-mobile-scan"},
    {id: 'M10', name: 'Criptografía Insuficiente', category: 'M10: Insufficient Cryptography', severity: 'HIGH', description: 'SAST verifica uso de criptografía', scanner: 'osdo-sast', status: ctx.hasSAST ? 'PASS' : 'FAIL', remediation: "Ejecuta 'osdo scan --type sast'"},
  ]
}

function buildSmartContractChecks(ctx: ScanContext): ComplianceCheck[] {
  const sc = ctx.hasSmartContractScan
  return [
    {id: 'SC1', name: 'Control de Acceso', category: 'SC1: Access Control Issues', severity: 'CRITICAL', description: 'Slither detecta problemas de control de acceso', scanner: 'osdo-smart-contract-audit', status: sc ? 'PASS' : 'FAIL', remediation: "Configura osdo-smart-contract-audit en el pipeline"},
    {id: 'SC2', name: 'Manipulación de Oracle', category: 'SC2: Price Oracle Manipulation', severity: 'CRITICAL', description: 'Análisis de dependencias de oracle', scanner: 'osdo-smart-contract-audit', status: sc ? 'PASS' : 'FAIL', remediation: "Configura osdo-smart-contract-audit con check-access-control: true"},
    {id: 'SC3', name: 'Errores de Lógica', category: 'SC3: Logic Errors', severity: 'HIGH', description: 'Mythril verifica lógica del contrato', scanner: 'osdo-smart-contract-audit', status: sc ? 'PASS' : 'FAIL', remediation: "Añade análisis con Mythril al pipeline"},
    {id: 'SC4', name: 'Validación de Input', category: 'SC4: Lack of Input Validation', severity: 'HIGH', description: 'Slither verifica validación de inputs', scanner: 'osdo-smart-contract-audit', status: sc ? 'PASS' : 'FAIL', remediation: "Configura osdo-smart-contract-audit"},
    {id: 'SC5', name: 'Reentrancy', category: 'SC5: Reentrancy Attacks', severity: 'CRITICAL', description: 'Detección de vulnerabilidades de reentrancy', scanner: 'osdo-smart-contract-audit', status: sc ? 'PASS' : 'FAIL', remediation: "Usa check-reentrancy: true en osdo-smart-contract-audit"},
    {id: 'SC6', name: 'SELFDESTRUCT', category: 'SC6: Unprotected SELFDESTRUCT', severity: 'CRITICAL', description: 'Verificación de SELFDESTRUCT expuesto', scanner: 'osdo-smart-contract-audit', status: sc ? 'PASS' : 'FAIL', remediation: "Configura osdo-smart-contract-audit"},
    {id: 'SC7', name: 'Integer Overflow', category: 'SC7: Integer Overflow and Underflow', severity: 'HIGH', description: 'Análisis de overflow aritmético', scanner: 'osdo-smart-contract-audit', status: sc ? 'PASS' : 'FAIL', remediation: "Configura osdo-smart-contract-audit"},
    {id: 'SC8', name: 'Llamadas Externas', category: 'SC8: Unsafe External Calls', severity: 'HIGH', description: 'Slither detecta llamadas externas inseguras', scanner: 'osdo-smart-contract-audit', status: sc ? 'PASS' : 'FAIL', remediation: "Configura osdo-smart-contract-audit"},
    {id: 'SC9', name: 'Denegación de Servicio', category: 'SC9: Denial of Service', severity: 'MEDIUM', description: 'Análisis de patrones DoS', scanner: 'osdo-smart-contract-audit', status: sc ? 'PASS' : 'FAIL', remediation: "Configura osdo-smart-contract-audit"},
    {id: 'SC10', name: 'Componentes Obsoletos', category: 'SC10: Vulnerable Components', severity: 'MEDIUM', description: 'SCA de dependencias Solidity', scanner: 'osdo-sca', status: ctx.hasSCA ? 'PASS' : 'FAIL', remediation: "Ejecuta 'osdo scan --type sca'"},
  ]
}

// ──────────────────────────────────────────────────────────────────────────────
// Estándares: nombres, constructores, aplicabilidad y selección
// ──────────────────────────────────────────────────────────────────────────────

const STANDARD_NAMES: Record<Standard, string> = {
  'owasp': 'OWASP Top 10 2021',
  'slsa': 'SLSA v1.0',
  'openssf': 'OpenSSF Scorecard',
  'soc2': 'SOC 2 Type II',
  'iso27001': 'ISO 27001:2022',
  'owasp-mobile': 'OWASP Mobile Top 10 2024',
  'smart-contract': 'OWASP Smart Contract Top 10',
}

const CHECK_BUILDERS: Record<Standard, (ctx: ScanContext) => ComplianceCheck[]> = {
  'owasp': buildOWASPChecks,
  'slsa': buildSLSAChecks,
  'openssf': buildOpenSSFChecks,
  'soc2': buildSOC2Checks,
  'iso27001': buildISO27001Checks,
  'owasp-mobile': buildOWASPMobileChecks,
  'smart-contract': buildSmartContractChecks,
}

function isStandard(value: string): value is Standard {
  return (ALL_STANDARDS as string[]).includes(value)
}

const TREE_SKIP_DIRS = new Set(['node_modules', '.git', '.osdo', 'dist', 'build', 'vendor', 'target'])

/** Busca un nombre de fichero o directorio que cumpla `match` hasta `maxDepth` niveles. */
function treeHas(root: string, match: (name: string) => boolean, maxDepth = 4): boolean {
  const walk = (dir: string, depth: number): boolean => {
    let entries: Dirent[]
    try {
      entries = readdirSync(dir, {withFileTypes: true})
    } catch {
      return false
    }
    for (const entry of entries) {
      if (match(entry.name)) return true
      if (entry.isDirectory() && depth < maxDepth && !TREE_SKIP_DIRS.has(entry.name) && walk(join(dir, entry.name), depth + 1)) {
        return true
      }
    }
    return false
  }
  return walk(root, 0)
}

interface Applicability {
  applicable: boolean
  reason?: string
}

/**
 * Decide si un estándar aplica al proyecto. Los estándares de software general
 * (OWASP Top 10, SLSA, OpenSSF, SOC 2, ISO 27001) aplican siempre; los específicos
 * solo cuando el proyecto tiene la tecnología correspondiente.
 */
function probeApplicability(standard: Standard, rootPath: string): Applicability {
  if (standard === 'owasp-mobile') {
    const mobile = existsSync(join(rootPath, '.osdo/results/mobile')) ||
      treeHas(rootPath, n => n === 'AndroidManifest.xml' || n === 'Info.plist' || n.endsWith('.xcodeproj') || n.endsWith('.xcworkspace'))
    return mobile
      ? {applicable: true}
      : {applicable: false, reason: 'no hay proyecto móvil (AndroidManifest.xml, Info.plist, *.xcodeproj/*.xcworkspace ni .osdo/results/mobile)'}
  }

  if (standard === 'smart-contract') {
    const contracts = existsSync(join(rootPath, '.osdo/results/smart-contract')) ||
      treeHas(rootPath, n => n.endsWith('.sol') || ['hardhat.config.js', 'hardhat.config.ts', 'foundry.toml', 'truffle-config.js'].includes(n))
    return contracts
      ? {applicable: true}
      : {applicable: false, reason: 'no hay contratos inteligentes (*.sol, Hardhat, Foundry, Truffle ni .osdo/results/smart-contract)'}
  }

  return {applicable: true}
}

interface EvaluatedStandard {
  id: Standard
  applicable: true
  result: CertificationResult
  /** Puntuación mínima exigida a este estándar (--min o --min-score); undefined si no hay umbral */
  threshold?: number
}

interface NotApplicableStandard {
  id: Standard
  applicable: false
  name: string
  reason: string
}

type StandardOutcome = EvaluatedStandard | NotApplicableStandard

function runStandard(standard: Standard, ctx: ScanContext): CertificationResult {
  const checks = CHECK_BUILDERS[standard](ctx)
  const standardName = STANDARD_NAMES[standard]

  const passed = checks.filter(c => c.status === 'PASS').length
  const failed = checks.filter(c => c.status === 'FAIL').length
  const manual = checks.filter(c => c.status === 'MANUAL').length

  // MANUAL cuenta como 0.5 hacia la puntuación
  const effectivePassed = passed + manual * 0.5
  const score = checks.length > 0 ? Math.round((effectivePassed / checks.length) * 100) : 0

  const gapAnalysis: string[] = []
  for (const c of checks.filter(ch => ch.status === 'FAIL')) {
    if (c.remediation) gapAnalysis.push(`[${c.id}] ${c.remediation}`)
  }

  if (!ctx.hasSAST)    gapAnalysis.push("Ejecuta 'osdo scan --type sast' para habilitar análisis estático")
  if (!ctx.hasSCA)     gapAnalysis.push("Ejecuta 'osdo scan --type sca' para habilitar análisis de dependencias")
  if (!ctx.hasWorkflow) gapAnalysis.push("Ejecuta 'osdo init' para crear workflows de seguridad")

  return {
    id: standard,
    standard: standardName,
    timestamp: new Date(),
    score,
    passed,
    failed,
    manual,
    checks,
    gapAnalysis: [...new Set(gapAnalysis)],
  }
}

// ──────────────────────────────────────────────────────────────────────────────
// Generación de reportes Markdown
// ──────────────────────────────────────────────────────────────────────────────

function verdictFor(score: number): string {
  return score >= 80
    ? '✅ **LISTO PARA CERTIFICACIÓN**'
    : score >= 60
      ? '⚠️ **CUMPLIMIENTO PARCIAL** — Resolver brechas antes de certificar'
      : '❌ **NO LISTO** — Se requiere remediación significativa'
}

/** Cuerpo de un estándar evaluado: resumen, controles, brechas y veredicto (subsecciones `###`). */
function renderStandardBody(result: CertificationResult): string {
  const statusEmoji = (s: CheckStatus) => s === 'PASS' ? '✅' : s === 'MANUAL' ? '🔵' : '❌'

  const rows = result.checks
    .map(c => `| ${c.id} | ${c.name} | ${c.category} | ${statusEmoji(c.status)} ${c.status} | ${c.severity} | ${c.scanner} | ${c.remediation || '—'} |`)
    .join('\n')

  const gaps = result.gapAnalysis.length > 0
    ? `\n### Análisis de Brechas\n\n${result.gapAnalysis.map(g => `- ${g}`).join('\n')}\n`
    : ''

  return `**Puntuación**: ${result.score}%

### Resumen

| Métrica | Valor |
|---------|-------|
| Aprobados | ${result.passed} |
| Fallidos | ${result.failed} |
| Manual | ${result.manual} |
| Puntuación | ${result.score}% |

### Controles Detallados

| ID | Control | Categoría | Estado | Severidad | Scanner | Remediación |
|----|---------|-----------|--------|-----------|---------|-------------|
${rows}
${gaps}
### Veredicto

${verdictFor(result.score)}
`
}

const REPORT_FOOTER = '---\n*Generado por OSDO CLI v2 — [opensecdevops.org](https://opensecdevops.org)*\n'

/** Reporte de un único estándar (`certification-<estándar>.md`). */
function renderStandardReport(result: CertificationResult): string {
  return `# Reporte de Certificación: ${result.standard}

**Generado**: ${result.timestamp.toISOString()}

${renderStandardBody(result)}
${REPORT_FOOTER}`
}

/** Reporte combinado (`certification-report.md`) con todos los estándares seleccionados. */
function renderCombinedReport(outcomes: StandardOutcome[], generatedAt: Date): string {
  const summaryRows = outcomes.map(o => {
    if (!o.applicable) return `| ${o.id} | ${STANDARD_NAMES[o.id]} | N/A | — | N/A |`
    const threshold = o.threshold === undefined ? '—' : `${o.threshold}%`
    const outcome = o.threshold === undefined
      ? 'Evaluado'
      : o.result.score >= o.threshold ? 'Cumple umbral' : 'No cumple umbral'
    return `| ${o.id} | ${o.result.standard} | ${o.result.score}% | ${threshold} | ${outcome} |`
  }).join('\n')

  const sections = outcomes.map(o => o.applicable
    ? `## ${o.result.standard}\n\n${renderStandardBody(o.result)}`
    : `## ${o.name} (N/A)\n\nNo aplica a este proyecto: ${o.reason}.\n`,
  ).join('\n')

  return `# Reporte de Certificación OSDO

**Generado**: ${generatedAt.toISOString()}

## Resumen global

| Id | Estándar | Puntuación | Umbral | Resultado |
|----|----------|------------|--------|-----------|
${summaryRows}

${sections}
${REPORT_FOOTER}`
}

/**
 * Escribe el reporte combinado y un fichero por estándar evaluado en .osdo/reports/.
 * Devuelve las rutas escritas.
 */
function writeReports(outcomes: StandardOutcome[], rootPath: string, generatedAt: Date): string[] {
  const reportsDir = join(rootPath, '.osdo', 'reports')
  mkdirSync(reportsDir, {recursive: true})

  const combinedPath = join(reportsDir, 'certification-report.md')
  writeFileSync(combinedPath, renderCombinedReport(outcomes, generatedAt))
  const written = [combinedPath]

  for (const o of outcomes) {
    if (!o.applicable) continue
    const perStandardPath = join(reportsDir, `certification-${o.id}.md`)
    writeFileSync(perStandardPath, renderStandardReport(o.result))
    written.push(perStandardPath)
  }

  return written
}

// ──────────────────────────────────────────────────────────────────────────────
// Comando
// ──────────────────────────────────────────────────────────────────────────────

const ALL_STANDARDS: Standard[] = ['owasp', 'slsa', 'openssf', 'soc2', 'iso27001', 'owasp-mobile', 'smart-contract']

export default class Certify extends BaseCommand {
  static description = 'Verificar preparación para certificación contra estándares de seguridad'

  static summary = 'Evalúa el proyecto frente a OWASP Top 10, SLSA, OpenSSF Scorecard, SOC 2, ISO 27001, OWASP Mobile y Smart Contract'

  static examples = [
    '<%= config.bin %> certify --standard owasp',
    '<%= config.bin %> certify --standard slsa --report',
    '<%= config.bin %> certify --standards owasp,slsa,openssf --min-score 70',
    '<%= config.bin %> certify --standards owasp,soc2 --min owasp=80 --min soc2=60',
    '<%= config.bin %> certify --standard openssf --output json',
    '<%= config.bin %> certify --standard all --report',
  ]

  static flags = {
    ...BaseCommand.globalFlags,
    standard: Flags.string({
      char: 's',
      description: 'Estándar a verificar, o "all". Por defecto: owasp. Incompatible con --standards',
      options: [...ALL_STANDARDS, 'all'],
    }),
    standards: Flags.string({
      description: 'Lista de estándares separada por comas (p. ej. owasp,slsa,openssf). Incompatible con --standard',
    }),
    'min-score': Flags.integer({
      description: 'Puntuación mínima (0-100) para cada estándar evaluado; exit 3 si alguno no la alcanza',
      min: 0,
      max: 100,
    }),
    min: Flags.string({
      description: 'Umbral de un estándar concreto: <estándar>=<0-100>. Repetible; prevalece sobre --min-score',
      helpValue: 'estandar=puntuacion',
      multiple: true,
    }),
    report: Flags.boolean({
      description: 'Generar reporte combinado en .osdo/reports/certification-report.md y un reporte por estándar (certification-<estándar>.md)',
      default: false,
    }),
    path: Flags.string({
      char: 'p',
      description: 'Ruta raíz del proyecto a evaluar',
      default: '.',
    }),
    output: Flags.string({
      char: 'o',
      description: 'Formato de salida (table, json)',
      options: ['table', 'json'],
      default: 'table',
    }),
  }

  async run(): Promise<void> {
    const {flags} = await this.parse(Certify)
    const rootPath = resolve(flags.path)
    const json = flags.output === 'json'
    const say = (msg = '') => {
      if (!json) this.log(msg)
    }

    const selected = this.resolveStandards(flags)
    const thresholds = this.resolveThresholds(flags, selected)

    say(chalk.cyan('\nOSDO Certification Readiness'))
    say(chalk.gray('════════════════════════════════════════\n'))

    const ctx = buildScanContext(rootPath)

    if (flags.verbose && !json) {
      this.log(chalk.gray('Contexto de escaneo detectado:'))
      this.log(chalk.gray(`  SAST:            ${ctx.hasSAST ? chalk.green('✓') : chalk.red('✗')} (.osdo/results/sast/semgrep.json)`))
      this.log(chalk.gray(`  SCA:             ${ctx.hasSCA ? chalk.green('✓') : chalk.red('✗')} (.osdo/results/sca/)`))
      this.log(chalk.gray(`  Secrets:         ${ctx.hasSecrets ? chalk.green('✓') : chalk.red('✗')} (.osdo/results/secrets/gitleaks.json)`))
      this.log(chalk.gray(`  SBOM:            ${ctx.hasSBOM ? chalk.green('✓') : chalk.red('✗')} (.osdo/results/sbom/)`))
      this.log(chalk.gray(`  Build SBOM:      ${ctx.hasBuildSBOM ? chalk.green('✓') : chalk.red('✗')} (.osdo/results/build/)`))
      this.log(chalk.gray(`  SLSA Provenance: ${ctx.hasSLSAProvenance ? chalk.green('✓') : chalk.red('✗')} (.osdo/results/slsa/)`))
      this.log(chalk.gray(`  Config OSDO:     ${ctx.hasOsdoConfig ? chalk.green('✓') : chalk.red('✗')} (.osdo/config.yaml)`))
      this.log(chalk.gray(`  Workflow:        ${ctx.hasWorkflow ? chalk.green('✓') : chalk.red('✗')} (.github/workflows/osdo-security.yml)`))
      this.log(chalk.gray(`  SECURITY.md:     ${ctx.hasSecurityMd ? chalk.green('✓') : chalk.red('✗')}`))
      this.log(chalk.gray(`  CODE_OF_CONDUCT: ${ctx.hasCodeOfConduct ? chalk.green('✓') : chalk.red('✗')}`))
      this.log(chalk.gray(`  LICENSE:         ${ctx.hasLicense ? chalk.green('✓') : chalk.red('✗')}`))
      this.log(chalk.gray(`  CHANGELOG.md:    ${ctx.hasChangelog ? chalk.green('✓') : chalk.red('✗')}`))
      this.log(chalk.gray(`  Dependabot:      ${ctx.hasDependabot ? chalk.green('✓') : chalk.red('✗')}`))
      this.log('')
    }

    const outcomes: StandardOutcome[] = selected.map((id): StandardOutcome => {
      const applicability = probeApplicability(id, rootPath)
      if (!applicability.applicable) {
        return {id, applicable: false, name: STANDARD_NAMES[id], reason: applicability.reason ?? 'no aplicable'}
      }
      return {
        id,
        applicable: true,
        result: runStandard(id, ctx),
        threshold: thresholds[id] ?? flags['min-score'],
      }
    })

    const evaluated = outcomes.filter((o): o is EvaluatedStandard => o.applicable)
    const failures = evaluated.filter(o => o.threshold !== undefined && o.result.score < o.threshold)

    if (json) {
      const payload = outcomes.map(o => o.applicable
        ? {
          status: 'evaluated',
          ...o.result,
          minScore: o.threshold ?? null,
          thresholdMet: o.threshold === undefined ? null : o.result.score >= o.threshold,
        }
        : {id: o.id, standard: o.name, status: 'N/A', reason: o.reason})
      this.log(JSON.stringify(payload.length === 1 ? payload[0] : payload, null, 2))
    } else {
      for (const o of outcomes) {
        if (!o.applicable) {
          this.log(chalk.gray(`\nEstándar: ${o.name} — N/A (${o.reason})`))
          continue
        }
        this.log(chalk.white(`Verificando: ${o.id.toUpperCase()}`) + chalk.gray(' ...'))
        this.displayResult(o.result)
      }
    }

    if (flags.report) {
      const paths = writeReports(outcomes, rootPath, new Date())
      say(chalk.green('\nReportes generados:'))
      for (const p of paths) say(chalk.cyan(`  ${p}`))
    }

    if (evaluated.length === 0) {
      say(chalk.yellow('\nNingún estándar seleccionado aplica a este proyecto; no hay nada que evaluar.'))
      return
    }

    if (!json && evaluated.length > 1) {
      const avgScore = Math.round(evaluated.reduce((s, o) => s + o.result.score, 0) / evaluated.length)
      this.log(chalk.gray('\n════════════════════════════════════════'))
      this.log(chalk.gray('Puntuación global: ') + chalk.cyan(`${avgScore}%`) +
        chalk.gray(` (${evaluated.length} evaluado(s)${outcomes.length > evaluated.length ? `, ${outcomes.length - evaluated.length} N/A` : ''})`))
    }

    if (!json) {
      const criticalFailed = evaluated.some(o =>
        o.result.checks.some(c => c.severity === 'CRITICAL' && c.status === 'FAIL'),
      )
      if (criticalFailed) {
        this.log('')
        this.log(chalk.red('Hay controles CRÍTICOS sin cubrir. Revisa el análisis de brechas.'))
      }
    }

    if (failures.length > 0) {
      const detail = failures
        .map(o => `${o.id} ${o.result.score}% < ${o.threshold}%`)
        .join('; ')
      this.error(`Umbral de puntuación no alcanzado: ${detail}`, {exit: 3})
    }
  }

  /** Estándares a evaluar: --standards (lista) o --standard (uno o "all"; por defecto owasp). */
  private resolveStandards(flags: {standard?: string; standards?: string}): Standard[] {
    if (flags.standard !== undefined && flags.standards !== undefined) {
      this.error('--standard y --standards son incompatibles; usa solo uno.', {exit: 2})
    }

    if (flags.standards !== undefined) {
      const names = flags.standards.split(',').map(s => s.trim().toLowerCase()).filter(s => s !== '')
      if (names.length === 0) this.error('--standards no contiene ningún estándar.', {exit: 2})
      if (names.includes('all')) return [...ALL_STANDARDS]
      const unknown = names.filter(n => !isStandard(n))
      if (unknown.length > 0) {
        this.error(`Estándar(es) desconocido(s): ${unknown.join(', ')}. Válidos: ${ALL_STANDARDS.join(', ')}`, {exit: 2})
      }
      return [...new Set(names as Standard[])]
    }

    const single = flags.standard ?? 'owasp'
    return single === 'all' ? [...ALL_STANDARDS] : [single as Standard]
  }

  /** Umbrales por estándar desde --min <estándar>=<n> (repetible). */
  private resolveThresholds(flags: {min?: string[]}, selected: Standard[]): Partial<Record<Standard, number>> {
    const thresholds: Partial<Record<Standard, number>> = {}
    for (const raw of flags.min ?? []) {
      const match = /^([a-z0-9-]+)=(\d{1,3})$/.exec(raw.trim().toLowerCase())
      if (!match) this.error(`--min inválido: "${raw}". Formato: <estándar>=<0-100>`, {exit: 2})
      const [, id, value] = match
      const score = Number(value)
      if (!isStandard(id)) this.error(`--min: estándar desconocido "${id}". Válidos: ${ALL_STANDARDS.join(', ')}`, {exit: 2})
      if (score > 100) this.error(`--min ${id}=${score}: la puntuación debe estar entre 0 y 100`, {exit: 2})
      if (!selected.includes(id)) this.error(`--min ${id}=${score}: ${id} no está entre los estándares seleccionados`, {exit: 2})
      if (thresholds[id] !== undefined) this.error(`--min repetido para ${id}`, {exit: 2})
      thresholds[id] = score
    }
    return thresholds
  }

  private displayResult(result: CertificationResult): void {
    this.log(chalk.cyan(`\nEstándar: ${result.standard}`))
    this.log(chalk.gray('─────────────────────────────────────────'))

    const table = new Table({
      head: [
        chalk.white('ID'),
        chalk.white('Control'),
        chalk.white('Categoría'),
        chalk.white('Estado'),
        chalk.white('Severidad'),
        chalk.white('Scanner'),
      ],
      colWidths: [7, 28, 24, 10, 12, 30],
      wordWrap: true,
      style: {head: [], border: ['gray']},
    })

    for (const check of result.checks) {
      const statusCell = check.status === 'PASS'
        ? chalk.green('PASS')
        : check.status === 'MANUAL'
          ? chalk.blue('MANUAL')
          : chalk.red('FAIL')

      const severityCell = check.severity === 'CRITICAL'
        ? chalk.bgRed.white('CRITICAL')
        : check.severity === 'HIGH'
          ? chalk.red('HIGH')
          : check.severity === 'MEDIUM'
            ? chalk.yellow('MEDIUM')
            : chalk.green('LOW')

      table.push([
        chalk.gray(check.id),
        check.name,
        chalk.gray(check.category.split(':').pop()?.trim() ?? check.category),
        statusCell,
        severityCell,
        chalk.gray(check.scanner),
      ])
    }

    this.log(table.toString())

    this.log(`\n  ${chalk.gray('Puntuación:')} ${chalk.cyan(result.score + '%')}  ` +
      chalk.green(`Aprobados: ${result.passed}`) + '  ' +
      chalk.red(`Fallidos: ${result.failed}`) + '  ' +
      chalk.blue(`Manual: ${result.manual}`))

    if (result.gapAnalysis.length > 0) {
      this.log('\n' + chalk.yellow('  Análisis de brechas:'))
      for (const gap of result.gapAnalysis.slice(0, 8)) {
        this.log(chalk.gray('    • ') + gap)
      }
      if (result.gapAnalysis.length > 8) {
        this.log(chalk.gray(`    ... y ${result.gapAnalysis.length - 8} más. Usa --report para ver todos.`))
      }
    }

    const verdict = result.score >= 80
      ? chalk.green('  LISTO PARA CERTIFICACION')
      : result.score >= 60
        ? chalk.yellow('  CUMPLIMIENTO PARCIAL — Resolver brechas antes de certificar')
        : chalk.red('  NO LISTO — Gaps significativos requieren remediacion')

    this.log('\n' + verdict + '\n')
  }
}
