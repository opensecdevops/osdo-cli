import {Flags} from '@oclif/core'
import {existsSync, mkdirSync, writeFileSync} from 'node:fs'
import {join} from 'node:path'
import chalk from 'chalk'
import {BaseCommand} from '../../lib/base-command.js'

/**
 * Resultado de un control de conformidad individual.
 */
interface ComplianceCheck {
  id: string
  name: string
  status: 'PASS' | 'FAIL' | 'MANUAL' | 'SKIP'
  detail: string
}

/**
 * SecurityCompliance — Verifica que el repositorio cumple con estándares
 * de seguridad reconocidos: OpenSSF Scorecard, SLSA, OWASP Top 10, SOC2 e ISO27001.
 *
 * Los controles se evalúan inspeccionando la presencia de artefactos en disco
 * (SECURITY.md, LICENSE, .github/workflows, resultados de SAST/SCA, SBOM, etc.)
 * y se complementan con controles MANUAL cuando se requiere revisión humana.
 *
 * La verificación no es invasiva: nunca escribe ni modifica archivos del proyecto.
 * El reporte Markdown opcional se genera en .osdo/reports/compliance-report.md.
 */
export default class SecurityCompliance extends BaseCommand {
  static description = 'Verificar conformidad con estándares de seguridad'

  static examples = [
    '<%= config.bin %> security compliance --standard owasp',
    '<%= config.bin %> security compliance --standard slsa',
    '<%= config.bin %> security compliance --standard all --report',
    '<%= config.bin %> security compliance --output json',
  ]

  static flags = {
    ...BaseCommand.globalFlags,
    standard: Flags.string({
      default: 'all',
      options: ['owasp', 'slsa', 'openssf', 'soc2', 'iso27001', 'all'],
      description: 'Estándar de seguridad a verificar',
    }),
    report: Flags.boolean({
      default: false,
      description: 'Generar reporte de conformidad en Markdown (.osdo/reports/)',
    }),
  }

  async run(): Promise<void> {
    const {flags} = await this.parse(SecurityCompliance)
    const cwd = process.cwd()

    this.log(chalk.bold('\nVerificacion de Conformidad OSDO'))
    this.log('═'.repeat(45) + '\n')

    // Inspección de artefactos presentes en el repositorio
    const hasSecurityMd    = existsSync(join(cwd, 'SECURITY.md'))
    const hasLicense       = existsSync(join(cwd, 'LICENSE')) || existsSync(join(cwd, 'LICENSE.md'))
    const hasChangelog     = existsSync(join(cwd, 'CHANGELOG.md')) || existsSync(join(cwd, 'CHANGELOG'))
    const hasContributing  = existsSync(join(cwd, 'CONTRIBUTING.md'))
    const hasCiWorkflow    = existsSync(join(cwd, '.github/workflows'))
    const hasSbom          = existsSync(join(cwd, '.osdo/results/build/sbom-cyclonedx.json')) ||
                             existsSync(join(cwd, '.osdo/results/build/sbom-spdx.json'))
    const hasSastResults   = existsSync(join(cwd, '.osdo/results/sast'))
    const hasSlsaProvenance = existsSync(join(cwd, '.osdo/results/build/provenance.intoto.jsonl'))
    const hasDepScan       = existsSync(join(cwd, '.osdo/results/sca'))
    const hasSecretsScan   = existsSync(join(cwd, '.osdo/results/secrets'))

    const checks: ComplianceCheck[] = []

    // ----- OpenSSF Scorecard -----
    if (flags.standard === 'all' || flags.standard === 'openssf') {
      checks.push(
        {
          id: 'OPENSSF-01',
          name: 'Licencia FLOSS presente',
          status: hasLicense ? 'PASS' : 'FAIL',
          detail: hasLicense ? 'LICENSE encontrado' : 'Falta archivo LICENSE',
        },
        {
          id: 'OPENSSF-02',
          name: 'SECURITY.md presente',
          status: hasSecurityMd ? 'PASS' : 'FAIL',
          detail: hasSecurityMd ? 'SECURITY.md encontrado' : 'Falta SECURITY.md con política de vulnerabilidades',
        },
        {
          id: 'OPENSSF-03',
          name: 'CHANGELOG presente',
          status: hasChangelog ? 'PASS' : 'FAIL',
          detail: hasChangelog ? 'CHANGELOG encontrado' : 'Falta CHANGELOG para trazabilidad de cambios',
        },
        {
          id: 'OPENSSF-04',
          name: 'CONTRIBUTING.md presente',
          status: hasContributing ? 'PASS' : 'FAIL',
          detail: hasContributing ? 'CONTRIBUTING.md encontrado' : 'Falta CONTRIBUTING.md',
        },
        {
          id: 'OPENSSF-05',
          name: 'CI/CD configurado',
          status: hasCiWorkflow ? 'PASS' : 'FAIL',
          detail: hasCiWorkflow ? '.github/workflows encontrado' : 'Sin workflows de CI/CD',
        },
        {
          id: 'OPENSSF-06',
          name: 'SAST ejecutado',
          status: hasSastResults ? 'PASS' : 'FAIL',
          detail: hasSastResults ? 'Resultados SAST encontrados' : 'Ejecuta: osdo scan --type sast',
        },
      )
    }

    // ----- SLSA (Supply chain Levels for Software Artifacts) -----
    if (flags.standard === 'all' || flags.standard === 'slsa') {
      checks.push(
        {
          id: 'SLSA-L1',
          name: 'Build scripted (CI/CD)',
          status: hasCiWorkflow ? 'PASS' : 'FAIL',
          detail: hasCiWorkflow ? 'Workflows de CI/CD detectados' : 'Requiere build automatizado en CI/CD',
        },
        {
          id: 'SLSA-L2',
          name: 'SBOM generado',
          status: hasSbom ? 'PASS' : 'FAIL',
          detail: hasSbom ? 'SBOM encontrado en .osdo/results/build/' : 'Ejecuta la action osdo-sbom para generar el SBOM',
        },
        {
          id: 'SLSA-L3',
          name: 'Provenance SLSA',
          status: hasSlsaProvenance ? 'PASS' : 'FAIL',
          detail: hasSlsaProvenance ? 'provenance.intoto.jsonl encontrado' : 'Ejecuta la action osdo-slsa-provenance',
        },
      )
    }

    // ----- OWASP Top 10 (controles verificables automáticamente) -----
    if (flags.standard === 'all' || flags.standard === 'owasp') {
      checks.push(
        {
          id: 'OWASP-A01',
          name: 'Control de acceso (IaC)',
          status: 'MANUAL',
          detail: 'Requiere revisión manual de políticas de acceso en IaC',
        },
        {
          id: 'OWASP-A02',
          name: 'SAST ejecutado (Criptografía)',
          status: hasSastResults ? 'PASS' : 'FAIL',
          detail: hasSastResults ? 'Semgrep detecta usos inseguros de criptografía' : 'Ejecuta: osdo scan --type sast',
        },
        {
          id: 'OWASP-A06',
          name: 'SCA ejecutado (Dependencias vulnerables)',
          status: hasDepScan ? 'PASS' : 'FAIL',
          detail: hasDepScan ? 'Scan de dependencias encontrado' : 'Ejecuta: osdo scan --type sca',
        },
        {
          id: 'OWASP-A09',
          name: 'Detección de secretos en código',
          status: hasSecretsScan ? 'PASS' : 'FAIL',
          detail: hasSecretsScan ? 'Scan de secretos (Gitleaks) encontrado' : 'Ejecuta: osdo scan --type secrets',
        },
      )
    }

    // ----- SOC2 (controles de proceso) -----
    if (flags.standard === 'all' || flags.standard === 'soc2') {
      checks.push(
        {
          id: 'SOC2-CC6.1',
          name: 'Revisión de acceso lógico',
          status: 'MANUAL',
          detail: 'Requiere auditoría de controles de acceso y autenticación',
        },
        {
          id: 'SOC2-CC7.1',
          name: 'Gestión de vulnerabilidades',
          status: hasDepScan && hasSastResults ? 'PASS' : 'FAIL',
          detail: hasDepScan && hasSastResults
            ? 'SCA + SAST ejecutados — evidencia de gestión de vulnerabilidades'
            : 'Ejecuta osdo scan --type all para generar evidencia',
        },
        {
          id: 'SOC2-CC8.1',
          name: 'Gestión de cambios (CI/CD)',
          status: hasCiWorkflow ? 'PASS' : 'FAIL',
          detail: hasCiWorkflow ? 'Pipeline de CI/CD detectado' : 'Implementa un pipeline de CI/CD',
        },
      )
    }

    // ----- ISO 27001 (controles clave) -----
    if (flags.standard === 'all' || flags.standard === 'iso27001') {
      checks.push(
        {
          id: 'ISO-A.8.8',
          name: 'Gestión de vulnerabilidades técnicas',
          status: hasDepScan && hasSastResults ? 'PASS' : 'FAIL',
          detail: 'Controles técnicos: SCA + SAST',
        },
        {
          id: 'ISO-A.8.25',
          name: 'Seguridad en ciclo de vida del desarrollo',
          status: hasCiWorkflow && hasSastResults ? 'PASS' : 'FAIL',
          detail: 'Requiere integración de seguridad en CI/CD con SAST',
        },
        {
          id: 'ISO-A.5.20',
          name: 'Seguridad en cadena de suministro',
          status: hasSbom ? 'PASS' : 'FAIL',
          detail: hasSbom ? 'SBOM generado — trazabilidad de dependencias' : 'Genera SBOM con la action osdo-sbom',
        },
      )
    }

    // Salida JSON si se solicita
    if (flags.output === 'json') {
      this.log(JSON.stringify(checks, null, 2))
      return
    }

    // Mostrar resultados
    let passCount   = 0
    let failCount   = 0
    let manualCount = 0

    for (const check of checks) {
      const icon =
        check.status === 'PASS'   ? chalk.green('✓') :
        check.status === 'FAIL'   ? chalk.red('✗') :
        chalk.yellow('◎')

      this.log(`${icon} [${check.id}] ${check.name}`)

      // Mostrar detalle siempre en modo verbose o cuando no pasa
      if (this.configManager.isVerbose() || check.status !== 'PASS') {
        this.log(`     ${chalk.gray(check.detail)}`)
      }

      if (check.status === 'PASS')        passCount++
      else if (check.status === 'FAIL')   failCount++
      else                                manualCount++
    }

    this.log(
      `\nResumen: ${chalk.green(passCount + ' PASS')} | ` +
      `${chalk.red(failCount + ' FAIL')} | ` +
      `${chalk.yellow(manualCount + ' MANUAL')}`,
    )

    // Generar reporte Markdown si se solicita
    if (flags.report) {
      const reportsDir = join(cwd, '.osdo', 'reports')
      mkdirSync(reportsDir, {recursive: true})
      const reportPath    = join(reportsDir, 'compliance-report.md')
      const reportContent = this.generateMarkdownReport(checks, flags.standard)
      writeFileSync(reportPath, reportContent)
      this.log(`\n✓ Reporte generado: ${reportPath}`)
    }
  }

  /**
   * Genera un reporte de conformidad en formato Markdown.
   */
  private generateMarkdownReport(checks: ComplianceCheck[], standard: string): string {
    const date       = new Date().toLocaleDateString('es-ES')
    const passCount  = checks.filter(c => c.status === 'PASS').length
    const total      = checks.length
    const score      = total > 0 ? Math.round((passCount / total) * 100) : 0
    const statusLine =
      score >= 80 ? '✅ **CONFORME**' :
      score >= 60 ? '⚠️ **PARCIALMENTE CONFORME**' :
      '❌ **NO CONFORME**'

    return `# Reporte de Conformidad OSDO

**Estándar**: ${standard.toUpperCase()}
**Fecha**: ${date}
**Puntuación**: ${score}% (${passCount}/${total} controles superados)

## Estado General

${statusLine}

## Resultados Detallados

| ID | Control | Estado | Detalle |
|----|---------|--------|---------|
${checks.map(c => `| ${c.id} | ${c.name} | ${c.status} | ${c.detail} |`).join('\n')}

---

*Generado por OSDO CLI v2.0*
`
  }
}
