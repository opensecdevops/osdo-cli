import {Flags} from '@oclif/core'
import {existsSync, mkdirSync, readFileSync, writeFileSync} from 'node:fs'
import {join} from 'node:path'
import chalk from 'chalk'
import {BaseCommand} from '../../lib/base-command.js'

interface AggregatedFinding {
  source: string
  tool: string
  id: string
  severity: string
  description: string
  resource?: string
}

/**
 * SecurityReport — Genera un reporte consolidado HTML/Markdown/JSON
 * a partir de todos los archivos JSON en .osdo/results/security/.
 *
 * Agrega resultados de:
 *   - trivy.json (Trivy container/filesystem vulns)
 *   - grype.json (Grype SCA)
 *   - gitleaks-raw.json (Gitleaks secrets)
 *   - policies.json (Kyverno/Conftest)
 *   - semgrep.json (SAST via osdo scan)
 */
export default class SecurityReport extends BaseCommand {
  static description = 'Generar reporte consolidado de todos los scans de seguridad'

  static examples = [
    '<%= config.bin %> security report',
    '<%= config.bin %> security report --format html',
    '<%= config.bin %> security report --format markdown --output-file ./security-report.md',
  ]

  static flags = {
    ...BaseCommand.globalFlags,
    format: Flags.string({
      char: 'f',
      default: 'markdown',
      options: ['markdown', 'html', 'json'],
      description: 'Formato del reporte de salida',
    }),
    'output-file': Flags.string({
      description: 'Ruta del archivo de salida (por defecto: .osdo/reports/security-<fecha>.md)',
    }),
    'results-dir': Flags.string({
      default: '.osdo/results/security',
      description: 'Directorio con los resultados JSON de los scans',
    }),
  }

  async run(): Promise<void> {
    const {flags} = await this.parse(SecurityReport)
    const resultsDir = join(process.cwd(), flags['results-dir'])
    const reportsDir = join(process.cwd(), '.osdo', 'reports')
    mkdirSync(reportsDir, {recursive: true})

    this.log(chalk.bold('\nOSDO Security Report Generator'))
    this.log('═'.repeat(45) + '\n')

    if (!existsSync(resultsDir)) {
      this.error(`Directorio de resultados no encontrado: ${resultsDir}\nEjecuta primero: osdo scan, osdo security scan`, {exit: 1})
    }

    // Agregar findings de todas las fuentes
    const findings = this.aggregateFindings(resultsDir)

    this.log(`Total de hallazgos: ${findings.length}`)

    // Generar reporte
    const timestamp = new Date().toISOString().split('T')[0]
    const ext = flags.format === 'html' ? 'html' : flags.format === 'json' ? 'json' : 'md'
    const defaultOutput = join(reportsDir, `security-${timestamp}.${ext}`)
    const outputPath = flags['output-file'] ?? defaultOutput

    let content: string
    if (flags.format === 'html') {
      content = this.renderHtml(findings, timestamp)
    } else if (flags.format === 'json') {
      content = JSON.stringify(findings, null, 2)
    } else {
      content = this.renderMarkdown(findings, timestamp)
    }

    writeFileSync(outputPath, content, 'utf8')
    this.log(chalk.green(`\n✓ Reporte generado: ${outputPath}`))

    // Resumen por severidad
    const critical = findings.filter(f => f.severity.toUpperCase() === 'CRITICAL').length
    const high     = findings.filter(f => f.severity.toUpperCase() === 'HIGH').length
    const medium   = findings.filter(f => f.severity.toUpperCase() === 'MEDIUM').length

    this.log(`\n  ${chalk.red(`Críticos: ${critical}`)}`)
    this.log(`  ${chalk.yellow(`Altos:    ${high}`)}`)
    this.log(`  ${chalk.blue(`Medios:   ${medium}`)}`)
  }

  private aggregateFindings(resultsDir: string): AggregatedFinding[] {
    const all: AggregatedFinding[] = []

    // Trivy
    const trivyPath = join(resultsDir, 'trivy.json')
    if (existsSync(trivyPath)) {
      try {
        const data = JSON.parse(readFileSync(trivyPath, 'utf8')) as {
          Results?: Array<{
            Vulnerabilities?: Array<{
              VulnerabilityID: string
              Severity: string
              PkgName: string
              InstalledVersion: string
              Title?: string
            }>
          }>
        }
        for (const r of data.Results ?? []) {
          for (const v of r.Vulnerabilities ?? []) {
            all.push({
              source: 'trivy',
              tool: 'Trivy',
              id: v.VulnerabilityID,
              severity: v.Severity,
              description: v.Title ?? v.VulnerabilityID,
              resource: `${v.PkgName}@${v.InstalledVersion}`,
            })
          }
        }
      } catch { /* skip */ }
    }

    // Gitleaks
    const gitleaksPath = join(resultsDir, 'gitleaks-raw.json')
    if (existsSync(gitleaksPath)) {
      try {
        const data = JSON.parse(readFileSync(gitleaksPath, 'utf8')) as Array<{
          RuleID?: string
          Description?: string
          File?: string
        }>
        for (const f of data) {
          all.push({
            source: 'gitleaks',
            tool: 'Gitleaks',
            id: f.RuleID ?? 'secret',
            severity: 'CRITICAL',
            description: f.Description ?? 'Secret detected',
            resource: f.File,
          })
        }
      } catch { /* skip */ }
    }

    // Policies (Kyverno/Conftest)
    const policiesPath = join(resultsDir, 'policies.json')
    if (existsSync(policiesPath)) {
      try {
        const data = JSON.parse(readFileSync(policiesPath, 'utf8')) as Array<{
          policy: string
          rule: string
          message: string
          resource?: string
          severity: string
        }>
        for (const v of data) {
          all.push({
            source: 'policies',
            tool: 'Kyverno/OPA',
            id: `${v.policy}/${v.rule}`,
            severity: v.severity === 'error' ? 'HIGH' : 'MEDIUM',
            description: v.message,
            resource: v.resource,
          })
        }
      } catch { /* skip */ }
    }

    // Secrets detected by osdo scan (semgrep)
    const semgrepPath = join(resultsDir, '..', 'semgrep.json')
    if (existsSync(semgrepPath)) {
      try {
        const data = JSON.parse(readFileSync(semgrepPath, 'utf8')) as {
          results?: Array<{
            check_id: string
            extra?: {severity?: string; message?: string}
            path?: string
          }>
        }
        for (const r of data.results ?? []) {
          all.push({
            source: 'semgrep',
            tool: 'Semgrep',
            id: r.check_id,
            severity: r.extra?.severity ?? 'MEDIUM',
            description: r.extra?.message ?? r.check_id,
            resource: r.path,
          })
        }
      } catch { /* skip */ }
    }

    return all
  }

  private renderMarkdown(findings: AggregatedFinding[], date: string): string {
    const critical = findings.filter(f => f.severity.toUpperCase() === 'CRITICAL')
    const high     = findings.filter(f => f.severity.toUpperCase() === 'HIGH')
    const others   = findings.filter(f => !['CRITICAL','HIGH'].includes(f.severity.toUpperCase()))

    const section = (title: string, items: AggregatedFinding[], emoji: string): string => {
      if (items.length === 0) return ''
      const rows = items.map(f =>
        `| ${f.tool} | \`${f.id}\` | ${f.description.replace(/\|/g, '\\|')} | ${f.resource ?? '—'} |`
      ).join('\n')
      return `\n## ${emoji} ${title} (${items.length})\n\n| Herramienta | ID | Descripción | Recurso |\n|---|---|---|---|\n${rows}\n`
    }

    return `# Reporte de Seguridad OSDO — ${date}

## Resumen Ejecutivo

| Severidad | Cantidad |
|-----------|---------|
| 🔴 Crítico | ${critical.length} |
| 🟠 Alto    | ${high.length} |
| 🟡 Otros   | ${others.length} |
| **Total**  | **${findings.length}** |
${section('Hallazgos Críticos', critical, '🔴')}
${section('Hallazgos Altos', high, '🟠')}
${section('Otros Hallazgos', others, '🟡')}

---
*Generado por OSDO CLI v2 — ${new Date().toISOString()}*
`
  }

  private renderHtml(findings: AggregatedFinding[], date: string): string {
    const critical = findings.filter(f => f.severity.toUpperCase() === 'CRITICAL').length
    const high     = findings.filter(f => f.severity.toUpperCase() === 'HIGH').length
    const medium   = findings.filter(f => f.severity.toUpperCase() === 'MEDIUM').length

    const rows = findings.map(f => {
      const color = f.severity.toUpperCase() === 'CRITICAL' ? '#dc2626'
        : f.severity.toUpperCase() === 'HIGH' ? '#ea580c'
        : f.severity.toUpperCase() === 'MEDIUM' ? '#ca8a04' : '#6b7280'
      return `<tr>
        <td>${f.tool}</td>
        <td><code>${f.id}</code></td>
        <td style="color:${color}"><strong>${f.severity}</strong></td>
        <td>${f.description}</td>
        <td>${f.resource ?? '—'}</td>
      </tr>`
    }).join('\n')

    return `<!DOCTYPE html>
<html lang="es">
<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width, initial-scale=1.0">
  <title>Reporte de Seguridad OSDO — ${date}</title>
  <style>
    body { font-family: system-ui, sans-serif; max-width: 1200px; margin: 40px auto; padding: 0 20px; color: #1f2937; }
    h1 { border-bottom: 2px solid #dc2626; padding-bottom: 10px; }
    .summary { display: grid; grid-template-columns: repeat(4, 1fr); gap: 16px; margin: 24px 0; }
    .card { border-radius: 8px; padding: 20px; text-align: center; }
    .card.critical { background: #fef2f2; border: 1px solid #fecaca; }
    .card.high { background: #fff7ed; border: 1px solid #fed7aa; }
    .card.medium { background: #fefce8; border: 1px solid #fde047; }
    .card.total { background: #f9fafb; border: 1px solid #d1d5db; }
    .card h3 { margin: 0 0 8px; font-size: 0.875rem; text-transform: uppercase; }
    .card .number { font-size: 2rem; font-weight: bold; }
    table { width: 100%; border-collapse: collapse; margin-top: 24px; }
    th { background: #f3f4f6; text-align: left; padding: 12px; font-size: 0.875rem; }
    td { padding: 12px; border-bottom: 1px solid #e5e7eb; font-size: 0.875rem; }
    tr:hover { background: #f9fafb; }
    code { background: #f3f4f6; padding: 2px 6px; border-radius: 4px; font-size: 0.8rem; }
    footer { margin-top: 40px; padding-top: 20px; border-top: 1px solid #e5e7eb; color: #9ca3af; font-size: 0.75rem; }
  </style>
</head>
<body>
  <h1>🔐 Reporte de Seguridad OSDO</h1>
  <p>Fecha: ${date} | Total: ${findings.length} hallazgos</p>

  <div class="summary">
    <div class="card critical"><h3>Crítico</h3><div class="number" style="color:#dc2626">${critical}</div></div>
    <div class="card high"><h3>Alto</h3><div class="number" style="color:#ea580c">${high}</div></div>
    <div class="card medium"><h3>Medio</h3><div class="number" style="color:#ca8a04">${medium}</div></div>
    <div class="card total"><h3>Total</h3><div class="number">${findings.length}</div></div>
  </div>

  <table>
    <thead>
      <tr><th>Herramienta</th><th>ID</th><th>Severidad</th><th>Descripción</th><th>Recurso</th></tr>
    </thead>
    <tbody>${rows}</tbody>
  </table>

  <footer>Generado por OSDO CLI v2 — ${new Date().toISOString()}</footer>
</body>
</html>`
  }
}
