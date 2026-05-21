import {Flags} from '@oclif/core'
import chalk from 'chalk'
import {execa} from 'execa'
import {existsSync, mkdirSync, readFileSync, writeFileSync} from 'node:fs'
import {join} from 'node:path'
import Table from 'cli-table3'
import {BaseCommand} from '../lib/base-command.js'

// ──────────────────────────────────────────────────────────────────────────────
// Tipos
// ──────────────────────────────────────────────────────────────────────────────

type Severity = 'CRITICAL' | 'HIGH' | 'MEDIUM' | 'LOW' | 'INFO'

interface ScanFinding {
  scanner: string
  severity: Severity
  rule: string
  file: string
  line: number
  message: string
  fixAvailable?: boolean
}

interface ScanResult {
  scanner: string
  type: string
  critical: number
  high: number
  medium: number
  low: number
  total: number
  findings: ScanFinding[]
  durationMs: number
  success: boolean
  error?: string
}

// Umbral de fallo → código de salida 3
const FAIL_EXIT_CODE = 3

// ──────────────────────────────────────────────────────────────────────────────
// Comando
// ──────────────────────────────────────────────────────────────────────────────

export default class Scan extends BaseCommand {
  static description = 'Ejecutar escaneos de seguridad locales en el codebase usando herramientas reales'

  static summary = 'Escaneo de seguridad local (Semgrep, OSV-Scanner, Gitleaks, Trivy, Hadolint, Checkov)'

  static examples = [
    '<%= config.bin %> scan',
    '<%= config.bin %> scan --type sast',
    '<%= config.bin %> scan --type sca',
    '<%= config.bin %> scan --type secrets',
    '<%= config.bin %> scan --type container',
    '<%= config.bin %> scan --type iac',
    '<%= config.bin %> scan --type all --output json',
    '<%= config.bin %> scan --fail-on high',
    '<%= config.bin %> scan --fail-on critical --report',
  ]

  static flags = {
    ...BaseCommand.globalFlags,
    type: Flags.string({
      char: 't',
      description: 'Tipo de escaneo a ejecutar',
      options: ['all', 'sast', 'sca', 'secrets', 'container', 'iac'],
      default: 'all',
    }),
    path: Flags.string({
      char: 'p',
      description: 'Ruta del codebase a escanear',
      default: '.',
    }),
    output: Flags.string({
      char: 'o',
      description: 'Formato de salida (table, json)',
      options: ['table', 'json'],
      default: 'table',
    }),
    'fail-on': Flags.string({
      description: 'Severidad mínima que causa fallo del comando (código de salida 3)',
      options: ['low', 'medium', 'high', 'critical'],
      default: 'high',
    }),
    image: Flags.string({
      description: 'Nombre de la imagen Docker para escaneo de contenedor con Trivy (p.ej. myapp:latest)',
    }),
    report: Flags.boolean({
      description: 'Generar reporte JSON en .osdo/reports/scan-report.json',
      default: false,
    }),
    config: Flags.string({
      char: 'c',
      description: 'Ruta al archivo de configuración OSDO (.osdo/config.yaml)',
    }),
  }

  // ────────────────────────────────────────────────────────────────────────────
  // Punto de entrada
  // ────────────────────────────────────────────────────────────────────────────

  async run(): Promise<void> {
    const {flags} = await this.parse(Scan)

    this.log(chalk.cyan('\nOSDO Security Scanner'))
    this.log(chalk.gray('════════════════════════════════════════\n'))

    const startTime = Date.now()
    const results: ScanResult[] = []

    // Ejecutar escaneos según tipo seleccionado
    const runAll = flags.type === 'all'

    if (runAll || flags.type === 'sast') {
      results.push(await this.runSASTScan(flags.path))
    }

    if (runAll || flags.type === 'sca') {
      results.push(await this.runSCAScan(flags.path))
    }

    if (runAll || flags.type === 'secrets') {
      results.push(await this.runSecretsScan(flags.path))
    }

    if (runAll || flags.type === 'container') {
      const containerResults = await this.runContainerScan(flags.path, flags.image)
      results.push(...containerResults)
    }

    if (runAll || flags.type === 'iac') {
      results.push(await this.runIaCScan(flags.path))
    }

    const totalDurationMs = Date.now() - startTime

    // ─── Salida ────────────────────────────────────────────────────────────────
    if (flags.output === 'json') {
      this.log(JSON.stringify({results, totalDurationMs, timestamp: new Date().toISOString()}, null, 2))
    } else {
      this.displayScanSummary(results, totalDurationMs)
    }

    // ─── Reporte ───────────────────────────────────────────────────────────────
    if (flags.report) {
      const reportsDir = join(flags.path, '.osdo', 'reports')
      mkdirSync(reportsDir, {recursive: true})
      const reportPath = join(reportsDir, 'scan-report.json')
      writeFileSync(reportPath, JSON.stringify({results, totalDurationMs, timestamp: new Date().toISOString()}, null, 2))
      this.log(`\nReporte guardado en: ${chalk.cyan(reportPath)}`)
    }

    // ─── Umbral de fallo ───────────────────────────────────────────────────────
    const totals = this.sumTotals(results)
    const failThreshold = flags['fail-on']
    const shouldFail = this.exceedsThreshold(totals, failThreshold)

    if (shouldFail) {
      this.log('')
      this.log(chalk.red('Escaneo de seguridad FALLIDO — hallazgos por encima del umbral configurado'))
      this.log(
        chalk.gray('  Umbral: ') + chalk.yellow(failThreshold) +
        chalk.gray('  |  Crítico: ') + this.colorCount(totals.critical, 'critical') +
        chalk.gray('  |  Alto: ') + this.colorCount(totals.high, 'high') +
        chalk.gray('  |  Medio: ') + this.colorCount(totals.medium, 'medium') +
        chalk.gray('  |  Bajo: ') + this.colorCount(totals.low, 'low'),
      )
      this.exit(FAIL_EXIT_CODE)
    }

    this.log('\n' + chalk.green('Todos los escaneos completados satisfactoriamente'))
  }

  // ────────────────────────────────────────────────────────────────────────────
  // Escaneo SAST — Semgrep
  // ────────────────────────────────────────────────────────────────────────────

  private async runSASTScan(targetPath: string): Promise<ScanResult> {
    const label = 'semgrep (SAST)'
    this.log(chalk.blue('Ejecutando SAST — Semgrep...'))
    const start = Date.now()
    const outputDir = join(targetPath, '.osdo', 'results', 'sast')
    const outputFile = join(outputDir, 'semgrep.json')
    mkdirSync(outputDir, {recursive: true})

    if (!await this.isToolAvailable('semgrep')) {
      this.warn('Semgrep no está instalado — omitiendo SAST. Instala con: pip install semgrep')
      return this.errorResult(label, 'sast', 'Semgrep no instalado', Date.now() - start)
    }

    try {
      // semgrep sale con código no-cero cuando encuentra hallazgos; capturamos igualmente
      await execa('semgrep', [
        'scan',
        '--config', 'auto',
        '--json',
        '--output', outputFile,
        targetPath,
      ], {reject: false})

      return this.parseSemgrepResults(outputFile, Date.now() - start)
    } catch (error) {
      return this.errorResult(label, 'sast', `Error al ejecutar Semgrep: ${(error as Error).message}`, Date.now() - start)
    }
  }

  // ────────────────────────────────────────────────────────────────────────────
  // Escaneo SCA — OSV-Scanner
  // ────────────────────────────────────────────────────────────────────────────

  private async runSCAScan(targetPath: string): Promise<ScanResult> {
    const label = 'osv-scanner (SCA)'
    this.log(chalk.blue('Ejecutando SCA — OSV-Scanner...'))
    const start = Date.now()
    const outputDir = join(targetPath, '.osdo', 'results', 'sca')
    const outputFile = join(outputDir, 'osv.json')
    mkdirSync(outputDir, {recursive: true})

    if (!await this.isToolAvailable('osv-scanner')) {
      this.warn('OSV-Scanner no está instalado — omitiendo SCA.\n  Instala con: go install github.com/google/osv-scanner/cmd/osv-scanner@latest')
      return this.errorResult(label, 'sca', 'OSV-Scanner no instalado', Date.now() - start)
    }

    try {
      // osv-scanner sale con código no-cero cuando encuentra vulnerabilidades
      await execa('osv-scanner', [
        '--format', 'json',
        '--output', outputFile,
        '-r', targetPath,
      ], {reject: false})

      return this.parseOSVResults(outputFile, Date.now() - start)
    } catch (error) {
      return this.errorResult(label, 'sca', `Error al ejecutar OSV-Scanner: ${(error as Error).message}`, Date.now() - start)
    }
  }

  // ────────────────────────────────────────────────────────────────────────────
  // Escaneo de Secretos — Gitleaks
  // ────────────────────────────────────────────────────────────────────────────

  private async runSecretsScan(targetPath: string): Promise<ScanResult> {
    const label = 'gitleaks (Secrets)'
    this.log(chalk.blue('Ejecutando Secrets — Gitleaks...'))
    const start = Date.now()
    const outputDir = join(targetPath, '.osdo', 'results', 'secrets')
    const outputFile = join(outputDir, 'gitleaks.json')
    mkdirSync(outputDir, {recursive: true})

    if (!await this.isToolAvailable('gitleaks')) {
      this.warn('Gitleaks no está instalado — omitiendo escaneo de secretos.\n  Instala con: brew install gitleaks  o  https://github.com/gitleaks/gitleaks')
      return this.errorResult(label, 'secrets', 'Gitleaks no instalado', Date.now() - start)
    }

    try {
      await execa('gitleaks', [
        'detect',
        '--source', targetPath,
        '--report-format', 'json',
        '--report-path', outputFile,
        '--exit-code', '0',
      ], {reject: false})

      return this.parseGitleaksResults(outputFile, Date.now() - start)
    } catch (error) {
      return this.errorResult(label, 'secrets', `Error al ejecutar Gitleaks: ${(error as Error).message}`, Date.now() - start)
    }
  }

  // ────────────────────────────────────────────────────────────────────────────
  // Escaneo de Contenedor — Hadolint + Trivy
  // ────────────────────────────────────────────────────────────────────────────

  private async runContainerScan(targetPath: string, image?: string): Promise<ScanResult[]> {
    this.log(chalk.blue('Ejecutando Container — Hadolint + Trivy...'))

    const results: ScanResult[] = []
    const dockerfilePath = join(targetPath, 'Dockerfile')
    const outputDir = join(targetPath, '.osdo', 'results', 'container')
    mkdirSync(outputDir, {recursive: true})

    if (!existsSync(dockerfilePath) && !image) {
      this.warn('No se encontró Dockerfile en la ruta especificada — omitiendo escaneo de contenedor')
      return results
    }

    // Hadolint — lint del Dockerfile
    if (existsSync(dockerfilePath)) {
      results.push(await this.runHadolintScan(dockerfilePath, outputDir))
    }

    // Trivy — imagen Docker (si se especificó) o filesystem
    if (image) {
      results.push(await this.runTrivyImageScan(image, outputDir))
    } else {
      results.push(await this.runTrivyFsScan(targetPath, outputDir))
    }

    return results
  }

  private async runHadolintScan(dockerfilePath: string, outputDir: string): Promise<ScanResult> {
    const label = 'hadolint (Container)'
    const start = Date.now()

    if (!await this.isToolAvailable('hadolint')) {
      this.warn('Hadolint no está instalado — omitiendo. Instala con: brew install hadolint')
      return this.errorResult(label, 'container', 'Hadolint no instalado', Date.now() - start)
    }

    try {
      const proc = await execa('hadolint', ['--format', 'json', dockerfilePath], {reject: false})
      const raw = JSON.parse(proc.stdout || '[]') as Array<{
        code: string; level: string; message: string; line: number
      }>

      const findings: ScanFinding[] = raw.map(f => ({
        scanner: 'hadolint',
        severity: f.level === 'error' ? 'HIGH' : f.level === 'warning' ? 'MEDIUM' : 'LOW',
        rule: f.code,
        file: dockerfilePath,
        line: f.line,
        message: f.message,
      }))

      writeFileSync(join(outputDir, 'hadolint.json'), JSON.stringify(raw, null, 2))

      return {
        scanner: label,
        type: 'container',
        critical: 0,
        high: findings.filter(f => f.severity === 'HIGH').length,
        medium: findings.filter(f => f.severity === 'MEDIUM').length,
        low: findings.filter(f => f.severity === 'LOW').length,
        total: findings.length,
        findings,
        durationMs: Date.now() - start,
        success: true,
      }
    } catch (error) {
      return this.errorResult(label, 'container', `Error al ejecutar Hadolint: ${(error as Error).message}`, Date.now() - start)
    }
  }

  private async runTrivyImageScan(image: string, outputDir: string): Promise<ScanResult> {
    const label = 'trivy-image (Container)'
    const start = Date.now()
    const outputFile = join(outputDir, 'trivy.json')

    if (!await this.isToolAvailable('trivy')) {
      this.warn('Trivy no está instalado — omitiendo escaneo de imagen. Instala con: brew install trivy')
      return this.errorResult(label, 'container', 'Trivy no instalado', Date.now() - start)
    }

    try {
      await execa('trivy', [
        'image',
        '--format', 'json',
        '--output', outputFile,
        image,
      ], {reject: false})

      return this.parseTrivyResults(label, 'container', outputFile, Date.now() - start)
    } catch (error) {
      return this.errorResult(label, 'container', `Error al ejecutar Trivy: ${(error as Error).message}`, Date.now() - start)
    }
  }

  private async runTrivyFsScan(targetPath: string, outputDir: string): Promise<ScanResult> {
    const label = 'trivy-fs (Container)'
    const start = Date.now()
    const outputFile = join(outputDir, 'trivy-fs.json')

    if (!await this.isToolAvailable('trivy')) {
      this.warn('Trivy no está instalado — omitiendo. Instala con: brew install trivy')
      return this.errorResult(label, 'container', 'Trivy no instalado', Date.now() - start)
    }

    try {
      await execa('trivy', [
        'fs',
        '--format', 'json',
        '--output', outputFile,
        targetPath,
      ], {reject: false})

      return this.parseTrivyResults(label, 'container', outputFile, Date.now() - start)
    } catch (error) {
      return this.errorResult(label, 'container', `Error al ejecutar Trivy fs: ${(error as Error).message}`, Date.now() - start)
    }
  }

  // ────────────────────────────────────────────────────────────────────────────
  // Escaneo IaC — Checkov
  // ────────────────────────────────────────────────────────────────────────────

  private async runIaCScan(targetPath: string): Promise<ScanResult> {
    const label = 'checkov (IaC)'
    this.log(chalk.blue('Ejecutando IaC — Checkov...'))
    const start = Date.now()
    const outputDir = join(targetPath, '.osdo', 'results', 'iac')
    const outputFile = join(outputDir, 'checkov.json')
    mkdirSync(outputDir, {recursive: true})

    if (!await this.isToolAvailable('checkov')) {
      this.warn('Checkov no está instalado — omitiendo IaC. Instala con: pip install checkov')
      return this.errorResult(label, 'iac', 'Checkov no instalado', Date.now() - start)
    }

    try {
      await execa('checkov', [
        '-d', targetPath,
        '-o', 'json',
        '--output-file', outputFile,
      ], {reject: false})

      return this.parseCheckovResults(outputFile, Date.now() - start)
    } catch (error) {
      return this.errorResult(label, 'iac', `Error al ejecutar Checkov: ${(error as Error).message}`, Date.now() - start)
    }
  }

  // ────────────────────────────────────────────────────────────────────────────
  // Parsers de resultados
  // ────────────────────────────────────────────────────────────────────────────

  private parseSemgrepResults(outputFile: string, durationMs: number): ScanResult {
    const label = 'semgrep (SAST)'
    try {
      const raw = JSON.parse(readFileSync(outputFile, 'utf8')) as {
        results?: Array<{
          check_id?: string
          path?: string
          start?: {line?: number}
          extra?: {severity?: string; message?: string}
        }>
      }
      const items = raw.results || []

      const findings: ScanFinding[] = items.map(r => ({
        scanner: 'semgrep',
        severity: this.mapSemgrepSeverity(r.extra?.severity),
        rule: r.check_id || '',
        file: r.path || '',
        line: r.start?.line || 0,
        message: r.extra?.message || '',
      }))

      return {
        scanner: label,
        type: 'sast',
        critical: findings.filter(f => f.severity === 'CRITICAL').length,
        high: findings.filter(f => f.severity === 'HIGH').length,
        medium: findings.filter(f => f.severity === 'MEDIUM').length,
        low: findings.filter(f => f.severity === 'LOW').length,
        total: findings.length,
        findings,
        durationMs,
        success: true,
      }
    } catch {
      return this.errorResult(label, 'sast', 'No se pudo leer el resultado de Semgrep', durationMs)
    }
  }

  private parseOSVResults(outputFile: string, durationMs: number): ScanResult {
    const label = 'osv-scanner (SCA)'
    try {
      const raw = JSON.parse(readFileSync(outputFile, 'utf8')) as {
        results?: Array<{
          packages?: Array<{
            package?: {name?: string}
            vulnerabilities?: Array<{
              id?: string
              summary?: string
              severity?: Array<{score?: number}>
            }>
          }>
        }>
      }

      const findings: ScanFinding[] = []
      for (const r of raw.results || []) {
        for (const pkg of r.packages || []) {
          for (const vuln of pkg.vulnerabilities || []) {
            const score = vuln.severity?.[0]?.score || 0
            findings.push({
              scanner: 'osv-scanner',
              severity: this.mapCvssScore(score),
              rule: vuln.id || '',
              file: pkg.package?.name || '',
              line: 0,
              message: vuln.summary || '',
            })
          }
        }
      }

      return {
        scanner: label,
        type: 'sca',
        critical: findings.filter(f => f.severity === 'CRITICAL').length,
        high: findings.filter(f => f.severity === 'HIGH').length,
        medium: findings.filter(f => f.severity === 'MEDIUM').length,
        low: findings.filter(f => f.severity === 'LOW').length,
        total: findings.length,
        findings,
        durationMs,
        success: true,
      }
    } catch {
      return this.errorResult(label, 'sca', 'No se pudo leer el resultado de OSV-Scanner', durationMs)
    }
  }

  private parseGitleaksResults(outputFile: string, durationMs: number): ScanResult {
    const label = 'gitleaks (Secrets)'
    try {
      const raw = JSON.parse(readFileSync(outputFile, 'utf8')) as Array<{
        RuleID?: string; Description?: string; File?: string; StartLine?: number
      }>

      const findings: ScanFinding[] = raw.map(f => ({
        scanner: 'gitleaks',
        severity: 'HIGH' as Severity,
        rule: f.RuleID || 'secreto-detectado',
        file: f.File || '',
        line: f.StartLine || 0,
        message: f.Description || 'Secreto potencial detectado',
      }))

      return {
        scanner: label,
        type: 'secrets',
        critical: 0,
        high: findings.length,
        medium: 0,
        low: 0,
        total: findings.length,
        findings,
        durationMs,
        success: true,
      }
    } catch {
      return this.errorResult(label, 'secrets', 'No se pudo leer el resultado de Gitleaks', durationMs)
    }
  }

  private parseTrivyResults(label: string, type: string, outputFile: string, durationMs: number): ScanResult {
    try {
      const raw = JSON.parse(readFileSync(outputFile, 'utf8')) as {
        Results?: Array<{
          Vulnerabilities?: Array<{
            VulnerabilityID?: string
            PkgName?: string
            Title?: string
            Severity?: string
          }>
        }>
      }

      const findings: ScanFinding[] = []
      for (const r of raw.Results || []) {
        for (const v of r.Vulnerabilities || []) {
          findings.push({
            scanner: 'trivy',
            severity: (v.Severity?.toUpperCase() as Severity) || 'LOW',
            rule: v.VulnerabilityID || '',
            file: v.PkgName || '',
            line: 0,
            message: v.Title || '',
          })
        }
      }

      return {
        scanner: label,
        type,
        critical: findings.filter(f => f.severity === 'CRITICAL').length,
        high: findings.filter(f => f.severity === 'HIGH').length,
        medium: findings.filter(f => f.severity === 'MEDIUM').length,
        low: findings.filter(f => f.severity === 'LOW').length,
        total: findings.length,
        findings,
        durationMs,
        success: true,
      }
    } catch {
      return this.errorResult(label, type, 'No se pudo leer el resultado de Trivy', durationMs)
    }
  }

  private parseCheckovResults(outputFile: string, durationMs: number): ScanResult {
    const label = 'checkov (IaC)'
    try {
      const raw = JSON.parse(readFileSync(outputFile, 'utf8')) as {
        results?: {
          failed_checks?: Array<{
            check_id?: string
            check_type?: string
            resource?: string
            file_path?: string
            file_line_range?: [number, number]
            severity?: string
          }>
        }
      }

      const failed = raw.results?.failed_checks || []
      const findings: ScanFinding[] = failed.map(c => ({
        scanner: 'checkov',
        severity: (c.severity?.toUpperCase() as Severity) || 'MEDIUM',
        rule: c.check_id || '',
        file: c.file_path || '',
        line: c.file_line_range?.[0] || 0,
        message: `${c.check_type || 'IaC'}: ${c.resource || ''}`,
      }))

      return {
        scanner: label,
        type: 'iac',
        critical: findings.filter(f => f.severity === 'CRITICAL').length,
        high: findings.filter(f => f.severity === 'HIGH').length,
        medium: findings.filter(f => f.severity === 'MEDIUM').length,
        low: findings.filter(f => f.severity === 'LOW').length,
        total: findings.length,
        findings,
        durationMs,
        success: true,
      }
    } catch {
      return this.errorResult(label, 'iac', 'No se pudo leer el resultado de Checkov', durationMs)
    }
  }

  // ────────────────────────────────────────────────────────────────────────────
  // Presentación de resultados
  // ────────────────────────────────────────────────────────────────────────────

  private displayScanSummary(results: ScanResult[], totalDurationMs: number): void {
    this.log('\n' + chalk.cyan('Resumen de escaneos de seguridad') + '\n')

    const table = new Table({
      head: [
        chalk.white('Escáner'),
        chalk.red('Crítico'),
        chalk.redBright('Alto'),
        chalk.yellow('Medio'),
        chalk.green('Bajo'),
        chalk.gray('Total'),
        chalk.gray('Duración'),
        chalk.white('Estado'),
      ],
      style: {
        head: [],
        border: ['gray'],
      },
    })

    for (const r of results) {
      const statusCell = r.error
        ? chalk.yellow(`Aviso: ${r.error.split(':')[0]}`)
        : r.total === 0
          ? chalk.green('Sin hallazgos')
          : chalk.yellow(`${r.total} hallazgo(s)`)

      table.push([
        chalk.white(r.scanner),
        this.colorCount(r.critical, 'critical'),
        this.colorCount(r.high, 'high'),
        this.colorCount(r.medium, 'medium'),
        this.colorCount(r.low, 'low'),
        chalk.gray(r.total.toString()),
        chalk.gray(`${(r.durationMs / 1000).toFixed(1)}s`),
        statusCell,
      ])
    }

    this.log(table.toString())

    const totals = this.sumTotals(results)
    this.log('')
    this.log(
      chalk.gray('Total — ') +
      chalk.red(`Crítico: ${totals.critical}`) +
      chalk.gray(' | ') +
      chalk.redBright(`Alto: ${totals.high}`) +
      chalk.gray(' | ') +
      chalk.yellow(`Medio: ${totals.medium}`) +
      chalk.gray(' | ') +
      chalk.green(`Bajo: ${totals.low}`),
    )
    this.log(chalk.gray(`Tiempo total: ${(totalDurationMs / 1000).toFixed(1)}s`))
  }

  // ────────────────────────────────────────────────────────────────────────────
  // Utilidades
  // ────────────────────────────────────────────────────────────────────────────

  private async isToolAvailable(cmd: string): Promise<boolean> {
    try {
      await execa(cmd, ['--version'], {reject: false, timeout: 5000})
      return true
    } catch (error) {
      // ENOENT = binario no encontrado
      return (error as NodeJS.ErrnoException).code !== 'ENOENT'
        ? true  // herramienta existe pero --version falló (raro pero válido)
        : false
    }
  }

  private errorResult(scanner: string, type: string, error: string, durationMs: number): ScanResult {
    return {scanner, type, critical: 0, high: 0, medium: 0, low: 0, total: 0, findings: [], durationMs, success: false, error}
  }

  private sumTotals(results: ScanResult[]) {
    return results.reduce(
      (acc, r) => ({
        critical: acc.critical + r.critical,
        high: acc.high + r.high,
        medium: acc.medium + r.medium,
        low: acc.low + r.low,
      }),
      {critical: 0, high: 0, medium: 0, low: 0},
    )
  }

  private exceedsThreshold(totals: {critical: number; high: number; medium: number; low: number}, threshold: string): boolean {
    switch (threshold) {
      case 'critical': return totals.critical > 0
      case 'high':     return totals.critical > 0 || totals.high > 0
      case 'medium':   return totals.critical > 0 || totals.high > 0 || totals.medium > 0
      case 'low':      return totals.critical + totals.high + totals.medium + totals.low > 0
      default:         return false
    }
  }

  private colorCount(n: number, level: 'critical' | 'high' | 'medium' | 'low'): string {
    if (n === 0) return chalk.gray('0')
    switch (level) {
      case 'critical': return chalk.bgRed.white(` ${n} `)
      case 'high':     return chalk.red(n.toString())
      case 'medium':   return chalk.yellow(n.toString())
      case 'low':      return chalk.green(n.toString())
    }
  }

  private mapSemgrepSeverity(s?: string): Severity {
    switch (s?.toUpperCase()) {
      case 'ERROR':    return 'CRITICAL'
      case 'WARNING':  return 'HIGH'
      case 'INFO':     return 'MEDIUM'
      default:         return 'LOW'
    }
  }

  private mapCvssScore(score: number): Severity {
    if (score >= 9.0) return 'CRITICAL'
    if (score >= 7.0) return 'HIGH'
    if (score >= 4.0) return 'MEDIUM'
    return 'LOW'
  }
}
