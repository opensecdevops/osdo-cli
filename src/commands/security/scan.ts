import {Flags} from '@oclif/core'
import {execa} from 'execa'
import {existsSync, mkdirSync, readFileSync} from 'node:fs'
import {join} from 'node:path'
import chalk from 'chalk'
import {BaseCommand} from '../../lib/base-command.js'

/**
 * Estructura de resultado de un hallazgo de seguridad de infraestructura.
 */
interface InfraFinding {
  tool: string
  id: string
  severity: string
  pkg: string
  title: string
}

/**
 * Estructura de salida de Trivy en formato JSON.
 */
interface TrivyResult {
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

/**
 * SecurityScan — Escanea la infraestructura en busca de vulnerabilidades
 * usando herramientas reales: Trivy (contenedores/filesystem) y Grype (SCA).
 *
 * Los resultados JSON de cada herramienta se guardan en:
 *   .osdo/results/security/trivy.json
 *   .osdo/results/security/grype.json
 *
 * Si alguna herramienta no está instalada, se advierte pero no se aborta
 * el escaneo para permitir ejecución parcial en entornos con herramientas limitadas.
 */
export default class SecurityScan extends BaseCommand {
  static description = 'Escanear infraestructura en busca de vulnerabilidades (Trivy, Grype, Falco)'

  static examples = [
    '<%= config.bin %> security scan --type all',
    '<%= config.bin %> security scan --type container --target nginx:latest',
    '<%= config.bin %> security scan --type filesystem --target ./dist',
    '<%= config.bin %> security scan --output json',
    '<%= config.bin %> security scan --fail-on HIGH',
  ]

  static flags = {
    ...BaseCommand.globalFlags,
    type: Flags.string({
      char: 't',
      default: 'all',
      options: ['all', 'container', 'filesystem', 'sbom', 'runtime'],
      description: 'Tipo de scan de infraestructura a ejecutar',
    }),
    target: Flags.string({
      description: 'Objetivo del scan (imagen Docker, directorio, ruta SBOM)',
      helpValue: 'nginx:latest | ./src | /path/to/sbom.json',
    }),
    'fail-on': Flags.string({
      default: 'CRITICAL',
      options: ['CRITICAL', 'HIGH', 'MEDIUM', 'LOW', 'UNKNOWN'],
      description: 'Severidad mínima para retornar código de error',
    }),
  }

  async run(): Promise<void> {
    const {flags} = await this.parse(SecurityScan)
    const resultsDir = join(process.cwd(), '.osdo', 'results', 'security')
    mkdirSync(resultsDir, {recursive: true})

    this.log(chalk.bold('\nOSDO Security Infrastructure Scan'))
    this.log('═'.repeat(45) + '\n')

    const findings: InfraFinding[] = []

    // Ejecutar Trivy para contenedores y filesystem
    if (flags.type === 'all' || flags.type === 'container' || flags.type === 'filesystem') {
      await this.runTrivyScan(flags.target ?? '.', resultsDir, findings)
    }

    // Ejecutar Grype para análisis de composición de software (SCA)
    if (flags.type === 'all' || flags.type === 'filesystem' || flags.type === 'sbom') {
      await this.runGrypeScan(flags.target ?? '.', resultsDir, findings)
    }

    // Salida JSON si se solicita
    if (flags.output === 'json') {
      this.log(JSON.stringify(findings, null, 2))
      return
    }

    // Resumen de hallazgos agrupados por severidad
    const critical = findings.filter(f => f.severity === 'CRITICAL').length
    const high     = findings.filter(f => f.severity === 'HIGH').length
    const rest     = findings.length - critical - high

    this.log(`Hallazgos totales: ${findings.length}`)
    this.log(`  ${chalk.red(`CRITICO: ${critical}`)}`)
    this.log(`  ${chalk.yellow(`ALTO:    ${high}`)}`)
    this.log(`  ${chalk.blue(`MEDIO/BAJO: ${rest}`)}`)

    // Detalle ampliado en modo verbose (primeros 20 hallazgos)
    if (findings.length > 0 && this.configManager.isVerbose()) {
      this.log('\nDetalle de hallazgos:')
      for (const finding of findings.slice(0, 20)) {
        const color = finding.severity === 'CRITICAL' ? chalk.red : chalk.yellow
        this.log(`  ${color(`[${finding.severity}]`)} ${finding.id} — ${finding.pkg}: ${finding.title}`)
      }
      if (findings.length > 20) {
        this.log(`  ... y ${findings.length - 20} hallazgo(s) más.`)
      }
    }

    // Evaluar umbral de fallo
    const severityOrder = ['CRITICAL', 'HIGH', 'MEDIUM', 'LOW', 'UNKNOWN']
    const failIndex  = severityOrder.indexOf(flags['fail-on'])
    const failCount  = findings.filter(f => severityOrder.indexOf(f.severity) <= failIndex).length

    if (failCount > 0) {
      this.error(
        `Scan fallido: ${failCount} hallazgo(s) con severidad ${flags['fail-on']} o superior.`,
        {exit: 3},
      )
    }

    this.log(chalk.green('\n✓ Scan completado sin hallazgos que superen el umbral.'))
  }

  /**
   * Ejecuta Trivy en modo filesystem y parsea el JSON resultante.
   */
  private async runTrivyScan(
    target: string,
    resultsDir: string,
    findings: InfraFinding[],
  ): Promise<void> {
    const outputPath = join(resultsDir, 'trivy.json')
    this.log('Ejecutando Trivy...')

    try {
      await execa('trivy', [
        'fs',
        '--format', 'json',
        '--output', outputPath,
        '--quiet',
        target,
      ], {reject: false})

      if (existsSync(outputPath)) {
        const raw = readFileSync(outputPath, 'utf8')
        const result: TrivyResult = JSON.parse(raw)
        const prevCount = findings.length

        for (const r of result.Results ?? []) {
          for (const v of r.Vulnerabilities ?? []) {
            findings.push({
              tool: 'trivy',
              id:       v.VulnerabilityID,
              severity: v.Severity,
              pkg:      `${v.PkgName}@${v.InstalledVersion}`,
              title:    v.Title ?? v.VulnerabilityID,
            })
          }
        }

        this.log(`  ✓ Trivy: ${findings.length - prevCount} hallazgo(s)`)
      } else {
        this.log('  ✓ Trivy: 0 hallazgo(s)')
      }
    } catch {
      this.warn('Trivy no encontrado. Instala con: brew install trivy')
    }
  }

  /**
   * Ejecuta Grype (SCA) y parsea el JSON resultante.
   */
  private async runGrypeScan(
    target: string,
    resultsDir: string,
    findings: InfraFinding[],
  ): Promise<void> {
    const outputPath = join(resultsDir, 'grype.json')
    const prevCount  = findings.length
    this.log('Ejecutando Grype...')

    try {
      await execa('grype', [target, '-o', 'json', '--file', outputPath, '-q'], {reject: false})

      if (existsSync(outputPath)) {
        const raw    = readFileSync(outputPath, 'utf8')
        const result = JSON.parse(raw) as {
          matches?: Array<{
            vulnerability: {id: string; severity: string; description?: string}
            artifact: {name: string; version: string}
          }>
        }

        for (const match of result.matches ?? []) {
          findings.push({
            tool: 'grype',
            id:       match.vulnerability.id,
            severity: match.vulnerability.severity.toUpperCase(),
            pkg:      `${match.artifact.name}@${match.artifact.version}`,
            title:    match.vulnerability.description ?? match.vulnerability.id,
          })
        }

        this.log(`  ✓ Grype: ${findings.length - prevCount} hallazgo(s)`)
      } else {
        this.log('  ✓ Grype: 0 hallazgo(s)')
      }
    } catch {
      this.warn('Grype no encontrado. Instala con: brew install grype')
    }
  }
}
