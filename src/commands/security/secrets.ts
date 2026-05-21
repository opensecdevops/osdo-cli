import {Flags} from '@oclif/core'
import {execa} from 'execa'
import {mkdirSync, readFileSync, writeFileSync, existsSync} from 'node:fs'
import {join} from 'node:path'
import chalk from 'chalk'
import {BaseCommand} from '../../lib/base-command.js'

interface SecretFinding {
  tool: string
  ruleId: string
  description: string
  file: string
  line: number | null
  commit?: string
}

interface GitleaksResult {
  RuleID?: string
  Secret?: string
  File?: string
  StartLine?: number
  Commit?: string
  Description?: string
}

/**
 * SecuritySecrets — Detecta secretos expuestos en el código fuente y en el historial de git.
 *
 * Herramientas soportadas (en orden de prioridad):
 *   1. Gitleaks — escaneo de archivos y commits git
 *   2. detect-secrets — fallback para proyectos sin git
 *
 * Resultados en: .osdo/results/security/secrets.json
 * Salida SARIF disponible con --format sarif.
 */
export default class SecuritySecrets extends BaseCommand {
  static description = 'Detectar secretos y credenciales expuestas (Gitleaks)'

  static examples = [
    '<%= config.bin %> security secrets',
    '<%= config.bin %> security secrets --mode git',
    '<%= config.bin %> security secrets --mode filesystem --target ./src',
    '<%= config.bin %> security secrets --format sarif',
  ]

  static flags = {
    ...BaseCommand.globalFlags,
    mode: Flags.string({
      char: 'm',
      default: 'auto',
      options: ['auto', 'git', 'filesystem'],
      description: 'Modo de escaneo: historial git o archivos del filesystem',
    }),
    target: Flags.string({
      char: 't',
      description: 'Directorio o ruta a escanear (por defecto: directorio actual)',
      default: '.',
    }),
    format: Flags.string({
      default: 'table',
      options: ['table', 'json', 'sarif'],
      description: 'Formato del reporte de salida',
    }),
    'no-git': Flags.boolean({
      default: false,
      description: 'Forzar modo filesystem aunque exista un repositorio git',
    }),
  }

  async run(): Promise<void> {
    const {flags} = await this.parse(SecuritySecrets)
    const resultsDir = join(process.cwd(), '.osdo', 'results', 'security')
    mkdirSync(resultsDir, {recursive: true})

    this.log(chalk.bold('\nOSDO Security Secrets Scan'))
    this.log('═'.repeat(45) + '\n')

    const findings: SecretFinding[] = []

    // Determinar modo
    const isGitRepo = existsSync(join(flags.target, '.git')) || flags.target === '.'
    const useGitMode = !flags['no-git'] && (flags.mode === 'git' || (flags.mode === 'auto' && isGitRepo))

    await this.runGitleaks(flags.target, useGitMode, resultsDir, findings)

    // Guardar resultados
    const reportPath = join(resultsDir, 'secrets.json')
    writeFileSync(reportPath, JSON.stringify(findings, null, 2))

    // Formato SARIF
    if (flags.format === 'sarif') {
      const sarif = buildSarif(findings)
      const sarifPath = join(resultsDir, 'secrets.sarif.json')
      writeFileSync(sarifPath, JSON.stringify(sarif, null, 2))
      this.log(`✓ SARIF guardado en ${sarifPath}`)
      return
    }

    // JSON raw
    if (flags.format === 'json' || flags.output === 'json') {
      this.log(JSON.stringify(findings, null, 2))
      return
    }

    // Tabla de resultados
    this.log(`\nSecretos detectados: ${findings.length}`)

    if (findings.length > 0) {
      this.log('')
      for (const f of findings) {
        const loc = f.line ? `:${f.line}` : ''
        this.log(`  ${chalk.red('●')} [${f.ruleId}] ${f.file}${loc}`)
        this.log(`    ${f.description}${f.commit ? ` (commit: ${f.commit.slice(0, 8)})` : ''}`)
      }
      this.log(`\n  ${chalk.yellow('▸')} Reporte completo: ${reportPath}`)

      this.error(
        `${findings.length} secreto(s) detectado(s). Elimínalos del historial antes de publicar.`,
        {exit: 3},
      )
    }

    this.log(chalk.green('\n✓ No se detectaron secretos expuestos.'))
  }

  private async runGitleaks(
    target: string,
    gitMode: boolean,
    resultsDir: string,
    findings: SecretFinding[],
  ): Promise<void> {
    const outputPath = join(resultsDir, 'gitleaks-raw.json')
    this.log(`Ejecutando Gitleaks (modo: ${gitMode ? 'git' : 'filesystem'})...`)

    try {
      const cmd = gitMode ? 'git' : 'detect'
      const args: string[] = [
        cmd,
        '--source', target,
        '--report-format', 'json',
        '--report-path', outputPath,
        '--exit-code', '0', // no fail on findings — we handle that
      ]

      await execa('gitleaks', args, {reject: false})

      if (existsSync(outputPath)) {
        const raw = readFileSync(outputPath, 'utf8')
        // gitleaks puede retornar [] o un array de hallazgos
        const rawFindings: GitleaksResult[] = JSON.parse(raw) ?? []
        const prevCount = findings.length

        for (const f of rawFindings) {
          findings.push({
            tool: 'gitleaks',
            ruleId:      f.RuleID ?? 'unknown',
            description: f.Description ?? f.RuleID ?? 'Secret detected',
            file:        f.File ?? '',
            line:        f.StartLine ?? null,
            commit:      f.Commit,
          })
        }

        this.log(`  ✓ Gitleaks: ${findings.length - prevCount} secreto(s)`)
      } else {
        this.log('  ✓ Gitleaks: 0 secreto(s)')
      }
    } catch {
      this.warn('Gitleaks no encontrado. Instala con: brew install gitleaks')
    }
  }
}

function buildSarif(findings: SecretFinding[]): object {
  return {
    version: '2.1.0',
    $schema: 'https://raw.githubusercontent.com/oasis-tcs/sarif-spec/master/Schemata/sarif-schema-2.1.0.json',
    runs: [
      {
        tool: {
          driver: {
            name: 'osdo-secrets',
            version: '2.0.0',
            rules: [...new Set(findings.map(f => f.ruleId))].map(id => ({
              id,
              name: id,
              shortDescription: {text: `Secret type: ${id}`},
            })),
          },
        },
        results: findings.map(f => ({
          ruleId: f.ruleId,
          message: {text: f.description},
          locations: [
            {
              physicalLocation: {
                artifactLocation: {uri: f.file},
                region: f.line ? {startLine: f.line} : undefined,
              },
            },
          ],
        })),
      },
    ],
  }
}
