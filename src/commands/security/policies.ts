import {Flags} from '@oclif/core'
import {execa} from 'execa'
import {existsSync, mkdirSync, readFileSync, writeFileSync} from 'node:fs'
import {join} from 'node:path'
import chalk from 'chalk'
import {BaseCommand} from '../../lib/base-command.js'

interface PolicyViolation {
  policy: string
  rule: string
  resource: string
  message: string
  severity: 'error' | 'warning'
}

interface KyvernoReport {
  items?: Array<{
    metadata?: {name: string}
    results?: Array<{
      policy: string
      rule: string
      scored: boolean
      result: 'pass' | 'fail' | 'warn'
      message: string
      resources?: Array<{name: string; kind: string; namespace: string}>
    }>
  }>
}

/**
 * SecurityPolicies — Evalúa policies de seguridad usando Kyverno y/o OPA Conftest.
 *
 * Lee policies desde:
 *   1. Directorio local --policies-dir (por defecto .osdo/policies/)
 *   2. Kyverno en cluster (si hay kubeconfig disponible)
 *
 * Resultados guardados en: .osdo/results/security/policies.json
 */
export default class SecurityPolicies extends BaseCommand {
  static description = 'Evaluar policies de seguridad con Kyverno y OPA Conftest'

  static examples = [
    '<%= config.bin %> security policies',
    '<%= config.bin %> security policies --engine kyverno --namespace production',
    '<%= config.bin %> security policies --engine conftest --policies-dir ./opa',
    '<%= config.bin %> security policies --target k8s/deployment.yaml',
  ]

  static flags = {
    ...BaseCommand.globalFlags,
    engine: Flags.string({
      char: 'e',
      default: 'auto',
      options: ['auto', 'kyverno', 'conftest'],
      description: 'Motor de evaluación de policies',
    }),
    'policies-dir': Flags.string({
      description: 'Directorio con archivos de policy (.yaml para Kyverno, .rego para OPA)',
      default: '.osdo/policies',
    }),
    target: Flags.string({
      char: 't',
      description: 'Manifiesto o directorio Kubernetes a evaluar (solo Conftest)',
    }),
    namespace: Flags.string({
      char: 'n',
      description: 'Namespace de Kubernetes a auditar (solo Kyverno en-cluster)',
    }),
    'fail-on-violation': Flags.boolean({
      default: true,
      description: 'Retornar código de error si existen violations (score:error)',
      allowNo: true,
    }),
  }

  async run(): Promise<void> {
    const {flags} = await this.parse(SecurityPolicies)
    const resultsDir = join(process.cwd(), '.osdo', 'results', 'security')
    mkdirSync(resultsDir, {recursive: true})

    this.log(chalk.bold('\nOSDO Security Policy Enforcement'))
    this.log('═'.repeat(45) + '\n')

    const violations: PolicyViolation[] = []

    const engine = flags.engine === 'auto'
      ? await this.detectEngine()
      : flags.engine

    if (engine === 'conftest' || flags.engine === 'conftest') {
      await this.runConftest(flags.target ?? '.', flags['policies-dir'], resultsDir, violations)
    } else if (engine === 'kyverno') {
      await this.runKyverno(flags.namespace, resultsDir, violations)
    } else {
      this.warn('No se detectó Kyverno ni Conftest instalados. Instala uno de ellos para continuar.')
      return
    }

    // Guardar resultados consolidados
    const reportPath = join(resultsDir, 'policies.json')
    writeFileSync(reportPath, JSON.stringify(violations, null, 2))

    // Salida JSON
    if (flags.output === 'json') {
      this.log(JSON.stringify(violations, null, 2))
      return
    }

    // Resumen
    const errors = violations.filter(v => v.severity === 'error').length
    const warnings = violations.filter(v => v.severity === 'warning').length

    this.log(`\nViolaciones encontradas: ${violations.length}`)
    this.log(`  ${chalk.red(`Errores:    ${errors}`)}`)
    this.log(`  ${chalk.yellow(`Avisos:     ${warnings}`)}`)

    if (violations.length > 0 && this.configManager.isVerbose()) {
      this.log('\nDetalle:')
      for (const v of violations) {
        const color = v.severity === 'error' ? chalk.red : chalk.yellow
        this.log(`  ${color(`[${v.severity.toUpperCase()}]`)} ${v.policy}/${v.rule} — ${v.resource}`)
        this.log(`    ${v.message}`)
      }
    }

    if (flags['fail-on-violation'] && errors > 0) {
      this.error(
        `Policy enforcement fallido: ${errors} violation(s). Ver ${reportPath}`,
        {exit: 3},
      )
    }

    this.log(chalk.green('\n✓ Evaluación de policies completada.'))
  }

  private async detectEngine(): Promise<string | null> {
    for (const tool of ['kyverno', 'conftest']) {
      try {
        await execa(tool, ['version'], {reject: false})
        return tool
      } catch {
        // not found
      }
    }
    return null
  }

  private async runKyverno(
    namespace: string | undefined,
    resultsDir: string,
    violations: PolicyViolation[],
  ): Promise<void> {
    this.log('Ejecutando Kyverno (audit mode)...')
    const outputPath = join(resultsDir, 'kyverno-raw.json')

    try {
      const args = ['get', 'polr', '--output', 'json', '-A']
      if (namespace) args.push('-n', namespace)

      const {stdout} = await execa('kubectl', args)
      writeFileSync(outputPath, stdout)

      const report: KyvernoReport = JSON.parse(stdout)
      const prevCount = violations.length

      for (const item of report.items ?? []) {
        for (const result of item.results ?? []) {
          if (result.result !== 'fail' && result.result !== 'warn') continue
          for (const resource of result.resources ?? []) {
            violations.push({
              policy: result.policy,
              rule: result.rule,
              resource: `${resource.kind}/${resource.namespace}/${resource.name}`,
              message: result.message,
              severity: result.result === 'fail' ? 'error' : 'warning',
            })
          }
        }
      }

      this.log(`  ✓ Kyverno: ${violations.length - prevCount} violation(s)`)
    } catch (err: unknown) {
      const msg = err instanceof Error ? err.message : String(err)
      if (msg.includes('not found')) {
        this.warn('kubectl o kyverno no disponible. Instala: https://kyverno.io/docs/installation/')
      } else {
        this.warn(`Kyverno: ${msg}`)
      }
    }
  }

  private async runConftest(
    target: string,
    policiesDir: string,
    resultsDir: string,
    violations: PolicyViolation[],
  ): Promise<void> {
    this.log('Ejecutando Conftest (OPA)...')
    const outputPath = join(resultsDir, 'conftest-raw.json')

    if (!existsSync(policiesDir)) {
      this.warn(`Directorio de policies no encontrado: ${policiesDir}. Crea archivos .rego para continuar.`)
      return
    }

    try {
      const {stdout} = await execa('conftest', [
        'test',
        '--policy', policiesDir,
        '--output', 'json',
        target,
      ], {reject: false})

      writeFileSync(outputPath, stdout)

      const results = JSON.parse(stdout) as Array<{
        filename: string
        failures?: Array<{msg: string}>
        warnings?: Array<{msg: string}>
      }>

      const prevCount = violations.length
      for (const r of results) {
        for (const f of r.failures ?? []) {
          violations.push({
            policy: 'conftest',
            rule: 'policy',
            resource: r.filename,
            message: f.msg,
            severity: 'error',
          })
        }
        for (const w of r.warnings ?? []) {
          violations.push({
            policy: 'conftest',
            rule: 'policy',
            resource: r.filename,
            message: w.msg,
            severity: 'warning',
          })
        }
      }

      this.log(`  ✓ Conftest: ${violations.length - prevCount} violation(s)`)
    } catch {
      this.warn('Conftest no encontrado. Instala con: brew install conftest')
    }
  }
}
