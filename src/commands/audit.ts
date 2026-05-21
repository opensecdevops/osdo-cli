import {Flags} from '@oclif/core'
import {existsSync, mkdirSync, writeFileSync} from 'node:fs'
import {dirname, join} from 'node:path'
import chalk from 'chalk'
import {BaseCommand} from '../lib/base-command.js'
import {loadWorkflowsFromDir, parseWorkflowContents, evaluateCoverage} from '../lib/audit/workflow-parser.js'
import type {WorkflowAuditResult} from '../lib/audit/workflow-parser.js'
import {GitHubFetcher} from '../lib/audit/github-fetcher.js'
import {GitLabFetcher} from '../lib/audit/gitlab-fetcher.js'
import {loadGitLabPipelinesFromDir, parseGitLabPipelineContents, evaluateGitLabCoverage} from '../lib/audit/gitlab-parser.js'
import {scoreToLevel, MAX_SCORE} from '../lib/audit/baseline.js'
import {renderTable, renderMarkdown, renderJson, renderHtml} from '../lib/audit/reporter.js'

/**
 * Audit — Audita los workflows de GitHub de un repositorio u organización
 * y determina qué controles DevSecOps faltan para cumplir con OSDO.
 *
 * Fuentes de datos (mutuamente excluyentes, en orden de prioridad):
 *   1. --repo owner/repo   → GitHub API: un repo específico
 *   2. --org nombre        → GitHub API: todos los repos de la org
 *   3. --path ./dir        → Archivos locales (defecto: .github/workflows/)
 *
 * Formatos de salida:
 *   table (defecto) · markdown · html · json
 *
 * Niveles de madurez OSDO:
 *   0 Sin DevSecOps | 1 Inicial | 2 Básico | 3 Establecido | 4 Avanzado | 5 Completo
 */
export default class Audit extends BaseCommand {
  static description = 'Auditar pipelines CI/CD y detectar gaps de seguridad respecto al baseline OSDO'

  static examples = [
    '<%= config.bin %> audit',
    '<%= config.bin %> audit --repo acme/backend --token $GITHUB_TOKEN',
    '<%= config.bin %> audit --org acme --format markdown --output-file audit-devsecops.md',
    '<%= config.bin %> audit --path .github/workflows --format html --output-file reporte.html',
    '<%= config.bin %> audit --repo acme/api --format json',
    '<%= config.bin %> audit --org acme --level esencial --fail-on-gap',
    '<%= config.bin %> audit --platform gitlab --gitlab-project acme/backend --token $GITLAB_TOKEN',
    '<%= config.bin %> audit --platform gitlab --gitlab-group acme --token $GITLAB_TOKEN --format markdown',
    '<%= config.bin %> audit --platform gitlab --path . --format table',
  ]

  static flags = {
    ...BaseCommand.globalFlags,

    // ── Plataforma ────────────────────────────────────────────────────────────
    platform: Flags.string({
      default: 'github',
      options: ['github', 'gitlab'],
      description: 'Plataforma CI/CD a auditar',
    }),

    // ── Fuentes GitHub ────────────────────────────────────────────────────────
    repo: Flags.string({
      char: 'r',
      description: 'Repositorio GitHub a auditar (formato: owner/repo)',
      helpValue: 'owner/repo',
    }),
    org: Flags.string({
      description: 'Organización GitHub: audita todos sus repositorios',
      helpValue: 'mi-empresa',
    }),

    // ── Fuentes GitLab ────────────────────────────────────────────────────────
    'gitlab-project': Flags.string({
      description: 'Proyecto GitLab a auditar (formato: group/project o ID numérico)',
      helpValue: 'group/project',
    }),
    'gitlab-group': Flags.string({
      description: 'Grupo GitLab: audita todos sus proyectos (equivalente a --org en GitHub)',
      helpValue: 'mi-grupo',
    }),
    'gitlab-url': Flags.string({
      description: 'URL base de GitLab (para instancias self-hosted)',
      default: 'https://gitlab.com',
      env: 'GITLAB_URL',
    }),

    // ── Ruta local (GitHub y GitLab) ──────────────────────────────────────────
    path: Flags.string({
      char: 'p',
      description: 'Ruta local al directorio de workflows/pipelines',
      default: '.github/workflows',
    }),

    // ── Autenticación ─────────────────────────────────────────────────────────
    token: Flags.string({
      char: 't',
      description: 'Personal Access Token (GITHUB_TOKEN o GITLAB_TOKEN según plataforma)',
      env: 'GITHUB_TOKEN',
    }),
    'github-url': Flags.string({
      description: 'URL base de la API de GitHub (para GitHub Enterprise)',
      default: 'https://api.github.com',
      env: 'GITHUB_API_URL',
    }),

    // ── Salida ────────────────────────────────────────────────────────────────
    format: Flags.string({
      char: 'f',
      default: 'table',
      options: ['table', 'markdown', 'html', 'json'],
      description: 'Formato del reporte de salida',
    }),
    'output-file': Flags.string({
      char: 'O',
      description: 'Guardar el reporte en un archivo',
    }),

    // ── Filtros ────────────────────────────────────────────────────────────────
    level: Flags.string({
      char: 'l',
      default: 'completo',
      options: ['esencial', 'recomendado', 'completo'],
      description: 'Nivel de controles a evaluar (esencial|recomendado|completo)',
    }),
    'include-archived': Flags.boolean({
      default: false,
      description: 'Incluir repos archivados (solo con --org)',
    }),

    // ── Modo CI ────────────────────────────────────────────────────────────────
    'fail-on-gap': Flags.boolean({
      default: false,
      description: 'Retornar código de error (exit 3) si hay gaps en el nivel indicado',
    }),
    'min-score': Flags.integer({
      description: `Puntuación mínima requerida (0-${MAX_SCORE}). Falla si el score es menor`,
    }),
  }

  async run(): Promise<void> {
    const {flags} = await this.parse(Audit)
    const date = new Date().toISOString().split('T')[0]

    // ── PLATAFORMA GITLAB ─────────────────────────────────────────────────────
    if (flags.platform === 'gitlab') {
      await this.runGitLabAudit(flags, date)
      return
    }

    // ── PLATAFORMA GITHUB (default) ───────────────────────────────────────────
    if ((flags.repo || flags.org) && !flags.token) {
      this.warn(
        'Sin --token GitHub: las solicitudes anónimas tienen límite de 60/hora.\n' +
        '  Establece GITHUB_TOKEN o usa --token para aumentar el límite.',
      )
    }

    // ── MODO ORG ──────────────────────────────────────────────────────────────
    if (flags.org) {
      await this.runOrgAudit({...flags, org: flags.org}, date)
      return
    }

    // ── MODO REPO o LOCAL ─────────────────────────────────────────────────────
    let target: string
    let workflows: ReturnType<typeof parseWorkflowContents>

    if (flags.repo) {
      const [owner, repo] = flags.repo.split('/')
      if (!owner || !repo) {
        this.error('Formato de repo inválido. Usa: owner/repo', {exit: 1})
      }

      this.log(chalk.dim(`Cargando workflows desde GitHub: ${flags.repo}...`))
      const fetcher = new GitHubFetcher(flags['github-url'], flags.token)

      try {
        const files = await fetcher.fetchWorkflowsFromRepo(owner, repo)
        if (files.length === 0) {
          this.warn(`No se encontraron workflows en ${flags.repo}/.github/workflows/`)
        }
        workflows = parseWorkflowContents(files)
        target = flags.repo
      } catch (err: unknown) {
        const msg = err instanceof Error ? err.message : String(err)
        if (msg.includes('401') || msg.includes('403')) {
          this.error(`Token inválido o sin permisos para acceder a ${flags.repo}`, {exit: 1})
        }
        this.error(`Error al conectar con GitHub: ${msg}`, {exit: 1})
      }
    } else {
      // Local
      const workflowsDir = join(process.cwd(), flags.path)
      if (!existsSync(workflowsDir)) {
        this.warn(`Directorio no encontrado: ${workflowsDir}`)
        this.log(`  Crea workflows en ${workflowsDir} o indica la ruta con --path`)
        workflows = []
      } else {
        workflows = loadWorkflowsFromDir(workflowsDir)
      }
      target = flags.path
    }

    // Evaluar cobertura
    const result = evaluateCoverage(workflows)

    // Filtrar controles según nivel solicitado
    if (flags.level !== 'completo') {
      const keep = new Set(flags.level === 'esencial' ? ['esencial'] : ['esencial', 'recomendado'])
      result.coverage = result.coverage.filter(c => keep.has(c.control.level))
    }

    // Generar y mostrar/guardar reporte
    const reportContent = this.buildReport(result, target, date, flags.format)
    this.outputReport(reportContent, flags.format, flags['output-file'], target)

    // ── CI: fail-on-gap / min-score ───────────────────────────────────────────
    const essentialGaps = result.coverage.filter(c => !c.covered && c.control.level === 'esencial')
    const {score} = result
    const {level, label} = scoreToLevel(score)

    if (flags['min-score'] !== undefined && score < flags['min-score']) {
      this.error(
        `Puntuación insuficiente: ${score}/${MAX_SCORE} < ${flags['min-score']} requerida.\n` +
        `  Nivel actual: Nivel ${level} — ${label}`,
        {exit: 3},
      )
    }

    if (flags['fail-on-gap'] && essentialGaps.length > 0) {
      this.error(
        `${essentialGaps.length} gap(s) en controles Esenciales: ${essentialGaps.map(c => c.control.name).join(', ')}`,
        {exit: 3},
      )
    }
  }

  // ── Auditoría de organización completa ─────────────────────────────────────

  private async runOrgAudit(
    flags: {
      org: string
      token?: string
      'github-url': string
      'include-archived': boolean
      format: string
      'output-file'?: string
      level: string
      'fail-on-gap': boolean
      'min-score'?: number
    },
    date: string,
  ): Promise<void> {
    const {org} = flags
    this.log(chalk.bold(`\nAuditoría de organización: ${org}\n`))

    const fetcher = new GitHubFetcher(flags['github-url'], flags.token)
    const repos = await fetcher.listOrgRepos(org, flags['include-archived'])
    this.log(chalk.dim(`  ${repos.length} repositorio(s) encontrado(s)\n`))

    const orgResults: Array<{
      repo: string
      score: number
      level: number
      label: string
      essentialGaps: number
    }> = []
    let totalScore = 0

    for (const [i, repo] of repos.entries()) {
      const [owner, name] = repo.full_name.split('/')
      process.stdout.write(`\r  [${i + 1}/${repos.length}] ${repo.full_name.padEnd(50)}`)

      try {
        const files = await fetcher.fetchWorkflowsFromRepo(owner, name)
        const workflows = parseWorkflowContents(files)
        const result = evaluateCoverage(workflows)
        const {level, label} = scoreToLevel(result.score)
        const essentialGaps = result.coverage.filter(
          c => !c.covered && c.control.level === 'esencial',
        ).length
        orgResults.push({repo: repo.full_name, score: result.score, level, label, essentialGaps})
        totalScore += result.score
      } catch {
        orgResults.push({repo: repo.full_name, score: 0, level: 0, label: 'Error', essentialGaps: 3})
      }
    }

    process.stdout.write('\n\n')

    orgResults.sort((a, b) => a.score - b.score)

    const avgScore = repos.length > 0 ? Math.round(totalScore / repos.length) : 0
    const {level: avgLevel, label: avgLabel, emoji} = scoreToLevel(avgScore)
    const criticalRepos = orgResults.filter(r => r.essentialGaps > 0)

    this.log(chalk.bold(`Resultado consolidado: ${emoji} ${org}`))
    this.log('═'.repeat(65))
    this.log(`  Score promedio:           ${chalk.bold(`${avgScore}/${MAX_SCORE}`)} pts`)
    this.log(`  Nivel:                    Nivel ${avgLevel} — ${avgLabel}`)
    this.log(`  Repositorios auditados:   ${repos.length}`)
    this.log(`  Con gaps críticos:        ${chalk.red(String(criticalRepos.length))}`)
    this.log('')

    this.log(chalk.bold('Repositorios (peor → mejor):'))
    this.log('─'.repeat(65))

    for (const r of orgResults) {
      const barFill = Math.round((r.score / MAX_SCORE) * 20)
      const bar = chalk.green('█'.repeat(barFill)) + chalk.gray('░'.repeat(20 - barFill))
      const gapTag = r.essentialGaps > 0 ? chalk.red(` [${r.essentialGaps} gaps esenciales]`) : ''
      const scoreColor = r.score >= 70 ? chalk.green : r.score >= 50 ? chalk.yellow : chalk.red
      this.log(`  ${r.repo.padEnd(38)} ${bar}  ${scoreColor(String(r.score).padStart(3))}/${MAX_SCORE}${gapTag}`)
    }

    this.log('')

    if (flags['output-file'] || flags.format !== 'table') {
      const content = buildOrgMarkdown(orgResults, org, avgScore, avgLevel, avgLabel, date)
      const filePath = flags['output-file'] ?? `osdo-audit-${org}-${date}.md`
      writeFileSync(filePath, content, 'utf8')
      this.log(chalk.green(`✓ Reporte guardado en: ${filePath}`))
    }

    if (flags['min-score'] !== undefined && avgScore < flags['min-score']) {
      this.error(`Score promedio ${avgScore} < ${flags['min-score']} requerido`, {exit: 3})
    }

    if (flags['fail-on-gap'] && criticalRepos.length > 0) {
      this.error(
        `${criticalRepos.length} repositorio(s) con gaps en controles Esenciales`,
        {exit: 3},
      )
    }
  }

  // ── Auditoría GitLab ────────────────────────────────────────────────────────

  private async runGitLabAudit(
    flags: {
      'gitlab-project'?: string
      'gitlab-group'?: string
      'gitlab-url': string
      token?: string
      path: string
      format: string
      'output-file'?: string
      level: string
      'include-archived': boolean
      'fail-on-gap': boolean
      'min-score'?: number
    },
    date: string,
  ): Promise<void> {
    const {['gitlab-project']: project, ['gitlab-group']: group} = flags

    // ── Grupo GitLab ──────────────────────────────────────────────────────────
    if (group) {
      const fetcher = new GitLabFetcher(flags['gitlab-url'], flags.token)
      this.log(chalk.bold(`\nAuditoría de grupo GitLab: ${group}\n`))

      const filesMap = await fetcher.fetchCiFilesFromGroup(group, {
        includeArchived: flags['include-archived'],
        onProgress: (done, total, proj) => {
          process.stdout.write(`\r  [${done + 1}/${total}] ${proj.padEnd(50)}`)
        },
      })
      process.stdout.write('\n\n')

      const groupResults: Array<{
        project: string
        score: number
        level: number
        label: string
        essentialGaps: number
      }> = []
      let totalScore = 0

      for (const [projPath, files] of filesMap.entries()) {
        const pipelines = parseGitLabPipelineContents(files)
        const result = evaluateGitLabCoverage(pipelines)
        const {level, label} = scoreToLevel(result.score)
        const essentialGaps = result.coverage.filter(c => !c.covered && c.control.level === 'esencial').length
        groupResults.push({project: projPath, score: result.score, level, label, essentialGaps})
        totalScore += result.score
      }

      groupResults.sort((a, b) => a.score - b.score)

      const avgScore = groupResults.length > 0 ? Math.round(totalScore / groupResults.length) : 0
      const {level: avgLevel, label: avgLabel, emoji} = scoreToLevel(avgScore)
      const criticalProjects = groupResults.filter(r => r.essentialGaps > 0)

      this.log(chalk.bold(`Resultado consolidado: ${emoji} ${group}`))
      this.log('═'.repeat(65))
      this.log(`  Score promedio:          ${chalk.bold(`${avgScore}/${MAX_SCORE}`)} pts`)
      this.log(`  Nivel:                   Nivel ${avgLevel} — ${avgLabel}`)
      this.log(`  Proyectos auditados:     ${groupResults.length}`)
      this.log(`  Con gaps críticos:       ${chalk.red(String(criticalProjects.length))}`)
      this.log('')
      this.log(chalk.bold('Proyectos (peor → mejor):'))
      this.log('─'.repeat(65))

      for (const r of groupResults) {
        const barFill = Math.round((r.score / MAX_SCORE) * 20)
        const bar = chalk.green('█'.repeat(barFill)) + chalk.gray('░'.repeat(20 - barFill))
        const gapTag = r.essentialGaps > 0 ? chalk.red(` [${r.essentialGaps} gaps esenciales]`) : ''
        const scoreColor = r.score >= 70 ? chalk.green : r.score >= 50 ? chalk.yellow : chalk.red
        this.log(`  ${r.project.padEnd(38)} ${bar}  ${scoreColor(String(r.score).padStart(3))}/${MAX_SCORE}${gapTag}`)
      }

      this.log('')

      if (flags['min-score'] !== undefined && avgScore < flags['min-score']) {
        this.error(`Score promedio ${avgScore} < ${flags['min-score']} requerido`, {exit: 3})
      }
      if (flags['fail-on-gap'] && criticalProjects.length > 0) {
        this.error(`${criticalProjects.length} proyecto(s) con gaps en controles Esenciales`, {exit: 3})
      }
      return
    }

    // ── Proyecto GitLab individual ─────────────────────────────────────────────
    let result: WorkflowAuditResult
    let target: string

    if (project) {
      this.log(chalk.dim(`Cargando pipeline desde GitLab: ${project}...`))
      const fetcher = new GitLabFetcher(flags['gitlab-url'], flags.token)
      try {
        const files = await fetcher.fetchCiFilesFromProject(project)
        if (files.length === 0) {
          this.warn(`No se encontró .gitlab-ci.yml en ${project}`)
        }
        const pipelines = parseGitLabPipelineContents(files)
        result = evaluateGitLabCoverage(pipelines)
        target = project
      } catch (err: unknown) {
        const msg = err instanceof Error ? err.message : String(err)
        if (msg.includes('401') || msg.includes('403')) {
          this.error(`Token inválido o sin permisos para acceder a ${project}`, {exit: 1})
        }
        this.error(`Error al conectar con GitLab: ${msg}`, {exit: 1})
      }
    } else {
      // Local path
      const localPath = join(process.cwd(), flags.path)
      const searchPath = flags.path === '.github/workflows' ? process.cwd() : localPath
      this.log(chalk.dim(`Cargando pipelines GitLab desde: ${searchPath}`))
      const pipelines = loadGitLabPipelinesFromDir(searchPath)
      if (pipelines.length === 0) {
        this.warn(`No se encontraron archivos .gitlab-ci.yml en ${searchPath}`)
        this.log('  Asegúrate de tener un archivo .gitlab-ci.yml en el directorio')
      }
      result = evaluateGitLabCoverage(pipelines)
      target = searchPath
    }

    // Filtrar controles según nivel
    if (flags.level !== 'completo') {
      const keep = new Set(flags.level === 'esencial' ? ['esencial'] : ['esencial', 'recomendado'])
      result.coverage = result.coverage.filter(c => keep.has(c.control.level))
    }

    const reportContent = this.buildReport(result, target, date, flags.format)
    this.outputReport(reportContent, flags.format, flags['output-file'], target)

    const essentialGaps = result.coverage.filter(c => !c.covered && c.control.level === 'esencial')
    const {score} = result
    const {level, label} = scoreToLevel(score)

    if (flags['min-score'] !== undefined && score < flags['min-score']) {
      this.error(
        `Puntuación insuficiente: ${score}/${MAX_SCORE} < ${flags['min-score']} requerida.\n` +
        `  Nivel actual: Nivel ${level} — ${label}`,
        {exit: 3},
      )
    }

    if (flags['fail-on-gap'] && essentialGaps.length > 0) {
      this.error(
        `${essentialGaps.length} gap(s) en controles Esenciales: ${essentialGaps.map(c => c.control.name).join(', ')}`,
        {exit: 3},
      )
    }
  }

  // ── Helpers ────────────────────────────────────────────────────────────────

  private buildReport(
    result: WorkflowAuditResult,
    target: string,
    date: string,
    format: string,
  ): string {
    switch (format) {
      case 'markdown': return renderMarkdown(result, target, date)
      case 'html':     return renderHtml(result, target, date)
      case 'json':     return JSON.stringify(renderJson(result, target), null, 2)
      default:         return renderTable(result, target)
    }
  }

  private outputReport(
    content: string,
    format: string,
    outputFile: string | undefined,
    target: string,
  ): void {
    if (outputFile) {
      mkdirSync(dirname(outputFile), {recursive: true})
      writeFileSync(outputFile, content, 'utf8')
      if (format !== 'json') {
        this.log(chalk.green(`✓ Reporte guardado en: ${outputFile}`))
      }
      return
    }

    if (format === 'json') {
      this.log(content)
      return
    }

    this.log(content)

    if (format !== 'table') {
      const ext = format === 'html' ? 'html' : 'md'
      const slug = target.replace(/\//g, '-')
      this.log(chalk.dim(`  Guarda con: --output-file osdo-audit-${slug}.${ext}`))
    }
  }
}

// ── Reporte Markdown para organizaciones ──────────────────────────────────────

function buildOrgMarkdown(
  results: Array<{repo: string; score: number; level: number; label: string; essentialGaps: number}>,
  org: string,
  avgScore: number,
  avgLevel: number,
  avgLabel: string,
  date: string,
): string {
  const {emoji} = scoreToLevel(avgScore)
  const criticals = results.filter(r => r.essentialGaps > 0)

  const table = results.map(r => {
    const {emoji: e} = scoreToLevel(r.score)
    const gaps = r.essentialGaps > 0 ? `⚠️ ${r.essentialGaps}` : '✅ 0'
    return `| ${r.repo} | ${r.score}/${MAX_SCORE} | ${e} Nivel ${r.level} — ${r.label} | ${gaps} |`
  }).join('\n')

  return `# Auditoría OSDO — Organización \`${org}\`

**Fecha:** ${date}
**Score promedio:** ${avgScore}/${MAX_SCORE} — ${emoji} Nivel ${avgLevel} — ${avgLabel}
**Repos auditados:** ${results.length} | **Repos con gaps críticos:** ${criticals.length}

---

## 📊 Resumen por Repositorio

| Repositorio | Score | Nivel | Gaps Esenciales |
|-------------|-------|-------|-----------------|
${table}

---

## 🚨 Repositorios con Atención Urgente

${criticals.length === 0
  ? '✅ Todos los repositorios cubren los controles esenciales.'
  : criticals.map(r => `### \`${r.repo}\` — ${r.score}/${MAX_SCORE} pts\n\n${r.essentialGaps} control(es) esencial(es) sin cobertura.\n\n\`\`\`bash\nosdo audit --repo ${r.repo} --format markdown\n\`\`\`\n`).join('\n---\n\n')
}

---

*Generado por OSDO CLI v2 — ${new Date().toISOString()}*
`
}
