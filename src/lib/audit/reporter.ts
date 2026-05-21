import chalk from 'chalk'
import type {WorkflowAuditResult, ControlCoverage} from './workflow-parser.js'
import {scoreToLevel, MAX_SCORE} from './baseline.js'

const LEVEL_COLORS: Record<string, (s: string) => string> = {
  esencial:    (s) => chalk.red(s),
  recomendado: (s) => chalk.yellow(s),
  completo:    (s) => chalk.blue(s),
}

const LEVEL_LABELS: Record<string, string> = {
  esencial:    'Esencial',
  recomendado: 'Recomendado',
  completo:    'Completo',
}

// ── Terminal (tabla) ──────────────────────────────────────────────────────────

export function renderTable(result: WorkflowAuditResult, target: string): string {
  const lines: string[] = []
  const {score, coverage, workflowCount} = result
  const {level, label, emoji} = scoreToLevel(score)

  lines.push('')
  lines.push(chalk.bold('OSDO Workflow Audit'))
  if (target) lines.push(chalk.dim(`  Objetivo: ${target}`))
  lines.push(chalk.dim(`  Workflows escaneados: ${workflowCount}`))
  lines.push('═'.repeat(70))
  lines.push('')

  // Tabla de controles
  const colW = [30, 12, 32, 12]
  const header = [
    'Control'.padEnd(colW[0]),
    'Estado'.padEnd(colW[1]),
    'Cobertura'.padEnd(colW[2]),
    'Nivel'.padEnd(colW[3]),
  ].join('  ')
  lines.push(chalk.bold(header))
  lines.push('─'.repeat(header.replace(/\x1b\[[0-9;]*m/g, '').length))

  for (const c of coverage) {
    const status = c.covered
      ? chalk.green('✓ Cubierto')
      : LEVEL_COLORS[c.control.level]('✗ FALTANTE')

    const coveredBy = c.covered
      ? chalk.dim((c.coveredBy ?? '').slice(0, colW[2] - 1))
      : chalk.dim('—')

    const lvlLabel = LEVEL_COLORS[c.control.level](
      LEVEL_LABELS[c.control.level].padEnd(colW[3]),
    )

    lines.push(
      [
        c.control.name.padEnd(colW[0]).slice(0, colW[0]),
        status.padEnd(colW[1] + 10), // +10 for ANSI escapes
        coveredBy,
        lvlLabel,
      ].join('  '),
    )
  }

  lines.push('')

  // Score final
  const bar = buildProgressBar(score, MAX_SCORE, 30)
  lines.push(`Puntuación OSDO:  ${bar}  ${chalk.bold(`${score}/${MAX_SCORE}`)} pts`)
  lines.push(`Nivel de madurez: ${emoji}  ${chalk.bold(`Nivel ${level} — ${label}`)}`)
  lines.push('')

  // Gaps críticos
  const gaps = coverage.filter(c => !c.covered)
  if (gaps.length === 0) {
    lines.push(chalk.green('✓ Cobertura completa — ¡ejercicio DevSecOps excelente!'))
  } else {
    lines.push(chalk.bold(`Gaps detectados: ${gaps.length}`))
    lines.push('')

    // Ordenar por nivel (esencial primero)
    const levelOrder = {esencial: 0, recomendado: 1, completo: 2}
    const sorted = [...gaps].sort(
      (a, b) => levelOrder[a.control.level] - levelOrder[b.control.level],
    )

    for (const [i, c] of sorted.entries()) {
      const tag = LEVEL_COLORS[c.control.level](`[${LEVEL_LABELS[c.control.level].toUpperCase()}]`)
      lines.push(`  ${i + 1}. ${tag} ${chalk.bold(c.control.name)}`)
      lines.push(`     ${c.control.description}`)
      lines.push(`     ${chalk.cyan('Solución:')} ${c.control.recommendation.split('\n')[0]}`)
      lines.push('')
    }
  }

  // Permisos
  const withoutPerms = result.permissionsCoverage.filter(p => !p.hasPermissions)
  if (withoutPerms.length > 0) {
    lines.push(chalk.yellow(`⚠ Workflows sin 'permissions:' declaradas (${withoutPerms.length}):`))
    for (const p of withoutPerms) lines.push(`   - ${p.file}`)
    lines.push('')
  }

  // Pinned
  const unpinnedRepos = result.pinnedActionsReport.filter(r => r.unpinned.length > 0)
  if (unpinnedRepos.length > 0) {
    lines.push(chalk.yellow('⚠ Actions NO fijadas por hash SHA:'))
    for (const r of unpinnedRepos) {
      lines.push(`   ${r.file}: ${r.unpinned.slice(0, 3).join(', ')}${r.unpinned.length > 3 ? ` +${r.unpinned.length - 3} más` : ''}`)
    }
    lines.push('')
  }

  lines.push(chalk.dim(`  Genera reporte completo: osdo audit --format markdown --output-file audit.md`))
  lines.push('')

  return lines.join('\n')
}

// ── Markdown ─────────────────────────────────────────────────────────────────

export function renderMarkdown(result: WorkflowAuditResult, target: string, date: string): string {
  const {score, coverage, workflowCount, pinnedActionsReport} = result
  const {level, label, emoji} = scoreToLevel(score)

  const covered = coverage.filter(c => c.covered)
  const gaps = coverage.filter(c => !c.covered)
  const essentialGaps = gaps.filter(c => c.control.level === 'esencial')

  const controlTable = coverage
    .map(c => {
      const status = c.covered ? '✅ Cubierto' : '❌ Faltante'
      const by = c.covered ? `\`${(c.coveredBy ?? '').slice(0, 45)}\`` : '—'
      const lvl = {esencial: '🔴 Esencial', recomendado: '🟡 Recomendado', completo: '🔵 Completo'}[c.control.level]
      return `| ${c.control.name} | ${status} | ${by} | ${lvl} | ${c.control.points}pts |`
    })
    .join('\n')

  const gapsList = gaps
    .sort((a, b) => {
      const ord = {esencial: 0, recomendado: 1, completo: 2}
      return ord[a.control.level] - ord[b.control.level]
    })
    .map(c => {
      const tag = c.control.level === 'esencial' ? '🔴' : c.control.level === 'recomendado' ? '🟡' : '🔵'
      const recLines = c.control.recommendation.split('\n').map(l => `  > ${l}`).join('\n')
      return `### ${tag} ${c.control.name}\n\n${c.control.description}\n\n**Frameworks:** ${c.control.frameworks.join(', ')}\n\n**Recomendación:**\n${recLines}\n`
    })
    .join('\n---\n\n')

  const unpinnedSection = pinnedActionsReport.some(r => r.unpinned.length > 0)
    ? `## ⚠️ Actions sin fijar por hash SHA\n\n${pinnedActionsReport
        .filter(r => r.unpinned.length > 0)
        .map(r => `**\`${r.file}\`**\n${r.unpinned.map(u => `- \`${u}\``).join('\n')}`)
        .join('\n\n')}\n\n> Fija todas las actions a su hash SHA-1 para evitar ataques de supply chain.\n`
    : ''

  return `# Reporte de Auditoría OSDO — ${target}

**Fecha:** ${date}
**Workflows auditados:** ${workflowCount}
**Puntuación:** ${score}/${MAX_SCORE} pts
**Nivel:** ${emoji} Nivel ${level} — ${label}

---

## 📊 Resumen Ejecutivo

| Métr ica | Valor |
|---------|-------|
| Puntuación OSDO | **${score}/${MAX_SCORE}** |
| Nivel de madurez | **${emoji} Nivel ${level} — ${label}** |
| Controles cubiertos | **${covered.length}/${coverage.length}** |
| Gaps críticos | **${essentialGaps.length}** controles esenciales faltantes |
| Workflows con permissions | **${result.permissionsCoverage.filter(p => p.hasPermissions).length}/${workflowCount}** |

${score < 50 ? `> ⚠️ **Acción inmediata requerida:** ${essentialGaps.length} control(es) esencial(es) sin cobertura. Esto representa un riesgo de seguridad alto.` : score < 70 ? `> 📈 **Progreso:** Los controles esenciales están cubiertos. El siguiente paso es completar los controles Recomendados.` : `> ✅ **Buen trabajo:** La organización supera el baseline OSDO. Continúa hacia el Nivel de madurez Completo.`}

---

## 🔍 Análisis de Controles

| Control | Estado | Cobertura | Nivel | Puntos |
|---------|--------|-----------|-------|--------|
${controlTable}

---

## 🚧 Gaps y Recomendaciones

${gaps.length === 0 ? '✅ **Sin gaps detectados.** Cobertura completa.' : gapsList}

${unpinnedSection}

---

## 📋 Siguiente Paso: Plan de Implementación

\`\`\`bash
# 1. Instalar OSDO CLI
npm install -g @osdo/cli

# 2. Inicializar OSDO en tu repositorio
osdo init

# 3. Generar pipeline de seguridad
osdo pipeline generate --template security

# 4. Ver catálogo de actions disponibles
osdo catalog list
\`\`\`

---

*Generado por [OSDO CLI](https://github.com/opensecdevops) v2 — ${new Date().toISOString()}*
`
}

// ── JSON ──────────────────────────────────────────────────────────────────────

export function renderJson(result: WorkflowAuditResult, target: string): object {
  const {score, coverage} = result
  const {level, label} = scoreToLevel(score)

  return {
    target,
    date: new Date().toISOString(),
    score: {
      total: score,
      max: MAX_SCORE,
      level,
      label,
    },
    summary: {
      total: coverage.length,
      covered: coverage.filter(c => c.covered).length,
      gaps: coverage.filter(c => !c.covered).length,
      essential_gaps: coverage.filter(c => !c.covered && c.control.level === 'esencial').length,
    },
    controls: coverage.map(c => ({
      id: c.control.id,
      name: c.control.name,
      level: c.control.level,
      covered: c.covered,
      covered_by: c.coveredBy,
      is_osdo: c.isOsdo,
      points: c.control.points,
      files: c.files,
      recommendation: c.covered ? null : c.control.recommendation,
    })),
    permissions: result.permissionsCoverage,
    pinned_actions: result.pinnedActionsReport.map(r => ({
      file: r.file,
      ratio: r.ratio,
      unpinned: r.unpinned,
    })),
  }
}

// ── HTML ──────────────────────────────────────────────────────────────────────

export function renderHtml(result: WorkflowAuditResult, target: string, date: string): string {
  const {score, coverage} = result
  const {level, label, emoji} = scoreToLevel(score)
  const gaps = coverage.filter(c => !c.covered)
  const essentialGaps = gaps.filter(c => c.control.level === 'esencial')

  const rows = coverage.map(c => {
    const statusIcon = c.covered ? '✅' : '❌'
    const levelColor = c.control.level === 'esencial' ? '#dc2626' : c.control.level === 'recomendado' ? '#ca8a04' : '#2563eb'
    const covBy = c.covered ? `<code>${(c.coveredBy ?? '').slice(0, 50)}</code>` : '—'
    return `<tr>
      <td>${c.control.name}</td>
      <td>${statusIcon}</td>
      <td>${covBy}</td>
      <td style="color:${levelColor}">${LEVEL_LABELS[c.control.level]}</td>
      <td><strong>${c.control.points}</strong></td>
    </tr>`
  }).join('\n')

  const gapCards = gaps
    .sort((a, b) => ({esencial:0,recomendado:1,completo:2}[a.control.level] - {esencial:0,recomendado:1,completo:2}[b.control.level]))
    .map(c => {
      const borderColor = c.control.level === 'esencial' ? '#dc2626' : c.control.level === 'recomendado' ? '#ca8a04' : '#2563eb'
      const recLines = c.control.recommendation.split('\n').map(l => `<p style="margin:4px 0">${l}</p>`).join('')
      return `<div style="border-left:4px solid ${borderColor};padding:12px 16px;margin:12px 0;background:#fafafa;border-radius:4px">
        <strong>${c.control.name}</strong> <span style="color:${borderColor};font-size:0.8rem">[${LEVEL_LABELS[c.control.level]}]</span>
        <p style="color:#4b5563;margin:8px 0">${c.control.description}</p>
        <p style="margin:4px 0"><em>Frameworks:</em> ${c.control.frameworks.join(', ')}</p>
        <div style="margin-top:8px;font-size:0.875rem">${recLines}</div>
      </div>`
    }).join('\n')

  const scorePercent = Math.round((score / MAX_SCORE) * 100)

  return `<!DOCTYPE html>
<html lang="es">
<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width,initial-scale=1">
  <title>OSDO Audit — ${target}</title>
  <style>
    *{box-sizing:border-box}body{font-family:system-ui,sans-serif;max-width:1100px;margin:40px auto;padding:0 20px;color:#1f2937}
    h1{border-bottom:3px solid #dc2626;padding-bottom:12px}h2{margin-top:32px}
    .cards{display:grid;grid-template-columns:repeat(4,1fr);gap:16px;margin:24px 0}
    .card{border-radius:8px;padding:20px;text-align:center;border:1px solid #e5e7eb}
    .card h3{margin:0 0 8px;font-size:.75rem;text-transform:uppercase;color:#6b7280}
    .card .val{font-size:2rem;font-weight:700}
    .score-bar{background:#e5e7eb;border-radius:4px;height:12px;margin:8px 0;overflow:hidden}
    .score-fill{height:100%;border-radius:4px;background:linear-gradient(90deg,#dc2626,#f97316,#22c55e);transition:width .4s}
    table{width:100%;border-collapse:collapse;margin-top:16px}
    th{background:#f3f4f6;text-align:left;padding:10px 12px;font-size:.8rem;text-transform:uppercase;color:#6b7280}
    td{padding:10px 12px;border-bottom:1px solid #e5e7eb;font-size:.875rem}
    tr:hover{background:#f9fafb}code{background:#f3f4f6;padding:2px 6px;border-radius:4px;font-size:.8rem}
    footer{margin-top:40px;padding-top:20px;border-top:1px solid #e5e7eb;color:#9ca3af;font-size:.75rem;text-align:center}
  </style>
</head>
<body>
  <h1>🔐 OSDO Workflow Audit</h1>
  <p><strong>Objetivo:</strong> ${target} &nbsp;|&nbsp; <strong>Fecha:</strong> ${date} &nbsp;|&nbsp; <strong>Workflows:</strong> ${result.workflowCount}</p>

  <div class="cards">
    <div class="card">
      <h3>Puntuación</h3>
      <div class="val">${score}<span style="font-size:1rem;color:#9ca3af">/${MAX_SCORE}</span></div>
      <div class="score-bar"><div class="score-fill" style="width:${scorePercent}%"></div></div>
    </div>
    <div class="card">
      <h3>Nivel</h3>
      <div class="val">${emoji} ${level}</div>
      <div style="font-size:.875rem;color:#6b7280">${label}</div>
    </div>
    <div class="card">
      <h3>Cubiertos</h3>
      <div class="val" style="color:#22c55e">${coverage.filter(c=>c.covered).length}</div>
      <div style="font-size:.875rem;color:#6b7280">de ${coverage.length} controles</div>
    </div>
    <div class="card" style="border-color:${essentialGaps.length>0?'#dc2626':'#22c55e'}">
      <h3>Gaps Críticos</h3>
      <div class="val" style="color:${essentialGaps.length>0?'#dc2626':'#22c55e'}">${essentialGaps.length}</div>
      <div style="font-size:.875rem;color:#6b7280">esenciales</div>
    </div>
  </div>

  <h2>📋 Controles de Seguridad</h2>
  <table>
    <thead><tr><th>Control</th><th>Estado</th><th>Herramienta Detectada</th><th>Nivel</th><th>Pts</th></tr></thead>
    <tbody>${rows}</tbody>
  </table>

  ${gaps.length > 0 ? `<h2>🚧 Gaps y Recomendaciones</h2>${gapCards}` : '<h2>✅ Cobertura Completa</h2><p>Todos los controles están cubiertos. ¡Excelente trabajo!</p>'}

  <footer>Generado por <strong>OSDO CLI v2</strong> — ${new Date().toISOString()}</footer>
</body>
</html>`
}

// ── Utilidades ────────────────────────────────────────────────────────────────

function buildProgressBar(current: number, max: number, width: number): string {
  const filled = Math.round((current / max) * width)
  const empty = width - filled
  const bar = chalk.green('█'.repeat(filled)) + chalk.gray('░'.repeat(empty))
  return `[${bar}]`
}

/** Ordena los ControlCoverage: primero gaps, luego por nivel */
export function sortCoverageForReport(coverage: ControlCoverage[]): ControlCoverage[] {
  const levelOrder = {esencial: 0, recomendado: 1, completo: 2}
  return [...coverage].sort((a, b) => {
    if (a.covered !== b.covered) return a.covered ? 1 : -1
    return levelOrder[a.control.level] - levelOrder[b.control.level]
  })
}
