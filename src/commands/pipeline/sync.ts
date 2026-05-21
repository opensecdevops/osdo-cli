import {Flags} from '@oclif/core'
import {existsSync, readdirSync, readFileSync, writeFileSync} from 'node:fs'
import {join} from 'node:path'
import {BaseCommand} from '../../lib/base-command.js'

interface SyncChange {
  file: string
  from: string
  to: string
  count: number
}

// Mapeo de versiones antiguas → versión v2 de cada action OSDO
// Formato de v2: opensecdevops/osdo-actions/actions/<name>@<name>/v2.0.0
const VERSION_UPGRADES: Array<{pattern: RegExp; replacement: string; actionName: string}> = [
  // Formato antiguo sin /actions/: opensecdevops/osdo-actions/osdo-<name>@v0.x o @v1.x
  {
    pattern: /opensecdevops\/osdo-actions\/osdo-sast@v[01](?:\.\d+)*/g,
    replacement: 'opensecdevops/osdo-actions/actions/osdo-sast@osdo-sast/v2.0.0',
    actionName: 'osdo-sast',
  },
  {
    pattern: /opensecdevops\/osdo-actions\/osdo-sca@v[01](?:\.\d+)*/g,
    replacement: 'opensecdevops/osdo-actions/actions/osdo-sca@osdo-sca/v2.0.0',
    actionName: 'osdo-sca',
  },
  {
    pattern: /opensecdevops\/osdo-actions\/osdo-secrets-scan@v[01](?:\.\d+)*/g,
    replacement: 'opensecdevops/osdo-actions/actions/osdo-secrets-scan@osdo-secrets-scan/v2.0.0',
    actionName: 'osdo-secrets-scan',
  },
  {
    pattern: /opensecdevops\/osdo-actions\/osdo-sbom@v[01](?:\.\d+)*/g,
    replacement: 'opensecdevops/osdo-actions/actions/osdo-sbom@osdo-sbom/v2.0.0',
    actionName: 'osdo-sbom',
  },
  {
    pattern: /opensecdevops\/osdo-actions\/osdo-container-scan@v[01](?:\.\d+)*/g,
    replacement: 'opensecdevops/osdo-actions/actions/osdo-container-scan@osdo-container-scan/v2.0.0',
    actionName: 'osdo-container-scan',
  },
  {
    pattern: /opensecdevops\/osdo-actions\/osdo-iac-scan@v[01](?:\.\d+)*/g,
    replacement: 'opensecdevops/osdo-actions/actions/osdo-iac-scan@osdo-iac-scan/v2.0.0',
    actionName: 'osdo-iac-scan',
  },
  {
    pattern: /opensecdevops\/osdo-actions\/osdo-dast-scan@v[01](?:\.\d+)*/g,
    replacement: 'opensecdevops/osdo-actions/actions/osdo-dast-scan@osdo-dast-scan/v2.0.0',
    actionName: 'osdo-dast-scan',
  },
  {
    pattern: /opensecdevops\/osdo-actions\/osdo-policy-gate@v[01](?:\.\d+)*/g,
    replacement: 'opensecdevops/osdo-actions/actions/osdo-policy-gate@osdo-policy-gate/v2.0.0',
    actionName: 'osdo-policy-gate',
  },
  {
    pattern: /opensecdevops\/osdo-actions\/osdo-slsa-provenance@v[01](?:\.\d+)*/g,
    replacement: 'opensecdevops/osdo-actions/actions/osdo-slsa-provenance@osdo-slsa-provenance/v2.0.0',
    actionName: 'osdo-slsa-provenance',
  },
  {
    pattern: /opensecdevops\/osdo-actions\/osdo-quality-gate@v[01](?:\.\d+)*/g,
    replacement: 'opensecdevops/osdo-actions/actions/osdo-quality-gate@osdo-quality-gate/v2.0.0',
    actionName: 'osdo-quality-gate',
  },
  {
    pattern: /opensecdevops\/osdo-actions\/osdo-release@v[01](?:\.\d+)*/g,
    replacement: 'opensecdevops/osdo-actions/actions/osdo-release@osdo-release/v2.0.0',
    actionName: 'osdo-release',
  },
  {
    pattern: /opensecdevops\/osdo-actions\/osdo-fuzz@v[01](?:\.\d+)*/g,
    replacement: 'opensecdevops/osdo-actions/actions/osdo-fuzz@osdo-fuzz/v2.0.0',
    actionName: 'osdo-fuzz',
  },
  // Formato antiguo con /actions/ pero en @v1
  {
    pattern: /opensecdevops\/osdo-actions\/actions\/osdo-([a-z-]+)@osdo-\1\/v1(?:\.\d+)*/g,
    replacement: '',  // Se maneja con lógica especial abajo
    actionName: 'generic-v1',
  },
]

function applyVersionUpgrades(content: string): {newContent: string; changes: Array<{from: string; to: string; count: number}>} {
  let newContent = content
  const changes: Array<{from: string; to: string; count: number}> = []

  for (const upgrade of VERSION_UPGRADES) {
    if (upgrade.actionName === 'generic-v1') {
      // Patrón genérico para /actions/<name>@<name>/v1.x
      const genericPattern = /opensecdevops\/osdo-actions\/actions\/(osdo-[a-z-]+)@osdo-[a-z-]+\/v1(?:\.\d+)*/g
      let match: RegExpExecArray | null
      const replacements = new Map<string, string>()

      while ((match = genericPattern.exec(content)) !== null) {
        const name = match[1]
        const oldRef = match[0]
        const newRef = `opensecdevops/osdo-actions/actions/${name}@${name}/v2.0.0`
        if (oldRef !== newRef) {
          replacements.set(oldRef, newRef)
        }
      }

      for (const [oldRef, newRef] of replacements) {
        const occurrences = (newContent.split(oldRef)).length - 1
        if (occurrences > 0) {
          newContent = newContent.replaceAll(oldRef, newRef)
          changes.push({from: oldRef, to: newRef, count: occurrences})
        }
      }
    } else {
      const occurrencesBefore = (newContent.match(upgrade.pattern) ?? []).length
      if (occurrencesBefore > 0) {
        const fromSample = (newContent.match(upgrade.pattern) ?? [])[0] ?? ''
        newContent = newContent.replace(upgrade.pattern, upgrade.replacement)
        changes.push({from: fromSample, to: upgrade.replacement, count: occurrencesBefore})
        // Resetear lastIndex del patrón global
        upgrade.pattern.lastIndex = 0
      }
    }
  }

  return {newContent, changes}
}

function collectWorkflowFiles(fileFlag: string | undefined): string[] {
  if (fileFlag) return existsSync(fileFlag) ? [fileFlag] : []

  const workflowDir = join('.github', 'workflows')
  if (!existsSync(workflowDir)) return []

  return readdirSync(workflowDir)
    .filter(f => f.endsWith('.yml') || f.endsWith('.yaml'))
    .map(f => join(workflowDir, f))
}

export default class PipelineSync extends BaseCommand {
  static description = 'Actualizar actions OSDO de @v0/@v1 a @v2 en los workflows'

  static examples = [
    '<%= config.bin %> pipeline sync',
    '<%= config.bin %> pipeline sync --dry-run',
    '<%= config.bin %> pipeline sync --file .github/workflows/osdo-security.yml',
    '<%= config.bin %> pipeline sync --file .github/workflows/ci.yml --dry-run',
  ]

  static flags = {
    ...BaseCommand.globalFlags,
    file: Flags.string({
      char: 'f',
      description: 'Archivo específico a sincronizar (por defecto todos los de .github/workflows/)',
    }),
  }

  async run(): Promise<void> {
    const {flags} = await this.parse(PipelineSync)

    const isDryRun = flags['dry-run'] || this.configManager.isDryRun()

    this.log('\nOSDO Pipeline Sync')
    this.log('═══════════════════════════════════════')
    if (isDryRun) this.log('  [dry-run] Solo se mostrarán los cambios, no se aplicarán\n')

    const files = collectWorkflowFiles(flags.file)

    if (files.length === 0) {
      if (flags.file) {
        this.warn(`Archivo no encontrado: ${flags.file}`)
      } else {
        this.warn('No se encontraron workflows en .github/workflows/. Genera uno con: osdo pipeline generate')
      }

      return
    }

    const allSyncChanges: SyncChange[] = []

    for (const filePath of files) {
      const original = readFileSync(filePath, 'utf8')

      if (!original.includes('opensecdevops/osdo-actions')) {
        this.log(`  ○ ${filePath} — sin actions OSDO, omitido`)
        continue
      }

      const {newContent, changes} = applyVersionUpgrades(original)

      if (changes.length === 0) {
        this.log(`  ✓ ${filePath} — ya está actualizado`)
        continue
      }

      for (const c of changes) {
        allSyncChanges.push({file: filePath, ...c})
        this.log(`  ↑ ${filePath}`)
        this.log(`    FROM: ${c.from}`)
        this.log(`    TO:   ${c.to}`)
        this.log(`    Ocurrencias: ${c.count}`)
      }

      if (!isDryRun) {
        writeFileSync(filePath, newContent, 'utf8')
        this.log(`    ✓ Guardado`)
      }

      this.log('')
    }

    this.log('═══════════════════════════════════════')

    if (allSyncChanges.length === 0) {
      this.log('Todos los workflows ya están actualizados a v2.')
      return
    }

    const updatedFiles = [...new Set(allSyncChanges.map(c => c.file))].length

    if (isDryRun) {
      this.log(`[dry-run] Se actualizarían ${updatedFiles} archivo(s) con ${allSyncChanges.length} cambio(s).`)
      this.log('Ejecuta sin --dry-run para aplicar los cambios.')
    } else {
      this.log(`${updatedFiles} archivo(s) actualizado(s) con ${allSyncChanges.length} cambio(s).`)
    }

    if (flags.output === 'json') {
      this.log(JSON.stringify(allSyncChanges, null, 2))
    }
  }
}
