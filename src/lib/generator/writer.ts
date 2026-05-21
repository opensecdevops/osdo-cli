import {mkdirSync, writeFileSync, existsSync} from 'node:fs'
import {dirname, join, resolve} from 'node:path'
import type {GeneratedFile} from './handlebars.js'

export interface WriteResult {
  file: string
  absolutePath: string
  skipped: boolean
}

/**
 * Escribe los archivos generados por renderPackage() al disco.
 *
 * Por defecto, si un archivo ya existe pregunta antes de sobrescribir
 * (controlado por el flag overwrite). En modo dry-run, solo imprime
 * qué se escribiría.
 */
export async function writeGeneratedFiles(
  files: GeneratedFile[],
  destDir: string,
  options: {
    overwrite?: boolean
    dryRun?: boolean
    log?: (msg: string) => void
  } = {},
): Promise<WriteResult[]> {
  const {overwrite = false, dryRun = false, log = console.log} = options
  const results: WriteResult[] = []
  const absDestDir = resolve(destDir)

  for (const file of files) {
    const absPath = join(absDestDir, file.file)
    const alreadyExists = existsSync(absPath)

    if (alreadyExists && !overwrite) {
      log(`  ⚠ Omitido (ya existe): ${file.file}  — usa --overwrite para reemplazar`)
      results.push({file: file.file, absolutePath: absPath, skipped: true})
      continue
    }

    if (dryRun) {
      log(`  [dry-run] Escribir ${file.file} (${file.language})`)
      results.push({file: file.file, absolutePath: absPath, skipped: false})
      continue
    }

    // Asegurarse de que el directorio padre existe
    mkdirSync(dirname(absPath), {recursive: true})
    writeFileSync(absPath, file.content, 'utf8')

    const action = alreadyExists ? 'Sobreescrito' : 'Creado'
    log(`  ✓ ${action}: ${file.file}`)
    results.push({file: file.file, absolutePath: absPath, skipped: false})
  }

  return results
}
