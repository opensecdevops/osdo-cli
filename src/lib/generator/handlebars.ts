import * as Handlebars from 'handlebars'
import type {Block, PackageConfig, Extra} from '../api/client.js'

export interface Template {
  file: string
  content: string
}

export interface GeneratedFile {
  file: string
  content: string
  language: string
}

export function renderPackage(
  form: PackageConfig,
  templates: Template[],
  values: Record<string, unknown>,
  activeBlocks: Set<string>,
): GeneratedFile[] {
  // 1. Reset and register all templates as Handlebars partials
  const hbs = Handlebars.create()
  for (const tpl of templates) {
    const name = tpl.file.replace(/\.twig$/, '')
    hbs.registerPartial(name, tpl.content)
  }

  // 2. Build context with select field dual-injection
  const context = buildContext(form.blocks, values, activeBlocks)

  // 3. Find main template content
  const mainTemplateName = form.template ?? 'main'
  const mainTpl = templates.find((t) => t.file === mainTemplateName || t.file === `${mainTemplateName}.twig`)
  if (!mainTpl) {
    throw new Error(`Template principal '${mainTemplateName}' no encontrado`)
  }

  // 4. Render main file
  const compiledMain = hbs.compile(mainTpl.content)
  const mainContent = compiledMain(context)
  const results: GeneratedFile[] = [
    {
      file: form.file ?? 'output',
      content: mainContent,
      language: form.language ?? 'yaml',
    },
  ]

  // 5. Render extra files for active blocks
  for (const block of form.blocks) {
    if (!activeBlocks.has(block.template)) continue
    if (!block.extra) continue

    for (const extra of block.extra) {
      // Check extra dependencies
      if (extra.dependencies) {
        const depsActive = extra.dependencies.every((d) => activeBlocks.has(d))
        if (!depsActive) continue
      }

      const extraTpl = templates.find(
        (t) => t.file === extra.template || t.file === `${extra.template}.twig`,
      )
      if (!extraTpl) continue

      const compiledExtra = hbs.compile(extraTpl.content)
      const extraContent = compiledExtra(context)
      results.push({
        file: `${extra.route ?? ''}${extra.file}`,
        content: extraContent,
        language: extra.language,
      })
    }
  }

  return results
}

function buildContext(
  blocks: Block[],
  values: Record<string, unknown>,
  activeBlocks: Set<string>,
): Record<string, unknown> {
  const context: Record<string, unknown> = {}

  for (const block of blocks) {
    if (!activeBlocks.has(block.template)) continue

    for (const field of block.fields) {
      const value = values[field.name] ?? field.default

      if (field.type === 'select' && field.options) {
        // Select fields inject two variables: fieldName (id) and fieldName_value (string value)
        const selectedOption = field.options.find((o) => String(o.id) === String(value))
        context[field.name] = value
        context[`${field.name}_value`] = selectedOption?.value ?? ''
      } else {
        context[field.name] = value
      }
    }
  }

  return context
}

export function resolveActiveBlocks(
  blocks: Block[],
  initialActive: Set<string>,
): Set<string> {
  const active = new Set(initialActive)
  let changed = true

  // Resolve dependencies recursively
  while (changed) {
    changed = false
    for (const block of blocks) {
      if (!active.has(block.template)) continue
      for (const dep of block.dependencies ?? []) {
        if (!active.has(dep)) {
          active.add(dep)
          changed = true
        }
      }
    }
  }

  return active
}

export function getDefaultActiveBlocks(blocks: Block[]): Set<string> {
  const active = new Set<string>()
  for (const block of blocks) {
    if (block.enabled) {
      active.add(block.template)
    }
  }
  return resolveActiveBlocks(blocks, active)
}
