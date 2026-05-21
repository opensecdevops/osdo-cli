import {input, confirm, select, checkbox} from '@inquirer/prompts'
import type {Block, Field, PackageConfig} from '../api/client.js'
import {resolveActiveBlocks} from './handlebars.js'

export interface GeneratorAnswers {
  values: Record<string, unknown>
  activeBlocks: Set<string>
}

export async function promptForPackage(form: PackageConfig): Promise<GeneratorAnswers> {
  const values: Record<string, unknown> = {}
  let activeBlocks = new Set<string>()

  // Start with enabled blocks
  for (const block of form.blocks) {
    if (block.enabled) activeBlocks.add(block.template)
  }

  // Ask user which blocks to enable
  if (form.blocks.length > 1) {
    const choices = form.blocks.map((b) => ({
      name: `${b.name}${b.description ? ` — ${b.description}` : ''}`,
      value: b.template,
      checked: b.enabled ?? false,
    }))

    const selectedBlocks = await checkbox({
      message: 'Selecciona los módulos a incluir:',
      choices,
    })

    activeBlocks = new Set(selectedBlocks)
  }

  // Resolve dependencies
  activeBlocks = resolveActiveBlocks(form.blocks, activeBlocks)

  // Prompt for each field in active blocks
  for (const block of form.blocks) {
    if (!activeBlocks.has(block.template)) continue

    console.log(`\n── ${block.name} ──`)

    for (const field of block.fields) {
      const value = await promptField(field)
      values[field.name] = value

      // Handle field-level dependencies (select/switch can activate blocks)
      if (field.type === 'select' && field.options) {
        const selectedOption = field.options.find((o) => String(o.id) === String(value))
        for (const dep of selectedOption?.dependencies ?? []) {
          activeBlocks.add(dep)
        }
      }
    }
  }

  return {values, activeBlocks}
}

async function promptField(field: Field): Promise<unknown> {
  const message = field.label + (field.info ? ` (${field.info})` : '')

  switch (field.type) {
    case 'text':
      return input({
        message,
        default: String(field.default ?? ''),
      })

    case 'switch':
      return confirm({
        message,
        default: Boolean(field.default ?? false),
      })

    case 'select':
      if (!field.options) return field.default ?? ''
      return select({
        message,
        choices: field.options.map((o) => ({name: o.label, value: String(o.id)})),
      })

    default:
      return field.default ?? ''
  }
}
