import {readFileSync} from 'node:fs'
import {join, dirname} from 'node:path'
import {fileURLToPath} from 'node:url'

const __dirname = dirname(fileURLToPath(import.meta.url))

export interface OfflineTemplate {
  name: string
  description: string
  config: object
  template: string
}

const TEMPLATES = ['basic', 'container', 'full'] as const
export type TemplateName = typeof TEMPLATES[number]

export function listOfflineTemplates(): Array<{name: string; description: string}> {
  return TEMPLATES.map(name => {
    const config = JSON.parse(
      readFileSync(join(__dirname, name, 'config.json'), 'utf8')
    )
    return {name, description: config.description}
  })
}

export function loadOfflineTemplate(name: TemplateName): OfflineTemplate {
  const configPath = join(__dirname, name, 'config.json')
  const templatePath = join(__dirname, name, 'workflow.yml.hbs')

  const config = JSON.parse(readFileSync(configPath, 'utf8'))
  const template = readFileSync(templatePath, 'utf8')

  return {
    name,
    description: config.description,
    config,
    template,
  }
}

export {TEMPLATES}
