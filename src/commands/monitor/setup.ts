import {Flags} from '@oclif/core'
import {input} from '@inquirer/prompts'
import {BaseCommand} from '../../lib/base-command.js'

/**
 * MonitorSetup — Guarda las URLs de los servicios de monitorización
 * en la configuración persistente del CLI (~/.config/osdo/config.json).
 *
 * Las URLs se pueden proporcionar como flags, variables de entorno
 * o de forma interactiva mediante prompts.
 */
export default class MonitorSetup extends BaseCommand {
  static description = 'Configurar URLs de monitorización (Prometheus, Grafana, Alertmanager)'

  static examples = [
    '<%= config.bin %> monitor setup --prometheus-url http://prometheus:9090',
    '<%= config.bin %> monitor setup --grafana-url http://grafana:3000 --alertmanager-url http://alertmanager:9093',
    '<%= config.bin %> monitor setup',
  ]

  static flags = {
    ...BaseCommand.globalFlags,
    'prometheus-url': Flags.string({
      description: 'URL de Prometheus',
      env: 'OSDO_PROMETHEUS_URL',
    }),
    'grafana-url': Flags.string({
      description: 'URL de Grafana',
      env: 'OSDO_GRAFANA_URL',
    }),
    'alertmanager-url': Flags.string({
      description: 'URL de Alertmanager',
      env: 'OSDO_ALERTMANAGER_URL',
    }),
  }

  async run(): Promise<void> {
    const {flags} = await this.parse(MonitorSetup)

    // Resolver URLs: flag > env > prompt interactivo
    const prometheusUrl = flags['prometheus-url'] ??
      await input({message: 'URL de Prometheus:', default: 'http://localhost:9090'})

    const grafanaUrl = flags['grafana-url'] ??
      await input({message: 'URL de Grafana:', default: 'http://localhost:3000'})

    const alertmanagerUrl = flags['alertmanager-url'] ??
      await input({message: 'URL de Alertmanager:', default: 'http://localhost:9093'})

    // Salir sin ejecutar si estamos en modo dry-run
    if (this.dryRun(`Guardar configuración de monitorización`)) return

    this.configManager.setMonitoringUrls({prometheusUrl, grafanaUrl, alertmanagerUrl})

    this.log('✓ Configuración de monitorización guardada.')
    this.log(`  Prometheus:    ${prometheusUrl}`)
    this.log(`  Grafana:       ${grafanaUrl}`)
    this.log(`  Alertmanager:  ${alertmanagerUrl}`)
  }
}
