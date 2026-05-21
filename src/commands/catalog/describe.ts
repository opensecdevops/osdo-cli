import {Args} from '@oclif/core'
import chalk from 'chalk'
import {BaseCommand} from '../../lib/base-command.js'
import {findInfraItem, CATEGORY_LABELS} from '../../lib/infra-catalog.js'

/**
 * Catalog Describe — Muestra los detalles completos de un componente de
 * infraestructura del catálogo OSDO, incluyendo instrucciones de instalación
 * para cada plataforma soportada.
 */
export default class CatalogDescribe extends BaseCommand {
  static description = 'Mostrar detalles completos de un componente de infraestructura del catálogo'

  static examples = [
    '<%= config.bin %> catalog describe prometheus',
    '<%= config.bin %> catalog describe vault',
    '<%= config.bin %> catalog describe gitlab --output json',
    '<%= config.bin %> catalog describe dependency-track',
  ]

  static args = {
    name: Args.string({
      description: 'Nombre del componente',
      required: true,
    }),
  }

  static flags = {
    ...BaseCommand.globalFlags,
  }

  async run(): Promise<void> {
    const {args, flags} = await this.parse(CatalogDescribe)

    const item = findInfraItem(args.name)

    if (!item) {
      this.error(
        `Componente no encontrado: "${args.name}"\n` +
          "Usa 'osdo catalog list' para ver los componentes disponibles.",
        {exit: 1},
      )
    }

    // Salida JSON
    if (flags.output === 'json') {
      this.log(JSON.stringify(item, null, 2))
      return
    }

    const categoryLabel = CATEGORY_LABELS[item.category]

    // Cabecera
    this.log('')
    this.log(chalk.bold(chalk.cyan(item.name)))
    this.log('═══════════════════════════════════════════════════════════════')
    this.log(`  Descripción: ${item.description}`)
    this.log(`  Categoría:   ${categoryLabel} (${item.category})`)
    this.log(`  Chart Helm:  ${chalk.dim(item.chart)}`)
    this.log(`  Versión:     ${item.version}`)
    this.log('')

    // Instrucciones de instalación por plataforma
    this.log(chalk.bold('Instrucciones de instalación:'))
    this.log('─────────────────────────────────────────────────────────────')

    this.log('')
    this.log(chalk.bold('  Helm (recomendado):'))
    this.log(`    helm upgrade --install ${item.name} ${item.chart} \\`)
    this.log(`      --namespace osdo \\`)
    this.log(`      --create-namespace \\`)
    this.log(`      --version ${item.version}`)

    this.log('')
    this.log(chalk.bold('  Kubernetes / K3s (con manifest propio):'))
    this.log(`    # Crea el manifiesto en:`)
    this.log(`    #   .osdo/manifests/${item.name}.yaml`)
    this.log(`    kubectl apply -f .osdo/manifests/${item.name}.yaml -n osdo`)

    this.log('')
    this.log(chalk.bold('  Docker Compose:'))
    this.log(`    # Crea el archivo en:`)
    this.log(`    #   .osdo/compose/${item.name}.yml`)
    this.log(`    docker compose -f .osdo/compose/${item.name}.yml up -d`)

    this.log('')

    // Accesos rápidos post-instalación
    this.log(chalk.bold('Accesos rápidos tras el despliegue:'))
    this.log('─────────────────────────────────────────────────────────────')
    this.printAccessInfo(item.name)

    this.log('')

    // Comando OSDO
    this.log(chalk.bold('Despliegue con OSDO CLI:'))
    this.log('─────────────────────────────────────────────────────────────')
    this.log(`    osdo deploy --components ${item.name} --platform helm`)
    this.log(`    osdo catalog add ${item.name}`)
    this.log('')
  }

  private printAccessInfo(name: string): void {
    const portForwards: Record<string, {port: string; desc: string}> = {
      prometheus: {port: '9090:9090', desc: 'UI de Prometheus'},
      grafana: {port: '3000:80', desc: 'UI de Grafana (admin/prom-operator)'},
      jaeger: {port: '16686:16686', desc: 'UI de Jaeger Tracing'},
      vault: {port: '8200:8200', desc: 'UI/API de HashiCorp Vault'},
      sonarqube: {port: '9000:9000', desc: 'UI de SonarQube (admin/admin)'},
      defectdojo: {port: '8080:80', desc: 'UI de DefectDojo'},
      harbor: {port: '8443:443', desc: 'Registry Harbor (https://localhost:8443)'},
      'dependency-track': {port: '8081:80', desc: 'UI de Dependency Track'},
      gitlab: {port: '8929:80', desc: 'UI de GitLab'},
      jenkins: {port: '8080:8080', desc: 'UI de Jenkins'},
      traefik: {port: '8080:8080', desc: 'Dashboard de Traefik'},
      portainer: {port: '9443:9443', desc: 'UI de Portainer (https://localhost:9443)'},
    }

    const info = portForwards[name]
    if (info) {
      this.log(`    kubectl port-forward svc/${name} ${info.port} -n osdo`)
      this.log(`    # ${info.desc}`)
    } else {
      this.log(`    kubectl get svc -n osdo -l app.kubernetes.io/name=${name}`)
    }
  }
}
