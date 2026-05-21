/**
 * OSDO Component Catalog — datos compartidos entre los comandos catalog/*.
 * Incluye 22 actions y 10 workflows con metadata detallada.
 */

export interface CatalogInput {
  name: string
  required: boolean
  description: string
  default?: string
}

export interface CatalogOutput {
  name: string
  description: string
}

export interface CatalogItem {
  name: string
  type: 'action' | 'workflow' | 'template' | 'policy'
  description: string
  version: string
  category: string
  tags: string[]
  inputs?: CatalogInput[]
  outputs?: CatalogOutput[]
  example?: string
}

export const CATALOG_ACTIONS: CatalogItem[] = [
  {
    name: 'osdo-sast',
    type: 'action',
    description: 'Static Application Security Testing con Semgrep, Bandit y ESLint Security',
    version: 'v2.0.0',
    category: 'Security Scanning',
    tags: ['sast', 'security', 'semgrep'],
    inputs: [
      {name: 'path', required: false, description: 'Ruta a escanear', default: '.'},
      {name: 'config', required: false, description: 'Configuración de Semgrep', default: 'p/security-audit'},
      {name: 'fail-on-finding', required: false, description: 'Falla si encuentra hallazgos', default: 'true'},
      {name: 'output-format', required: false, description: 'Formato de salida (sarif, json)', default: 'sarif'},
    ],
    outputs: [
      {name: 'findings-count', description: 'Número total de hallazgos'},
      {name: 'sarif-path', description: 'Ruta al archivo SARIF generado'},
    ],
    example: `- name: SAST Scan
  uses: opensecdevops/osdo-actions/actions/osdo-sast@osdo-sast/v2.0.0
  with:
    path: .
    fail-on-finding: true`,
  },
  {
    name: 'osdo-sca',
    type: 'action',
    description: 'Software Composition Analysis con OSV-Scanner y Grype',
    version: 'v2.0.0',
    category: 'Supply Chain',
    tags: ['sca', 'dependencies', 'vulnerabilities'],
    inputs: [
      {name: 'path', required: false, description: 'Ruta a escanear', default: '.'},
      {name: 'scanners', required: false, description: 'Escáneres a usar (osv,grype)', default: 'osv,grype'},
      {name: 'fail-on-critical', required: false, description: 'Falla en vulnerabilidades críticas', default: 'true'},
    ],
    outputs: [
      {name: 'vulnerability-count', description: 'Número de vulnerabilidades encontradas'},
      {name: 'critical-count', description: 'Número de vulnerabilidades críticas'},
    ],
    example: `- name: SCA Scan
  uses: opensecdevops/osdo-actions/actions/osdo-sca@osdo-sca/v2.0.0
  with:
    scanners: osv,grype
    fail-on-critical: true`,
  },
  {
    name: 'osdo-secrets-scan',
    type: 'action',
    description: 'Detección de secretos con Gitleaks y TruffleHog',
    version: 'v2.0.0',
    category: 'Security Scanning',
    tags: ['secrets', 'gitleaks', 'trufflehog'],
    inputs: [
      {name: 'scanners', required: false, description: 'Escáneres (gitleaks,trufflehog)', default: 'gitleaks'},
      {name: 'fail-on-finding', required: false, description: 'Falla si encuentra secretos', default: 'true'},
      {name: 'baseline-path', required: false, description: 'Ruta al baseline de Gitleaks'},
    ],
    outputs: [
      {name: 'secrets-found', description: 'Número de secretos detectados'},
    ],
    example: `- name: Secrets Scan
  uses: opensecdevops/osdo-actions/actions/osdo-secrets-scan@osdo-secrets-scan/v2.0.0
  with:
    fail-on-finding: true`,
  },
  {
    name: 'osdo-sbom',
    type: 'action',
    description: 'Generación de SBOM en formato SPDX y CycloneDX con Syft',
    version: 'v2.0.0',
    category: 'Supply Chain',
    tags: ['sbom', 'spdx', 'cyclonedx', 'syft'],
    inputs: [
      {name: 'format', required: false, description: 'Formato de salida (spdx,cyclonedx,both)', default: 'both'},
      {name: 'upload-artifact', required: false, description: 'Subir SBOM como artifact', default: 'true'},
      {name: 'output-prefix', required: false, description: 'Prefijo para archivos de salida', default: 'sbom'},
    ],
    outputs: [
      {name: 'sbom-spdx-path', description: 'Ruta al SBOM SPDX'},
      {name: 'sbom-cdx-path', description: 'Ruta al SBOM CycloneDX'},
    ],
    example: `- name: Generate SBOM
  uses: opensecdevops/osdo-actions/actions/osdo-sbom@osdo-sbom/v2.0.0
  with:
    format: both
    upload-artifact: true`,
  },
  {
    name: 'osdo-container-scan',
    type: 'action',
    description: 'Escaneo de seguridad de contenedores con Trivy y Grype',
    version: 'v2.0.0',
    category: 'Security Scanning',
    tags: ['container', 'trivy', 'docker', 'grype'],
    inputs: [
      {name: 'image', required: true, description: 'Imagen de contenedor a escanear'},
      {name: 'scanners', required: false, description: 'Escáneres (trivy,grype)', default: 'trivy'},
      {name: 'fail-on', required: false, description: 'Severidad mínima para fallo (HIGH,CRITICAL)', default: 'HIGH'},
    ],
    outputs: [
      {name: 'vulnerability-count', description: 'Vulnerabilidades en la imagen'},
    ],
    example: `- name: Container Scan
  uses: opensecdevops/osdo-actions/actions/osdo-container-scan@osdo-container-scan/v2.0.0
  with:
    image: \${{ github.repository }}:\${{ github.sha }}
    fail-on: HIGH`,
  },
  {
    name: 'osdo-iac-scan',
    type: 'action',
    description: 'Escaneo de Infrastructure as Code con Checkov y KICS',
    version: 'v2.0.0',
    category: 'Security Scanning',
    tags: ['iac', 'checkov', 'terraform', 'kubernetes'],
    inputs: [
      {name: 'path', required: false, description: 'Ruta de IaC a escanear', default: '.'},
      {name: 'scanners', required: false, description: 'Escáneres (checkov,kics)', default: 'checkov'},
      {name: 'frameworks', required: false, description: 'Frameworks (terraform,kubernetes,dockerfile)', default: 'all'},
    ],
    outputs: [
      {name: 'failed-checks', description: 'Número de controles fallidos'},
    ],
    example: `- name: IaC Scan
  uses: opensecdevops/osdo-actions/actions/osdo-iac-scan@osdo-iac-scan/v2.0.0
  with:
    path: .
    frameworks: terraform,kubernetes`,
  },
  {
    name: 'osdo-dast-scan',
    type: 'action',
    description: 'Dynamic Application Security Testing con OWASP ZAP',
    version: 'v2.0.0',
    category: 'Security Scanning',
    tags: ['dast', 'zap', 'owasp'],
    inputs: [
      {name: 'target-url', required: true, description: 'URL objetivo para el scan'},
      {name: 'scan-type', required: false, description: 'Tipo de scan (baseline,full,api)', default: 'baseline'},
      {name: 'fail-on-severity', required: false, description: 'Severidad mínima para fallo', default: 'HIGH'},
    ],
    outputs: [
      {name: 'alerts-count', description: 'Número de alertas encontradas'},
    ],
    example: `- name: DAST Scan
  uses: opensecdevops/osdo-actions/actions/osdo-dast-scan@osdo-dast-scan/v2.0.0
  with:
    target-url: https://myapp.example.com
    scan-type: baseline`,
  },
  {
    name: 'osdo-policy-gate',
    type: 'action',
    description: 'Cumplimiento de políticas con OPA/Rego y Kyverno',
    version: 'v2.0.0',
    category: 'Quality',
    tags: ['policy', 'opa', 'kyverno', 'compliance'],
    inputs: [
      {name: 'builtin-policies', required: false, description: 'Políticas built-in (security,compliance)', default: 'security'},
      {name: 'custom-policies-path', required: false, description: 'Ruta a políticas personalizadas'},
      {name: 'fail-on-violation', required: false, description: 'Falla en violaciones de política', default: 'true'},
    ],
    outputs: [
      {name: 'violations-count', description: 'Número de violaciones de política'},
    ],
    example: `- name: Policy Gate
  uses: opensecdevops/osdo-actions/actions/osdo-policy-gate@osdo-policy-gate/v2.0.0
  with:
    builtin-policies: security,compliance
    fail-on-violation: true`,
  },
  {
    name: 'osdo-slsa-provenance',
    type: 'action',
    description: 'Generación de provenance SLSA Level 3',
    version: 'v2.0.0',
    category: 'Supply Chain',
    tags: ['slsa', 'provenance', 'supply-chain'],
    inputs: [
      {name: 'subject-path', required: true, description: 'Artefactos para los que generar provenance'},
      {name: 'slsa-level', required: false, description: 'Nivel SLSA objetivo (1,2,3)', default: '3'},
    ],
    outputs: [
      {name: 'provenance-path', description: 'Ruta al archivo de provenance'},
    ],
    example: `- name: Generate Provenance
  uses: opensecdevops/osdo-actions/actions/osdo-slsa-provenance@osdo-slsa-provenance/v2.0.0
  with:
    subject-path: dist/*
    slsa-level: "3"`,
  },
  {
    name: 'osdo-fuzz',
    type: 'action',
    description: 'Fuzz testing con AFL++ y Atheris',
    version: 'v2.0.0',
    category: 'Quality',
    tags: ['fuzzing', 'afl', 'testing'],
    inputs: [
      {name: 'fuzz-seconds', required: false, description: 'Duración del fuzz en segundos', default: '60'},
      {name: 'fuzz-target', required: false, description: 'Función objetivo para fuzzing'},
    ],
    outputs: [
      {name: 'crashes-found', description: 'Número de crashes encontrados'},
    ],
    example: `- name: Fuzz Testing
  uses: opensecdevops/osdo-actions/actions/osdo-fuzz@osdo-fuzz/v2.0.0
  with:
    fuzz-seconds: 120`,
  },
  {
    name: 'osdo-quality-gate',
    type: 'action',
    description: 'Control de calidad del código: cobertura, complejidad, duplicación',
    version: 'v2.0.0',
    category: 'Quality',
    tags: ['quality', 'coverage', 'sonarqube'],
    inputs: [
      {name: 'coverage-minimum', required: false, description: 'Cobertura mínima (%)', default: '80'},
      {name: 'fail-below-threshold', required: false, description: 'Falla si no se alcanza el umbral', default: 'true'},
    ],
    outputs: [
      {name: 'coverage-percentage', description: 'Porcentaje de cobertura actual'},
    ],
    example: `- name: Quality Gate
  uses: opensecdevops/osdo-actions/actions/osdo-quality-gate@osdo-quality-gate/v2.0.0
  with:
    coverage-minimum: 80`,
  },
  {
    name: 'osdo-release',
    type: 'action',
    description: 'Automatización segura de releases con SBOM y firma',
    version: 'v2.0.0',
    category: 'Infrastructure',
    tags: ['release', 'signing', 'automation'],
    inputs: [
      {name: 'sign-artifacts', required: false, description: 'Firmar artefactos con Sigstore', default: 'true'},
      {name: 'generate-changelog', required: false, description: 'Generar changelog automático', default: 'true'},
    ],
    outputs: [
      {name: 'release-url', description: 'URL del release creado'},
    ],
    example: `- name: Secure Release
  uses: opensecdevops/osdo-actions/actions/osdo-release@osdo-release/v2.0.0
  with:
    sign-artifacts: true`,
  },
  {
    name: 'osdo-mobile-scan',
    type: 'action',
    description: 'Seguridad en apps móviles: OWASP Mobile Top 10 y MASVS',
    version: 'v2.0.0',
    category: 'Security Scanning',
    tags: ['mobile', 'android', 'ios', 'masvs'],
    inputs: [
      {name: 'app-path', required: false, description: 'Ruta de la app móvil', default: '.'},
      {name: 'platform', required: false, description: 'Plataforma (android,ios,both)', default: 'android'},
      {name: 'check-ssl-pinning', required: false, description: 'Verificar SSL pinning', default: 'true'},
      {name: 'check-obfuscation', required: false, description: 'Verificar ofuscación del código', default: 'true'},
      {name: 'fail-on-severity', required: false, description: 'Severidad mínima para fallo', default: 'HIGH'},
    ],
    outputs: [
      {name: 'issues-count', description: 'Problemas de seguridad móvil encontrados'},
    ],
    example: `- name: Mobile Security Scan
  uses: opensecdevops/osdo-actions/actions/osdo-mobile-scan@osdo-mobile-scan/v2.0.0
  with:
    platform: android
    check-ssl-pinning: true`,
  },
  {
    name: 'osdo-smart-contract-audit',
    type: 'action',
    description: 'Auditoría de smart contracts con Slither, Mythril y Solhint',
    version: 'v2.0.0',
    category: 'Security Scanning',
    tags: ['web3', 'solidity', 'slither', 'mythril'],
    inputs: [
      {name: 'contracts-path', required: false, description: 'Ruta a los contratos', default: './contracts'},
      {name: 'scanners', required: false, description: 'Escáneres (slither,mythril,solhint)', default: 'slither,mythril,solhint'},
      {name: 'solidity-version', required: false, description: 'Versión de Solidity', default: '0.8.20'},
    ],
    outputs: [
      {name: 'vulnerabilities-count', description: 'Vulnerabilidades en smart contracts'},
    ],
    example: `- name: Smart Contract Audit
  uses: opensecdevops/osdo-actions/actions/osdo-smart-contract-audit@osdo-smart-contract-audit/v2.0.0
  with:
    contracts-path: ./contracts
    scanners: slither,mythril,solhint`,
  },
  {
    name: 'osdo-llm-scan',
    type: 'action',
    description: 'Seguridad en LLM/GenAI: OWASP GenAI Top 10',
    version: 'v2.0.0',
    category: 'Security Scanning',
    tags: ['genai', 'llm', 'ai-security', 'owasp-genai'],
    inputs: [
      {name: 'source-path', required: false, description: 'Ruta del código fuente', default: '.'},
      {name: 'check-prompt-injection', required: false, description: 'Verificar inyección de prompts', default: 'true'},
      {name: 'check-pii-exposure', required: false, description: 'Verificar exposición de PII', default: 'true'},
    ],
    outputs: [
      {name: 'genai-risks-count', description: 'Riesgos de GenAI identificados'},
    ],
    example: `- name: GenAI Security Scan
  uses: opensecdevops/osdo-actions/actions/osdo-llm-scan@osdo-llm-scan/v2.0.0
  with:
    check-prompt-injection: true
    check-pii-exposure: true`,
  },
  {
    name: 'osdo-license-scan',
    type: 'action',
    description: 'Escaneo de licencias de dependencias con FOSSA y License Finder',
    version: 'v2.0.0',
    category: 'Supply Chain',
    tags: ['license', 'compliance', 'fossa'],
    inputs: [
      {name: 'path', required: false, description: 'Ruta a escanear', default: '.'},
      {name: 'allowed-licenses', required: false, description: 'Licencias permitidas (MIT,Apache-2.0)', default: 'MIT,Apache-2.0,BSD-3-Clause'},
      {name: 'fail-on-unapproved', required: false, description: 'Falla en licencias no aprobadas', default: 'true'},
    ],
    outputs: [
      {name: 'unapproved-count', description: 'Dependencias con licencias no aprobadas'},
    ],
    example: `- name: License Scan
  uses: opensecdevops/osdo-actions/actions/osdo-license-scan@osdo-license-scan/v2.0.0
  with:
    allowed-licenses: MIT,Apache-2.0`,
  },
  {
    name: 'osdo-malware-scan',
    type: 'action',
    description: 'Detección de malware y código malicioso en dependencias',
    version: 'v2.0.0',
    category: 'Supply Chain',
    tags: ['malware', 'supply-chain', 'backdoor'],
    inputs: [
      {name: 'path', required: false, description: 'Ruta a escanear', default: '.'},
      {name: 'scan-node-modules', required: false, description: 'Escanear node_modules', default: 'true'},
    ],
    outputs: [
      {name: 'malware-found', description: 'Número de paquetes maliciosos encontrados'},
    ],
    example: `- name: Malware Scan
  uses: opensecdevops/osdo-actions/actions/osdo-malware-scan@osdo-malware-scan/v2.0.0
  with:
    scan-node-modules: true`,
  },
  {
    name: 'osdo-pentest',
    type: 'action',
    description: 'Pentesting automatizado con Nuclei y Nmap',
    version: 'v2.0.0',
    category: 'Security Scanning',
    tags: ['pentest', 'nuclei', 'nmap'],
    inputs: [
      {name: 'target', required: true, description: 'URL o host objetivo'},
      {name: 'templates', required: false, description: 'Templates de Nuclei a usar', default: 'cves,misconfigurations'},
    ],
    outputs: [
      {name: 'findings-count', description: 'Hallazgos del pentest'},
    ],
    example: `- name: Automated Pentest
  uses: opensecdevops/osdo-actions/actions/osdo-pentest@osdo-pentest/v2.0.0
  with:
    target: https://staging.example.com`,
  },
  {
    name: 'osdo-threat-model',
    type: 'action',
    description: 'Modelado de amenazas automatizado con análisis de arquitectura',
    version: 'v2.0.0',
    category: 'Quality',
    tags: ['threat-model', 'stride', 'architecture'],
    inputs: [
      {name: 'diagram-path', required: false, description: 'Ruta al diagrama de arquitectura'},
      {name: 'output-format', required: false, description: 'Formato de salida (html,json)', default: 'html'},
    ],
    outputs: [
      {name: 'threats-identified', description: 'Amenazas identificadas'},
    ],
    example: `- name: Threat Model
  uses: opensecdevops/osdo-actions/actions/osdo-threat-model@osdo-threat-model/v2.0.0
  with:
    diagram-path: docs/architecture.drawio`,
  },
  {
    name: 'osdo-compliance-check',
    type: 'action',
    description: 'Verificación de cumplimiento: OWASP, SLSA, OpenSSF Scorecard',
    version: 'v2.0.0',
    category: 'Quality',
    tags: ['compliance', 'owasp', 'slsa', 'openssf'],
    inputs: [
      {name: 'standards', required: false, description: 'Estándares a verificar (owasp,slsa,openssf)', default: 'owasp,slsa'},
      {name: 'fail-on-gap', required: false, description: 'Falla en gaps críticos', default: 'true'},
    ],
    outputs: [
      {name: 'compliance-score', description: 'Puntuación de cumplimiento (0-100)'},
    ],
    example: `- name: Compliance Check
  uses: opensecdevops/osdo-actions/actions/osdo-compliance-check@osdo-compliance-check/v2.0.0
  with:
    standards: owasp,slsa,openssf`,
  },
  {
    name: 'osdo-sbom-verify',
    type: 'action',
    description: 'Verificación e integridad de SBOM con validación de firma',
    version: 'v2.0.0',
    category: 'Supply Chain',
    tags: ['sbom', 'verification', 'integrity'],
    inputs: [
      {name: 'sbom-path', required: true, description: 'Ruta al SBOM a verificar'},
      {name: 'verify-signature', required: false, description: 'Verificar firma del SBOM', default: 'true'},
    ],
    outputs: [
      {name: 'verified', description: 'Si el SBOM es válido y verificado'},
    ],
    example: `- name: Verify SBOM
  uses: opensecdevops/osdo-actions/actions/osdo-sbom-verify@osdo-sbom-verify/v2.0.0
  with:
    sbom-path: .osdo/results/sbom/sbom.spdx.json`,
  },
  {
    name: 'osdo-signing',
    type: 'action',
    description: 'Firma de artefactos con Cosign y Sigstore para supply chain security',
    version: 'v2.0.0',
    category: 'Supply Chain',
    tags: ['signing', 'cosign', 'sigstore'],
    inputs: [
      {name: 'artifacts', required: true, description: 'Artefactos a firmar (glob)'},
      {name: 'identity-token', required: false, description: 'Token de identidad OIDC'},
    ],
    outputs: [
      {name: 'signature-path', description: 'Ruta a la firma generada'},
    ],
    example: `- name: Sign Artifacts
  uses: opensecdevops/osdo-actions/actions/osdo-signing@osdo-signing/v2.0.0
  with:
    artifacts: dist/*`,
  },
]

export const CATALOG_WORKFLOWS: CatalogItem[] = [
  {
    name: 'osdo-security-pipeline',
    type: 'workflow',
    description: 'Pipeline completo de seguridad: SAST, SCA, secrets, SBOM y policy gate',
    version: 'v2.0.0',
    category: 'Security Scanning',
    tags: ['security', 'ci', 'complete'],
    example: 'osdo pipeline generate --template security',
  },
  {
    name: 'osdo-supply-chain',
    type: 'workflow',
    description: 'Seguridad de cadena de suministro: SBOM, provenance SLSA Level 3, firma',
    version: 'v2.0.0',
    category: 'Supply Chain',
    tags: ['slsa', 'sbom', 'provenance'],
    example: 'osdo pipeline generate --template release',
  },
  {
    name: 'osdo-release',
    type: 'workflow',
    description: 'Release seguro con SBOM, provenance y firma de artefactos',
    version: 'v2.0.0',
    category: 'Infrastructure',
    tags: ['release', 'signing'],
    example: 'osdo pipeline generate --template release',
  },
  {
    name: 'osdo-mobile',
    type: 'workflow',
    description: 'Pipeline de seguridad móvil: OWASP Mobile Top 10 y MASVS',
    version: 'v2.0.0',
    category: 'Security Scanning',
    tags: ['mobile', 'android', 'ios'],
    example: 'osdo pipeline generate --template mobile',
  },
  {
    name: 'osdo-web3',
    type: 'workflow',
    description: 'Auditoría de smart contracts: OWASP Smart Contract Top 10',
    version: 'v2.0.0',
    category: 'Security Scanning',
    tags: ['web3', 'solidity', 'smart-contract'],
    example: 'osdo pipeline generate --template web3',
  },
  {
    name: 'osdo-genai',
    type: 'workflow',
    description: 'Seguridad en LLM/GenAI: OWASP GenAI Top 10',
    version: 'v2.0.0',
    category: 'Security Scanning',
    tags: ['genai', 'llm', 'ai'],
    example: 'osdo pipeline generate --template genai',
  },
  {
    name: 'osdo-full-pipeline',
    type: 'workflow',
    description: 'Pipeline completo: security, build, container, policy, release',
    version: 'v2.0.0',
    category: 'Infrastructure',
    tags: ['full', 'ci', 'devops'],
    example: 'osdo pipeline generate --template full',
  },
  {
    name: 'osdo-container-security',
    type: 'workflow',
    description: 'Seguridad de contenedores: Trivy, Hadolint, Dockle y firma de imagen',
    version: 'v2.0.0',
    category: 'Security Scanning',
    tags: ['container', 'docker', 'trivy'],
    example: 'Incluido en osdo-full-pipeline',
  },
  {
    name: 'osdo-iac-security',
    type: 'workflow',
    description: 'Seguridad de IaC: Checkov, KICS y políticas OPA para Terraform/K8s',
    version: 'v2.0.0',
    category: 'Security Scanning',
    tags: ['iac', 'terraform', 'kubernetes'],
    example: 'Incluido en osdo-security-pipeline con --type iac',
  },
  {
    name: 'osdo-devsecops-starter',
    type: 'workflow',
    description: 'Starter mínimo de DevSecOps: SAST + secrets + SCA básico',
    version: 'v2.0.0',
    category: 'Security Scanning',
    tags: ['starter', 'beginner', 'minimal'],
    example: 'osdo pipeline generate --template security',
  },
]

export const CATALOG_TEMPLATES: CatalogItem[] = [
  {
    name: 'web-api',
    type: 'template',
    description: 'REST/GraphQL API con pipeline de seguridad completo',
    version: 'v2.0.0',
    category: 'Infrastructure',
    tags: ['go', 'api', 'rest'],
    example: 'osdo init --template web-api --name my-api',
  },
  {
    name: 'microservice',
    type: 'template',
    description: 'Microservicio en contenedor con manifiestos K8s',
    version: 'v2.0.0',
    category: 'Infrastructure',
    tags: ['go', 'kubernetes', 'docker'],
    example: 'osdo init --template microservice --name my-service',
  },
  {
    name: 'library',
    type: 'template',
    description: 'Librería reutilizable con workflow de publicación seguro',
    version: 'v2.0.0',
    category: 'Infrastructure',
    tags: ['npm', 'library', 'typescript'],
    example: 'osdo init --template library --name my-lib',
  },
  {
    name: 'cli',
    type: 'template',
    description: 'Herramienta CLI con automatización de releases',
    version: 'v2.0.0',
    category: 'Infrastructure',
    tags: ['go', 'cli', 'release'],
    example: 'osdo init --template cli --name my-cli',
  },
  {
    name: 'mobile',
    type: 'template',
    description: 'App móvil con seguridad específica de plataforma',
    version: 'v2.0.0',
    category: 'Security Scanning',
    tags: ['mobile', 'react-native', 'android', 'ios'],
    example: 'osdo init --template mobile --name my-app',
  },
]

export const CATALOG_POLICIES: CatalogItem[] = [
  {
    name: 'kubernetes-security',
    type: 'policy',
    description: 'Políticas de seguridad Kubernetes (OPA/Rego)',
    version: 'v2.0.0',
    category: 'Quality',
    tags: ['k8s', 'opa', 'rego'],
    example: 'osdo catalog add kubernetes-security',
  },
  {
    name: 'terraform-security',
    type: 'policy',
    description: 'Políticas de seguridad Terraform con OPA',
    version: 'v2.0.0',
    category: 'Quality',
    tags: ['terraform', 'opa', 'iac'],
    example: 'osdo catalog add terraform-security',
  },
  {
    name: 'dockerfile-security',
    type: 'policy',
    description: 'Políticas de mejores prácticas para Dockerfile',
    version: 'v2.0.0',
    category: 'Quality',
    tags: ['docker', 'opa', 'container'],
    example: 'osdo catalog add dockerfile-security',
  },
]

/** Catálogo completo combinado */
export const ALL_CATALOG: Record<string, CatalogItem[]> = {
  actions: CATALOG_ACTIONS,
  workflows: CATALOG_WORKFLOWS,
  templates: CATALOG_TEMPLATES,
  policies: CATALOG_POLICIES,
}

/** Busca un componente por nombre en todas las categorías */
export function findCatalogItem(name: string): {item: CatalogItem; category: string} | null {
  for (const [category, items] of Object.entries(ALL_CATALOG)) {
    const found = items.find(i => i.name === name)
    if (found) return {item: found, category}
  }

  return null
}
