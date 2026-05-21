import {expect} from 'chai'
import {readFileSync} from 'node:fs'
import {join} from 'node:path'
import {fileURLToPath} from 'node:url'
import {parseGitLabPipelineContents, evaluateGitLabCoverage, loadGitLabPipelinesFromDir} from '../../../src/lib/audit/gitlab-parser.js'

const __dirname = fileURLToPath(new URL('.', import.meta.url))
// Fixture: el pipeline real de la OSDO App
const APP_PIPELINE_PATH = join(__dirname, '../../../../app/.gitlab-ci.yml')

describe('GitLab Audit — OSDO App pipeline', () => {
  let result: ReturnType<typeof evaluateGitLabCoverage>

  before(() => {
    const content = readFileSync(APP_PIPELINE_PATH, 'utf8')
    const pipelines = parseGitLabPipelineContents([{file: '.gitlab-ci.yml', content}])
    result = evaluateGitLabCoverage(pipelines)
  })

  it('parsea el pipeline correctamente (1 pipeline)', () => {
    expect(result.workflowCount).to.equal(1)
  })

  // ── Controles CUBIERTOS ────────────────────────────────────────────────────

  it('detecta secrets scanning (gitleaks)', () => {
    const ctrl = result.coverage.find(c => c.control.id === 'secrets')
    expect(ctrl?.covered, 'secrets debe estar cubierto').to.be.true
    expect(ctrl?.coveredBy).to.include('gitleak')
  })

  it('detecta SAST (sonarqube)', () => {
    const ctrl = result.coverage.find(c => c.control.id === 'sast')
    expect(ctrl?.covered, 'sast debe estar cubierto').to.be.true
    expect(ctrl?.coveredBy).to.satisfy((s: string | null) =>
      s?.toLowerCase().includes('sonar') ?? false,
    )
  })

  it('detecta SBOM (cyclonedx)', () => {
    const ctrl = result.coverage.find(c => c.control.id === 'sbom')
    expect(ctrl?.covered, 'sbom debe estar cubierto').to.be.true
    expect(ctrl?.coveredBy).to.satisfy((s: string | null) =>
      s?.toLowerCase().includes('cyclonedx') ?? false,
    )
  })

  it('detecta container scanning (trivy image)', () => {
    const ctrl = result.coverage.find(c => c.control.id === 'container-scan')
    expect(ctrl?.covered, 'container-scan debe estar cubierto').to.be.true
    expect(ctrl?.coveredBy).to.satisfy((s: string | null) =>
      s?.toLowerCase().includes('trivy') ?? false,
    )
  })

  it('detecta IaC scanning (hadolint)', () => {
    const ctrl = result.coverage.find(c => c.control.id === 'iac')
    expect(ctrl?.covered, 'iac debe estar cubierto').to.be.true
    expect(ctrl?.coveredBy).to.satisfy((s: string | null) =>
      s?.toLowerCase().includes('hadolint') ?? false,
    )
  })

  it('detecta image signing (cosign)', () => {
    const ctrl = result.coverage.find(c => c.control.id === 'signing')
    expect(ctrl?.covered, 'signing debe estar cubierto').to.be.true
    expect(ctrl?.coveredBy).to.satisfy((s: string | null) =>
      s?.toLowerCase().includes('cosign') ?? false,
    )
  })

  // ── Controles NO CUBIERTOS ─────────────────────────────────────────────────

  it('reporta SCA como faltante', () => {
    const ctrl = result.coverage.find(c => c.control.id === 'sca')
    expect(ctrl?.covered, 'sca no debe estar cubierto').to.be.false
  })

  it('reporta DAST como faltante', () => {
    const ctrl = result.coverage.find(c => c.control.id === 'dast')
    expect(ctrl?.covered, 'dast no debe estar cubierto').to.be.false
  })

  it('reporta SLSA como faltante', () => {
    const ctrl = result.coverage.find(c => c.control.id === 'slsa')
    expect(ctrl?.covered, 'slsa no debe estar cubierto').to.be.false
  })

  it('reporta policy-gate como faltante', () => {
    const ctrl = result.coverage.find(c => c.control.id === 'policy-gate')
    expect(ctrl?.covered, 'policy-gate no debe estar cubierto').to.be.false
  })

  it('reporta license scanning como faltante', () => {
    const ctrl = result.coverage.find(c => c.control.id === 'license')
    expect(ctrl?.covered, 'license no debe estar cubierto').to.be.false
  })

  // ── Score ──────────────────────────────────────────────────────────────────

  it('score es >= 40 pts (nivel básico con 6 controles cubiertos)', () => {
    expect(result.score).to.be.greaterThanOrEqual(40)
  })

  it('score es < 100 (hay controles faltantes)', () => {
    expect(result.score).to.be.lessThan(100)
  })

  // ── Permisos (rules/only en jobs sensibles) ────────────────────────────────

  it('evalúa control de permisos (jobs sign_image/push_image tienen rules:)', () => {
    // docker_sign y docker_push tienen rules con if: CI_COMMIT_TAG
    const permCtrl = result.coverage.find(c => c.control.id === 'permissions')
    // Al menos tiene una evaluación (covered o no)
    expect(permCtrl).to.exist
  })

  // ── Imágenes fijadas ───────────────────────────────────────────────────────

  it('pinnedActionsReport tiene al menos una imagen no fijada', () => {
    const report = result.pinnedActionsReport[0]
    // trivy:latest, sonar-scanner-cli:latest, node:20-alpine, etc. están sin sha256
    expect(report.unpinned.length).to.be.greaterThan(0)
  })
})

describe('GitLab Audit — loadGitLabPipelinesFromDir', () => {
  it('carga pipeline desde el directorio de la app', () => {
    const appDir = join(__dirname, '../../../../app')
    const pipelines = loadGitLabPipelinesFromDir(appDir)
    expect(pipelines.length).to.be.greaterThanOrEqual(1)
    expect(pipelines[0].file).to.include('gitlab-ci')
  })

  it('retorna [] para un directorio inexistente', () => {
    const pipelines = loadGitLabPipelinesFromDir('/ruta/que/no/existe')
    expect(pipelines).to.deep.equal([])
  })
})

describe('GitLab Audit — pipeline vacío', () => {
  it('score 0 para pipeline sin jobs de seguridad', () => {
    const pipelines = parseGitLabPipelineContents([{
      file: '.gitlab-ci.yml',
      content: `
stages:
  - build
  - deploy

build_app:
  stage: build
  script:
    - npm install
    - npm run build

deploy_prod:
  stage: deploy
  script:
    - kubectl apply -f k8s/
`,
    }])
    const result = evaluateGitLabCoverage(pipelines)
    expect(result.score).to.equal(0)
    expect(result.coverage.filter(c => c.covered).length).to.equal(0)
  })

  it('detecta secrets por script keyword', () => {
    const pipelines = parseGitLabPipelineContents([{
      file: '.gitlab-ci.yml',
      content: `
stages:
  - security

detect_secrets:
  stage: security
  image: ubuntu:latest
  script:
    - trufflehog git https://github.com/example/repo
`,
    }])
    const result = evaluateGitLabCoverage(pipelines)
    const secretsCtrl = result.coverage.find(c => c.control.id === 'secrets')
    expect(secretsCtrl?.covered).to.be.true
    expect(secretsCtrl?.coveredBy).to.include('trufflehog')
  })

  it('detecta SAST por template de GitLab', () => {
    const pipelines = parseGitLabPipelineContents([{
      file: '.gitlab-ci.yml',
      content: `
include:
  - template: Security/SAST.gitlab-ci.yml

stages:
  - test
`,
    }])
    const result = evaluateGitLabCoverage(pipelines)
    const sastCtrl = result.coverage.find(c => c.control.id === 'sast')
    expect(sastCtrl?.covered).to.be.true
    expect(sastCtrl?.coveredBy).to.include('include:')
  })
})
