import {expect} from 'chai'
import {runCommand} from '@oclif/test'
import {existsSync, mkdirSync, mkdtempSync, readFileSync, rmSync, writeFileSync} from 'node:fs'
import {tmpdir} from 'node:os'
import {join} from 'node:path'

const tmpDirs: string[] = []

function emptyProject(files: Record<string, string> = {}): string {
  const dir = mkdtempSync(join(tmpdir(), 'osdo-certify-'))
  tmpDirs.push(dir)
  for (const [rel, content] of Object.entries(files)) {
    const full = join(dir, rel)
    mkdirSync(join(full, '..'), {recursive: true})
    writeFileSync(full, content)
  }
  return dir
}

const reports = (dir: string) => join(dir, '.osdo', 'reports')

describe('certify — selección de estándares, umbrales y reportes', () => {
  after(() => {
    for (const dir of tmpDirs) rmSync(dir, {recursive: true, force: true})
  })

  describe('reportes', () => {
    it('escribe un reporte combinado y un fichero por estándar seleccionado', async () => {
      const dir = emptyProject()
      const {error} = await runCommand(['certify', '--standards', 'owasp,slsa', '--report', '--path', dir])
      expect(error).to.be.undefined
      expect(existsSync(join(reports(dir), 'certification-report.md'))).to.be.true
      expect(existsSync(join(reports(dir), 'certification-owasp.md'))).to.be.true
      expect(existsSync(join(reports(dir), 'certification-slsa.md'))).to.be.true

      const combined = readFileSync(join(reports(dir), 'certification-report.md'), 'utf8')
      expect(combined).to.include('## OWASP Top 10 2021')
      expect(combined).to.include('## SLSA v1.0')

      const owasp = readFileSync(join(reports(dir), 'certification-owasp.md'), 'utf8')
      expect(owasp).to.include('# Reporte de Certificación: OWASP Top 10 2021')
      expect(owasp).not.to.include('SLSA v1.0')
    })

    it('con --standard all, el reporte combinado no sobrescribe por estándar', async () => {
      const dir = emptyProject()
      const {error} = await runCommand(['certify', '--standard', 'all', '--report', '--path', dir])
      expect(error).to.be.undefined
      const combined = readFileSync(join(reports(dir), 'certification-report.md'), 'utf8')
      for (const name of ['OWASP Top 10 2021', 'SLSA v1.0', 'OpenSSF Scorecard', 'SOC 2 Type II', 'ISO 27001:2022']) {
        expect(combined, name).to.include(`## ${name}`)
      }
      expect(existsSync(join(reports(dir), 'certification-soc2.md'))).to.be.true
    })

    it('usa la ruta absoluta de --path aunque el cwd sea otro', async () => {
      const dir = emptyProject()
      const cwd = process.cwd()
      process.chdir(tmpdir())
      try {
        const {error} = await runCommand(['certify', '--standards', 'owasp', '--report', '--path', dir])
        expect(error).to.be.undefined
      } finally {
        process.chdir(cwd)
      }
      expect(existsSync(join(reports(dir), 'certification-owasp.md'))).to.be.true
    })
  })

  describe('aplicabilidad', () => {
    it('owasp-mobile y smart-contract son N/A en un proyecto sin móvil ni contratos', async () => {
      const dir = emptyProject({'README.md': '# x'})
      const {stdout, error} = await runCommand(['certify', '--standards', 'owasp-mobile,smart-contract', '--report', '--path', dir])
      expect(error).to.be.undefined
      expect(stdout).to.include('N/A')
      expect(existsSync(join(reports(dir), 'certification-owasp-mobile.md'))).to.be.false
      expect(existsSync(join(reports(dir), 'certification-smart-contract.md'))).to.be.false
      const combined = readFileSync(join(reports(dir), 'certification-report.md'), 'utf8')
      expect(combined).to.include('## OWASP Smart Contract Top 10 (N/A)')
    })

    it('smart-contract se evalúa si hay ficheros .sol', async () => {
      const dir = emptyProject({'contracts/Token.sol': 'pragma solidity ^0.8.0;'})
      const {error} = await runCommand(['certify', '--standards', 'smart-contract', '--report', '--path', dir])
      expect(error).to.be.undefined
      expect(existsSync(join(reports(dir), 'certification-smart-contract.md'))).to.be.true
    })

    it('owasp-mobile se evalúa si hay AndroidManifest.xml', async () => {
      const dir = emptyProject({'app/src/main/AndroidManifest.xml': '<manifest/>'})
      const {error} = await runCommand(['certify', '--standards', 'owasp-mobile', '--report', '--path', dir])
      expect(error).to.be.undefined
      expect(existsSync(join(reports(dir), 'certification-owasp-mobile.md'))).to.be.true
    })

    it('si ningún estándar seleccionado aplica, sale con código 0 sin evaluar', async () => {
      const dir = emptyProject()
      const {error, stdout} = await runCommand(['certify', '--standard', 'owasp-mobile', '--path', dir])
      expect(error).to.be.undefined
      expect(stdout).to.include('nada que evaluar')
    })
  })

  describe('umbrales y códigos de salida', () => {
    it('exit 3 si un estándar no alcanza --min-score', async () => {
      const dir = emptyProject()
      const {error} = await runCommand(['certify', '--standards', 'owasp', '--min-score', '100', '--path', dir])
      expect(error?.oclif?.exit).to.equal(3)
    })

    it('--min <estándar>=<n> prevalece sobre --min-score para ese estándar', async () => {
      const dir = emptyProject()
      const {error} = await runCommand(['certify', '--standards', 'owasp,slsa', '--min-score', '0', '--min', 'owasp=100', '--path', dir])
      expect(error?.oclif?.exit).to.equal(3)
      expect(error?.message).to.include('owasp')
      expect(error?.message).not.to.include('slsa')
    })

    it('sin fallos de umbral sale con 0', async () => {
      const dir = emptyProject()
      const {error} = await runCommand(['certify', '--standards', 'owasp', '--min-score', '0', '--path', dir])
      expect(error).to.be.undefined
    })

    it('exit 2 si --min nombra un estándar no seleccionado', async () => {
      const dir = emptyProject()
      const {error} = await runCommand(['certify', '--standards', 'owasp', '--min', 'slsa=50', '--path', dir])
      expect(error?.oclif?.exit).to.equal(2)
    })

    it('exit 2 con formato de --min inválido o puntuación fuera de rango', async () => {
      const dir = emptyProject()
      const bad = await runCommand(['certify', '--standards', 'owasp', '--min', 'owasp', '--path', dir])
      expect(bad.error?.oclif?.exit).to.equal(2)
      const range = await runCommand(['certify', '--standards', 'owasp', '--min', 'owasp=101', '--path', dir])
      expect(range.error?.oclif?.exit).to.equal(2)
    })

    it('exit 2 si se combinan --standard y --standards', async () => {
      const dir = emptyProject()
      const {error} = await runCommand(['certify', '--standard', 'owasp', '--standards', 'slsa', '--path', dir])
      expect(error?.oclif?.exit).to.equal(2)
    })

    it('exit 2 con un estándar desconocido en --standards', async () => {
      const dir = emptyProject()
      const {error} = await runCommand(['certify', '--standards', 'owasp,nope', '--path', dir])
      expect(error?.oclif?.exit).to.equal(2)
      expect(error?.message).to.include('nope')
    })
  })

  describe('salida JSON', () => {
    it('con varios estándares emite un único array JSON válido', async () => {
      const dir = emptyProject()
      const {stdout, error} = await runCommand(['certify', '--standards', 'owasp,owasp-mobile', '--output', 'json', '--path', dir])
      expect(error).to.be.undefined
      const payload = JSON.parse(stdout)
      expect(payload).to.be.an('array').with.lengthOf(2)
      expect(payload[0]).to.include({id: 'owasp', status: 'evaluated', minScore: null, thresholdMet: null})
      expect(payload[1]).to.include({id: 'owasp-mobile', status: 'N/A'})
    })
  })
})
