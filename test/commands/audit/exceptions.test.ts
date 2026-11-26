import {expect} from 'chai'
import {runCommand} from '@oclif/test'
import {mkdirSync, mkdtempSync, readFileSync, rmSync, writeFileSync} from 'node:fs'
import {tmpdir} from 'node:os'
import {join} from 'node:path'
import {fileURLToPath} from 'node:url'
import {addDays} from '../../../src/lib/audit/exceptions.js'

const FIXTURES = fileURLToPath(new URL('../../fixtures/audit-exceptions/', import.meta.url))
const TODAY = new Date().toISOString().slice(0, 10)
const EXPIRES = addDays(TODAY, 180)

const tmpDirs: string[] = []

/** Repositorio temporal con el workflow de un fixture y, opcionalmente, .osdo/exceptions.yml. */
function makeRepo(fixture: string, exceptions?: string): string {
  const dir = mkdtempSync(join(tmpdir(), 'osdo-audit-'))
  tmpDirs.push(dir)
  mkdirSync(join(dir, '.github', 'workflows'), {recursive: true})
  writeFileSync(
    join(dir, '.github', 'workflows', 'ci.yml'),
    readFileSync(join(FIXTURES, fixture, '.github', 'workflows', 'ci.yml'), 'utf8'),
  )
  if (exceptions !== undefined) {
    mkdirSync(join(dir, '.osdo'), {recursive: true})
    writeFileSync(join(dir, '.osdo', 'exceptions.yml'), exceptions)
  }
  return dir
}

/** Archivo de excepciones válido con caducidad relativa a hoy. */
function exceptionsYaml(controls: string[]): string {
  return controls.map(control => `- control: ${control}
  status: not-applicable
  reason: Motivo suficientemente largo para superar la validación de longitud.
  owner: equipo-plataforma
  approved_by: jefe-seguridad
  expires: ${EXPIRES}
`).join('')
}

async function inDir<T>(dir: string, fn: () => Promise<T>): Promise<T> {
  const previous = process.cwd()
  process.chdir(dir)
  try {
    return await fn()
  } finally {
    process.chdir(previous)
  }
}

describe('osdo audit — excepciones N/A y códigos de salida', () => {
  after(() => {
    for (const dir of tmpDirs) rmSync(dir, {recursive: true, force: true})
  })

  it('aplica .osdo/exceptions.yml del directorio actual (score 78, bruta 66)', async () => {
    const dir = makeRepo('valid', exceptionsYaml(['sbom', 'iac']))
    const {stdout, error} = await inDir(dir, () => runCommand(['audit', '--format', 'json']))
    expect(error).to.be.undefined
    const json = JSON.parse(stdout)
    expect(json.score.total).to.equal(78)
    expect(json.scoreWithoutExceptions).to.equal(66)
    expect(json.exceptions.map((e: {control: string}) => e.control)).to.deep.equal(['sbom', 'iac'])
    expect(json.exceptions[0]).to.include({owner: 'equipo-plataforma', approved_by: 'jefe-seguridad', expires: EXPIRES})
    expect(json.summary.not_applicable).to.equal(2)
    expect(json.summary.gaps).to.equal(6)
  })

  it('--no-exceptions ignora el archivo y no oculta nada', async () => {
    const dir = makeRepo('valid', exceptionsYaml(['sbom', 'iac']))
    const {stdout, error} = await inDir(dir, () => runCommand(['audit', '--format', 'json', '--no-exceptions']))
    expect(error).to.be.undefined
    const json = JSON.parse(stdout)
    expect(json.score.total).to.equal(66)
    expect(json.scoreWithoutExceptions).to.equal(66)
    expect(json.exceptions).to.deep.equal([])
    expect(json.summary.gaps).to.equal(8)
  })

  it('--exceptions <archivo> usa la ruta indicada en lugar del defecto', async () => {
    const dir = makeRepo('valid')
    const file = join(dir, 'custom-exceptions.yml')
    writeFileSync(file, exceptionsYaml(['sbom', 'iac']))
    const {stdout, error} = await inDir(dir, () => runCommand(['audit', '--format', 'json', '--exceptions', file]))
    expect(error).to.be.undefined
    expect(JSON.parse(stdout).score.total).to.equal(78)
  })

  it('exit 2 si se intenta exceptuar un control esencial', async () => {
    const dir = makeRepo('valid', exceptionsYaml(['secrets']))
    const {error} = await inDir(dir, () => runCommand(['audit']))
    expect(error?.oclif?.exit).to.equal(2)
    expect(error?.message).to.include("el control 'secrets' es esencial y no puede exceptuarse")
  })

  it('exit 2 y lista todos los problemas de un archivo inválido', async () => {
    const invalid = readFileSync(join(FIXTURES, 'invalid', '.osdo', 'exceptions.yml'), 'utf8')
    const dir = makeRepo('valid', invalid)
    const {error} = await inDir(dir, () => runCommand(['audit']))
    expect(error?.oclif?.exit).to.equal(2)
    expect(error?.message).to.include('Archivo de excepciones inválido')
    expect(error?.message).to.include("Entrada #1: 'reason' debe tener al menos 20 caracteres")
    expect(error?.message).to.include("Entrada #2: control desconocido 'control-inexistente'")
    expect(error?.message).to.include("Entrada #3: falta el campo obligatorio 'expires'")
    expect(error?.message).to.include("Entrada #4: el control 'sbom' ya está exceptuado en la entrada #1")
  })

  it('exit 2 si --exceptions apunta a un archivo inexistente', async () => {
    const dir = makeRepo('valid')
    const {error} = await inDir(dir, () => runCommand(['audit', '--exceptions', 'no-existe.yml']))
    expect(error?.oclif?.exit).to.equal(2)
    expect(error?.message).to.include('el archivo no existe')
  })

  it('exit 2 con --exceptions y --no-exceptions a la vez', async () => {
    const {error} = await runCommand(['audit', '--exceptions', 'x.yml', '--no-exceptions'])
    expect(error?.oclif?.exit).to.equal(2)
    expect(error?.message).to.include('incompatibles')
  })

  it('exit 2 con --exceptions en --org (las excepciones son por repositorio)', async () => {
    const {error} = await runCommand(['audit', '--org', 'acme', '--exceptions', 'x.yml'])
    expect(error?.oclif?.exit).to.equal(2)
    expect(error?.message).to.include('no es compatible con --org')
  })

  it('exit 3 si --min-score no se alcanza (antes salía con 1)', async () => {
    const dir = makeRepo('valid')
    const {error} = await inDir(dir, () => runCommand(['audit', '--min-score', '70']))
    expect(error?.oclif?.exit).to.equal(3)
    expect(error?.message).to.include('Puntuación insuficiente: 66/100')
  })

  it('--min-score se evalúa con la puntuación tras excepciones', async () => {
    const dir = makeRepo('valid', exceptionsYaml(['sbom', 'iac']))
    const {error} = await inDir(dir, () => runCommand(['audit', '--min-score', '70']))
    expect(error).to.be.undefined
  })

  it('exit 3 con --fail-on-gap si falta un control esencial (antes salía con 1)', async () => {
    const dir = makeRepo('reusable')
    const {error} = await inDir(dir, () => runCommand(['audit', '--fail-on-gap']))
    expect(error?.oclif?.exit).to.equal(3)
    expect(error?.message).to.include('gap(s) en controles Esenciales: SCA (Dependencias)')
  })

  it('--fail-on-gap no falla cuando los esenciales están cubiertos', async () => {
    const dir = makeRepo('valid')
    const {error} = await inDir(dir, () => runCommand(['audit', '--fail-on-gap']))
    expect(error).to.be.undefined
  })

  it('reusable workflow OSDO cuenta como cobertura en el JSON', async () => {
    const dir = makeRepo('reusable')
    const {stdout, error} = await inDir(dir, () => runCommand(['audit', '--format', 'json']))
    expect(error).to.be.undefined
    const json = JSON.parse(stdout)
    const sast = json.controls.find((c: {id: string}) => c.id === 'sast')
    expect(sast.covered).to.be.true
    expect(sast.is_osdo).to.be.true
    expect(json.score.total).to.equal(36) // secrets 14 + sast 14 + permissions 8
  })
})

describe('osdo audit --path', () => {
  it('acepta una ruta absoluta aunque el cwd sea otro directorio', async () => {
    const dir = makeRepo('valid')
    const otherCwd = mkdtempSync(join(tmpdir(), 'osdo-cwd-'))
    tmpDirs.push(otherCwd)
    const {stdout, error} = await inDir(otherCwd, () =>
      runCommand(['audit', '--path', join(dir, '.github', 'workflows'), '--format', 'json']),
    )
    expect(error).to.be.undefined
    expect(JSON.parse(stdout).score.total).to.be.greaterThan(0)
  })
})
