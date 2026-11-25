import {expect} from 'chai'
import {
  AuditExceptionsError,
  addDays,
  applyExceptions,
  parseExceptions,
  type AuditException,
} from '../../../src/lib/audit/exceptions.js'
import {evaluateCoverage, parseWorkflowContents} from '../../../src/lib/audit/workflow-parser.js'

const TODAY = '2026-11-25'

const VALID_ENTRY = `
- control: sbom
  status: not-applicable
  reason: Librería sin artefactos publicados; no hay nada que inventariar.
  owner: equipo-plataforma
  approved_by: jefe-seguridad
  expires: 2027-06-30
`

function entry(overrides: Record<string, string | null>): string {
  const base: Record<string, string> = {
    control: 'sbom',
    status: 'not-applicable',
    reason: 'Motivo suficientemente largo para la validación de longitud.',
    owner: 'equipo-plataforma',
    approved_by: 'jefe-seguridad',
    expires: '2027-06-30',
  }
  const merged = {...base, ...overrides}
  const lines = Object.entries(merged)
    .filter(([, v]) => v !== null)
    .map(([k, v], i) => (i === 0 ? `- ${k}: ${v}` : `  ${k}: ${v}`))
  return lines.join('\n') + '\n'
}

function parseError(content: string): AuditExceptionsError {
  try {
    parseExceptions(content, TODAY, 'exceptions.yml')
  } catch (err) {
    if (err instanceof AuditExceptionsError) return err
    throw err
  }
  throw new Error('se esperaba AuditExceptionsError')
}

describe('audit exceptions — parseExceptions', () => {
  it('acepta una entrada válida y devuelve sus campos', () => {
    const result = parseExceptions(VALID_ENTRY, TODAY)
    expect(result).to.have.length(1)
    expect(result[0]).to.deep.equal({
      control: 'sbom',
      status: 'not-applicable',
      reason: 'Librería sin artefactos publicados; no hay nada que inventariar.',
      owner: 'equipo-plataforma',
      approved_by: 'jefe-seguridad',
      expires: '2027-06-30',
    })
  })

  it('trata la fecha sin comillas como texto YYYY-MM-DD, no como Date', () => {
    const [e] = parseExceptions(VALID_ENTRY, TODAY)
    expect(e.expires).to.be.a('string').and.equal('2027-06-30')
  })

  it('devuelve lista vacía para un archivo vacío', () => {
    expect(parseExceptions('', TODAY)).to.deep.equal([])
    expect(parseExceptions('[]\n', TODAY)).to.deep.equal([])
  })

  it('rechaza una raíz que no es lista', () => {
    const err = parseError('control: sbom\n')
    expect(err.problems[0]).to.include('lista')
  })

  it('rechaza YAML inválido', () => {
    const err = parseError('- control: [sbom\n')
    expect(err.problems[0]).to.include('YAML inválido')
  })

  it('rechaza un control esencial (secrets, sast, sca)', () => {
    for (const control of ['secrets', 'sast', 'sca']) {
      const err = parseError(entry({control}))
      expect(err.problems.join('\n')).to.include(`'${control}' es esencial y no puede exceptuarse`)
    }
  })

  it('rechaza un control desconocido', () => {
    const err = parseError(entry({control: 'control-inexistente'}))
    expect(err.problems).to.deep.equal(["Entrada #1: control desconocido 'control-inexistente'"])
  })

  it('exige reason de al menos 20 caracteres', () => {
    const short = entry({reason: 'x'.repeat(19)})
    expect(parseError(short).problems[0]).to.include("'reason' debe tener al menos 20 caracteres (tiene 19)")
    expect(parseExceptions(entry({reason: 'x'.repeat(20)}), TODAY)).to.have.length(1)
  })

  it('exige todos los campos obligatorios', () => {
    for (const field of ['owner', 'approved_by', 'expires', 'reason', 'status', 'control']) {
      const err = parseError(entry({[field]: null}))
      expect(err.problems.join('\n'), field).to.include(`falta el campo obligatorio '${field}'`)
    }
  })

  it('rechaza campos desconocidos', () => {
    const err = parseError(entry({}) + '  extra: algo\n')
    expect(err.problems).to.include("Entrada #1: campo desconocido 'extra'")
  })

  it('solo admite status not-applicable', () => {
    const err = parseError(entry({status: 'accepted'}))
    expect(err.problems[0]).to.include("'status' debe ser 'not-applicable'")
  })

  it('rechaza una excepción caducada y acepta la que caduca hoy', () => {
    expect(parseError(entry({expires: '2026-11-24'})).problems[0]).to.include('la excepción caducó el 2026-11-24')
    expect(parseExceptions(entry({expires: TODAY}), TODAY)).to.have.length(1)
  })

  it('acepta como máximo 365 días desde hoy', () => {
    expect(addDays(TODAY, 365)).to.equal('2027-11-25')
    expect(parseExceptions(entry({expires: '2027-11-25'}), TODAY)).to.have.length(1)
    const err = parseError(entry({expires: '2027-11-26'}))
    expect(err.problems[0]).to.include("supera el máximo de 365 días desde hoy (2027-11-25)")
  })

  it('rechaza fechas de calendario inválidas y formatos no YYYY-MM-DD', () => {
    expect(parseError(entry({expires: '2027-02-30'})).problems[0]).to.include('fecha válida YYYY-MM-DD')
    expect(parseError(entry({expires: '2027-6-30'})).problems[0]).to.include('fecha válida YYYY-MM-DD')
    expect(parseError(entry({expires: '2027-06-30T00:00:00Z'})).problems[0]).to.include('fecha válida YYYY-MM-DD')
  })

  it('rechaza un control repetido indicando la entrada original', () => {
    const err = parseError(VALID_ENTRY + entry({control: 'sbom'}))
    expect(err.problems).to.deep.equal([
      "Entrada #2: el control 'sbom' ya está exceptuado en la entrada #1",
    ])
  })

  it('informa de todos los problemas en una sola pasada', () => {
    const content = [
      entry({reason: 'corta', expires: '2020-01-01'}),
      entry({control: 'desconocido', extra: 'x'}),
      entry({control: 'iac', expires: null}),
    ].join('')
    const err = parseError(content)
    // entrada 1: reason corta + caducada; entrada 2: control desconocido + campo extra; entrada 3: sin expires
    expect(err.problems).to.have.length(5)
    expect(err.message).to.include('Archivo de excepciones inválido: exceptions.yml')
    expect(err.message).to.include('Entrada #3: falta el campo obligatorio \'expires\'')
  })
})

describe('audit exceptions — applyExceptions', () => {
  // covered: secrets 14 + sast 14 + sca 14 + container-scan 8 + permissions 8 + pinned 8 = 66
  const WORKFLOW = `
name: CI
on: [push]
permissions:
  contents: read
jobs:
  scan:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@11bd71901bbe5b1630ceea73d27597364c9af683
      - uses: opensecdevops/osdo-actions/actions/osdo-secrets-scan@1111111111111111111111111111111111111111
      - uses: opensecdevops/osdo-actions/actions/osdo-sast@2222222222222222222222222222222222222222
      - uses: opensecdevops/osdo-actions/actions/osdo-sca@3333333333333333333333333333333333333333
      - uses: opensecdevops/osdo-actions/actions/osdo-container-scan@4444444444444444444444444444444444444444
`

  const exc = (control: string): AuditException => ({
    control,
    status: 'not-applicable',
    reason: 'Motivo suficientemente largo para la validación de longitud.',
    owner: 'equipo-plataforma',
    approved_by: 'jefe-seguridad',
    expires: '2027-06-30',
  })

  const base = () => evaluateCoverage(parseWorkflowContents([{file: 'ci.yml', content: WORKFLOW}]))

  it('sin excepciones la puntuación coincide con la bruta', () => {
    const result = applyExceptions(base(), [])
    expect(result.score).to.equal(66)
    expect(result.scoreWithoutExceptions).to.equal(66)
    expect(result.exceptions).to.deep.equal([])
    expect(result.coverage.every(c => c.exception === undefined)).to.be.true
  })

  it('excluye los controles exceptuados de numerador y denominador, redondeando hacia abajo', () => {
    // applicable = 100 - sbom(8) - iac(8) = 84; covered applicable = 66 → 66*100/84 = 78.57 → 78
    const result = applyExceptions(base(), [exc('sbom'), exc('iac')])
    expect(result.score).to.equal(78)
    expect(result.scoreWithoutExceptions).to.equal(66)
    expect(result.exceptions.map(e => e.control)).to.deep.equal(['sbom', 'iac'])
    expect(result.coverage.find(c => c.control.id === 'sbom')?.exception?.expires).to.equal('2027-06-30')
    expect(result.coverage.find(c => c.control.id === 'secrets')?.exception).to.be.undefined
  })

  it('un control exceptuado que estaba cubierto no suma puntos', () => {
    // applicable = 100 - container-scan(8) = 92; covered applicable = 58 → 58*100/92 = 63.04 → 63
    const result = applyExceptions(base(), [exc('container-scan')])
    expect(result.score).to.equal(63)
    expect(result.scoreWithoutExceptions).to.equal(66)
  })

  it('no modifica el resultado original', () => {
    const original = base()
    applyExceptions(original, [exc('sbom')])
    expect(original.score).to.equal(66)
    expect(original.exceptions).to.deep.equal([])
  })
})
