import {expect} from 'chai'
import {evaluateCoverage, parseWorkflowContents} from '../../../src/lib/audit/workflow-parser.js'

function evaluate(content: string) {
  return evaluateCoverage(parseWorkflowContents([{file: 'ci.yml', content}]))
}

const covered = (result: ReturnType<typeof evaluate>, id: string) =>
  result.coverage.find(c => c.control.id === id)!

describe('audit — jobs.<id>.uses (reusable workflows)', () => {
  it('da crédito a una reusable workflow OSDO del mismo control', () => {
    const result = evaluate(`
name: CI
on: [push]
permissions:
  contents: read
jobs:
  sast:
    uses: opensecdevops/osdo-workflows/.github/workflows/osdo-sast.yml@v2
    with:
      severity: high
`)
    const sast = covered(result, 'sast')
    expect(sast.covered).to.be.true
    expect(sast.isOsdo).to.be.true
    expect(sast.coveredBy).to.equal('opensecdevops/osdo-workflows/.github/workflows/osdo-sast.yml@v2')
    expect(sast.files).to.deep.equal(['ci.yml'])
    expect(result.score).to.equal(14 + 8) // sast (14) + permissions (8)
  })

  it('no da crédito por una reusable de terceros con el mismo nombre de fichero', () => {
    const result = evaluate(`
name: CI
on: [push]
jobs:
  sast:
    uses: someone/else/.github/workflows/osdo-sast.yml@v2
`)
    expect(covered(result, 'sast').covered).to.be.false
  })

  it('exige coincidencia exacta del nombre de la reusable workflow', () => {
    const result = evaluate(`
name: CI
on: [push]
jobs:
  sast:
    uses: opensecdevops/osdo-workflows/.github/workflows/osdo-sast-legacy.yml@v2
`)
    expect(covered(result, 'sast').covered).to.be.false
  })

  it('incluye jobs.<id>.uses en el análisis de actions fijadas por hash', () => {
    const result = evaluate(`
name: CI
on: [push]
jobs:
  sast:
    uses: opensecdevops/osdo-workflows/.github/workflows/osdo-sast.yml@v2
  build:
    uses: ./.github/workflows/local-build.yml
`)
    const [report] = result.pinnedActionsReport
    expect(report.unpinned).to.deep.equal(['opensecdevops/osdo-workflows/.github/workflows/osdo-sast.yml@v2'])
    // la referencia local (./...) no lleva @ver y no cuenta como no fijada
    expect(report.ratio).to.equal(0.5)
  })

  it('sigue leyendo los steps de jobs normales junto a jobs con uses', () => {
    const result = evaluate(`
name: CI
on: [push]
jobs:
  secrets:
    uses: opensecdevops/osdo-workflows/.github/workflows/osdo-secrets-scan.yml@v2
  scan:
    runs-on: ubuntu-latest
    steps:
      - uses: opensecdevops/osdo-actions/actions/osdo-sca@3333333333333333333333333333333333333333
`)
    expect(covered(result, 'secrets').covered).to.be.true
    expect(covered(result, 'sca').covered).to.be.true
  })

  it('evaluateCoverage deja la puntuación bruta y sin excepciones', () => {
    const result = evaluate(`
name: CI
on: [push]
jobs:
  sast:
    uses: opensecdevops/osdo-workflows/.github/workflows/osdo-sast.yml@v2
`)
    expect(result.exceptions).to.deep.equal([])
    expect(result.scoreWithoutExceptions).to.equal(result.score)
  })
})
