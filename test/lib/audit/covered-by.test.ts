import {expect} from 'chai'
import {evaluateCoverage, parseWorkflowContents} from '../../../src/lib/audit/workflow-parser.js'

function evaluate(content: string) {
  return evaluateCoverage(parseWorkflowContents([{file: 'ci.yml', content}]))
}

const covered = (result: ReturnType<typeof evaluate>, id: string) =>
  result.coverage.find(c => c.control.id === id)!

describe('audit — covered_by reporta la action/workflow OSDO, no el último step', () => {
  it('una action OSDO declarada antes de un step de terceros con el mismo control gana', () => {
    const result = evaluate(`
name: CI
on: [push]
permissions:
  contents: read
jobs:
  build:
    runs-on: ubuntu-latest
    steps:
      - uses: opensecdevops/osdo-actions/actions/osdo-sast@v2
      - uses: github/codeql-action/analyze@v3
      - run: npx semgrep --config auto
`)
    const sast = covered(result, 'sast')
    expect(sast.isOsdo).to.be.true
    expect(sast.coveredBy).to.equal('opensecdevops/osdo-actions/actions/osdo-sast@v2')
    expect(sast.files).to.deep.equal(['ci.yml'])
  })

  it('una action OSDO declarada después de un step de terceros sigue siendo la reportada', () => {
    const result = evaluate(`
name: CI
on: [push]
permissions:
  contents: read
jobs:
  build:
    runs-on: ubuntu-latest
    steps:
      - uses: github/codeql-action/analyze@v3
      - run: npx semgrep --config auto
      - uses: opensecdevops/osdo-actions/actions/osdo-sast@v2
`)
    const sast = covered(result, 'sast')
    expect(sast.isOsdo).to.be.true
    expect(sast.coveredBy).to.equal('opensecdevops/osdo-actions/actions/osdo-sast@v2')
  })

  it('una reusable workflow OSDO en jobs.<id>.uses gana a un step run: posterior', () => {
    const result = evaluate(`
name: CI
on: [push]
permissions:
  contents: read
jobs:
  sast:
    uses: opensecdevops/osdo-workflows/.github/workflows/osdo-sast.yml@v2
  lint:
    runs-on: ubuntu-latest
    steps:
      - run: npx semgrep --config auto
`)
    const sast = covered(result, 'sast')
    expect(sast.isOsdo).to.be.true
    expect(sast.coveredBy).to.equal('opensecdevops/osdo-workflows/.github/workflows/osdo-sast.yml@v2')
  })

  it('sin OSDO, una equivalente de terceros gana a un run: posterior', () => {
    const result = evaluate(`
name: CI
on: [push]
permissions:
  contents: read
jobs:
  build:
    runs-on: ubuntu-latest
    steps:
      - run: npx semgrep --config auto
      - uses: github/codeql-action/analyze@v3
`)
    const sast = covered(result, 'sast')
    expect(sast.isOsdo).to.be.false
    expect(sast.coveredBy).to.equal('github/codeql-action/analyze@v3')
  })

  it('entre varias coincidencias del mismo rango, reporta la primera en orden de declaración', () => {
    const result = evaluate(`
name: CI
on: [push]
permissions:
  contents: read
jobs:
  build:
    runs-on: ubuntu-latest
    steps:
      - uses: opensecdevops/osdo-actions/actions/osdo-sast@v1
      - uses: opensecdevops/osdo-actions/actions/osdo-sast@v2
`)
    expect(covered(result, 'sast').coveredBy).to.equal('opensecdevops/osdo-actions/actions/osdo-sast@v1')
  })
})
