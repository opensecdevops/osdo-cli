import {expect} from 'chai'
import {runCommand} from '@oclif/test'

describe('security:scan', () => {
  it('runs security:scan --help', async () => {
    const {stdout} = await runCommand(['security:scan', '--help'])
    expect(stdout).to.include('scan')
    expect(stdout).to.include('--type')
    expect(stdout).to.include('--fail-on')
  })

  it('no falla con error de parsing con flags válidos', async () => {
    const {error} = await runCommand(['security:scan', '--type', 'filesystem', '--output', 'json'])
    // exit 64 = usage error de oclif
    expect(error?.oclif?.exit).to.not.equal(64)
  })

  it('falla con tipo de scan desconocido', async () => {
    const {error} = await runCommand(['security:scan', '--type', 'foobar'])
    expect(error).to.exist
  })
})

describe('security:secrets', () => {
  it('runs security:secrets --help', async () => {
    const {stdout} = await runCommand(['security:secrets', '--help'])
    expect(stdout).to.include('secrets')
    expect(stdout).to.include('--mode')
  })
})

describe('security:policies', () => {
  it('runs security:policies --help', async () => {
    const {stdout} = await runCommand(['security:policies', '--help'])
    expect(stdout).to.include('policies')
    expect(stdout).to.include('--engine')
  })
})

describe('security:report', () => {
  it('runs security:report --help', async () => {
    const {stdout} = await runCommand(['security:report', '--help'])
    expect(stdout).to.include('report')
    expect(stdout).to.include('--format')
  })
})

describe('security:compliance', () => {
  it('runs security:compliance --help', async () => {
    const {stdout} = await runCommand(['security:compliance', '--help'])
    expect(stdout).to.include('compliance')
  })
})
