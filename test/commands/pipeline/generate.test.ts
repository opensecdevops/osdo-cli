import {expect} from 'chai'
import {runCommand} from '@oclif/test'

describe('pipeline:generate', () => {
  it('runs pipeline:generate --help', async () => {
    const {stdout} = await runCommand(['pipeline:generate', '--help'])
    expect(stdout).to.include('generate')
    expect(stdout).to.include('--platform')
  })

  it('valida plataforma desconocida', async () => {
    const {error} = await runCommand(['pipeline:generate', '--platform', 'unknown', '--type', 'ci'])
    expect(error).to.exist
  })

  it('genera pipeline para github sin error de parsing', async () => {
    const {error} = await runCommand(['pipeline:generate', '--platform', 'github', '--type', 'ci', '--dry-run'])
    expect(error?.oclif?.exit).to.not.equal(64)
  })
})

describe('pipeline:validate', () => {
  it('runs pipeline:validate --help', async () => {
    const {stdout} = await runCommand(['pipeline:validate', '--help'])
    expect(stdout).to.include('validate')
  })
})

describe('pipeline:sync', () => {
  it('runs pipeline:sync --help', async () => {
    const {stdout} = await runCommand(['pipeline:sync', '--help'])
    expect(stdout).to.include('sync')
    expect(stdout).to.include('--dry-run')
  })
})
