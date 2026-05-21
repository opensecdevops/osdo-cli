import {expect} from 'chai'
import {runCommand} from '@oclif/test'

describe('scan', () => {
  it('runs scan --help', async () => {
    const {stdout} = await runCommand(['scan', '--help'])
    expect(stdout).to.include('scan')
    expect(stdout).to.include('--type')
  })

  it('runs scan with json output format', async () => {
    const {error} = await runCommand(['scan', '--type', 'sast', '--output', 'json', '--path', '.'])
    // En el entorno de test no esperamos éxito real (semgrep no está instalado)
    // Solo verificamos que el comando no falla por error de parsing
    expect(error?.oclif?.exit).to.not.equal(64) // 64 = usage error
  })

  it('fails on unknown scan type', async () => {
    const {error} = await runCommand(['scan', '--type', 'unknown'])
    expect(error).to.exist
  })
})
