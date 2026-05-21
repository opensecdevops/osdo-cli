import {expect} from 'chai'
import {runCommand} from '@oclif/test'

describe('certify', () => {
  it('runs certify --help', async () => {
    const {stdout} = await runCommand(['certify', '--help'])
    expect(stdout).to.include('certify')
  })

  it('no falla con error de parsing en directorio sin resultados', async () => {
    const {error} = await runCommand(['certify', '--output', 'json'])
    // exit 64 = usage error en oclif — no debe ocurrir con flags válidos
    expect(error?.oclif?.exit).to.not.equal(64)
  })
})
