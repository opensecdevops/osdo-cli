import {expect} from 'chai'
import {runCommand} from '@oclif/test'

describe('app login', () => {
  it('runs login --help', async () => {
    const {stdout} = await runCommand(['app', 'login', '--help'])
    expect(stdout).to.include('Autenticarse')
    expect(stdout).to.include('--url')
  })
})
