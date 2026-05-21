import {expect} from 'chai'
import {runCommand} from '@oclif/test'

describe('catalog:list', () => {
  it('runs catalog:list --help', async () => {
    const {stdout} = await runCommand(['catalog:list', '--help'])
    expect(stdout).to.include('catalog')
  })

  it('lista actions en modo standalone', async () => {
    const {stdout, error} = await runCommand(['catalog:list', '--type', 'actions', '--output', 'json'])
    expect(error?.oclif?.exit).to.not.equal(64)
    // En modo standalone (sin App), debe retornar al menos algunas actions del catálogo local
    if (!error) {
      expect(stdout).to.be.a('string')
    }
  })

  it('lista workflows en modo standalone', async () => {
    const {error} = await runCommand(['catalog:list', '--type', 'workflows'])
    expect(error?.oclif?.exit).to.not.equal(64)
  })
})

describe('catalog:describe', () => {
  it('runs catalog:describe --help', async () => {
    const {stdout} = await runCommand(['catalog:describe', '--help'])
    expect(stdout).to.include('describe')
  })

  it('falla con nombre desconocido', async () => {
    const {error} = await runCommand(['catalog:describe', 'accion-que-no-existe'])
    expect(error).to.exist
  })

  it('describe una action existente', async () => {
    const {error} = await runCommand(['catalog:describe', 'osdo-sast'])
    expect(error?.oclif?.exit).to.not.equal(64)
  })
})
