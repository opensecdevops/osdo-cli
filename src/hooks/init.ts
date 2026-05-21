import type {Hook} from '@oclif/core'

/**
 * Hook de inicialización — se ejecuta antes de cada comando.
 * Equivale a cobra.OnInitialize en root.go.
 */
const hook: Hook<'init'> = async function () {
  // Setup global antes de cualquier comando
  // Por ejemplo: verificar versión de Node, cargar plugins, etc.
}

export default hook
