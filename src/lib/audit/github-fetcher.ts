import axios, {type AxiosInstance} from 'axios'

export interface GitHubWorkflowFile {
  file: string
  content: string
}

export interface GitHubRepo {
  full_name: string
  default_branch: string
  archived: boolean
  private: boolean
}

/**
 * GitHubFetcher — Obtiene archivos de workflows desde la API de GitHub.
 *
 * Soporta:
 *   - Repositorio individual:       owner/repo
 *   - Organización completa:        --org mi-empresa (itera todos los repos)
 *   - GitHub Enterprise Server:     --github-url https://github.empresa.com
 *
 * Autenticación: Bearer token via GITHUB_TOKEN o --token.
 */
export class GitHubFetcher {
  private http: AxiosInstance

  constructor(baseUrl = 'https://api.github.com', token?: string) {
    this.http = axios.create({
      baseURL: baseUrl,
      headers: {
        Accept: 'application/vnd.github.v3+json',
        'X-GitHub-Api-Version': '2022-11-28',
        ...(token ? {Authorization: `Bearer ${token}`} : {}),
      },
      timeout: 30_000,
    })
  }

  /**
   * Obtiene todos los archivos de workflow de un repositorio.
   * Retorna un array de {file, content} listos para pasear con yaml.
   */
  async fetchWorkflowsFromRepo(owner: string, repo: string): Promise<GitHubWorkflowFile[]> {
    const path = `.github/workflows`

    // Listar archivos en el directorio de workflows
    let items: Array<{name: string; path: string; type: string; download_url: string | null}>
    try {
      const {data} = await this.http.get<typeof items>(
        `/repos/${owner}/${repo}/contents/${path}`,
      )
      items = data
    } catch (err: unknown) {
      if (axios.isAxiosError(err) && err.response?.status === 404) {
        return [] // Sin directorio de workflows
      }
      throw err
    }

    // Filtrar solo archivos .yml/.yaml
    const yamlFiles = items.filter(
      i => i.type === 'file' && (i.name.endsWith('.yml') || i.name.endsWith('.yaml')),
    )

    // Descargar contenidos en paralelo
    const results = await Promise.allSettled(
      yamlFiles.map(async (item) => {
        const {data} = await this.http.get<{content: string; encoding: string}>(
          `/repos/${owner}/${repo}/contents/${item.path}`,
        )
        // GitHub devuelve contenido en base64
        const content = Buffer.from(data.content, 'base64').toString('utf8')
        return {file: item.name, content}
      }),
    )

    return results
      .filter((r): r is PromiseFulfilledResult<GitHubWorkflowFile> => r.status === 'fulfilled')
      .map(r => r.value)
  }

  /**
   * Lista todos los repositorios de una organización (paginado).
   * Excluye repositorios archivados por defecto.
   */
  async listOrgRepos(org: string, includeArchived = false): Promise<GitHubRepo[]> {
    const repos: GitHubRepo[] = []
    let page = 1
    const perPage = 100

    while (true) {
      const {data} = await this.http.get<GitHubRepo[]>(`/orgs/${org}/repos`, {
        params: {type: 'all', per_page: perPage, page},
      })

      if (data.length === 0) break
      repos.push(...data.filter(r => includeArchived || !r.archived))
      if (data.length < perPage) break
      page++
    }

    return repos
  }

  /**
   * Obtiene workflows de todos los repositorios de una organización.
   * Retorna un mapa: repo → archivos de workflow.
   *
   * @param maxConcurrent Máximo de repos a consultar en paralelo (evitar rate limiting)
   */
  async fetchWorkflowsFromOrg(
    org: string,
    options: {
      includeArchived?: boolean
      maxConcurrent?: number
      onProgress?: (done: number, total: number, repo: string) => void
    } = {},
  ): Promise<Map<string, GitHubWorkflowFile[]>> {
    const {includeArchived = false, maxConcurrent = 5, onProgress} = options
    const repos = await this.listOrgRepos(org, includeArchived)
    const result = new Map<string, GitHubWorkflowFile[]>()

    // Procesar en lotes para respetar el rate limit de GitHub (5000 req/h)
    for (let i = 0; i < repos.length; i += maxConcurrent) {
      const batch = repos.slice(i, i + maxConcurrent)
      await Promise.allSettled(
        batch.map(async repo => {
          const [owner, name] = repo.full_name.split('/')
          onProgress?.(i, repos.length, repo.full_name)
          const workflows = await this.fetchWorkflowsFromRepo(owner, name)
          if (workflows.length > 0) {
            result.set(repo.full_name, workflows)
          }
        }),
      )
    }

    return result
  }

  /**
   * Verifica que el token tenga los permisos necesarios.
   * Lanza un error descriptivo si no los tiene.
   */
  async verifyToken(): Promise<{login: string; type: string}> {
    const {data} = await this.http.get<{login: string; type: string}>('/user')
    return data
  }

  /**
   * Obtiene los detalles de un repositorio específico.
   */
  async getRepo(owner: string, repo: string): Promise<GitHubRepo> {
    const {data} = await this.http.get<GitHubRepo>(`/repos/${owner}/${repo}`)
    return data
  }
}
