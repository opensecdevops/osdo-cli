import axios, {type AxiosInstance} from 'axios'

export interface GitLabWorkflowFile {
  file: string
  content: string
}

export interface GitLabProject {
  id: number
  path_with_namespace: string
  archived: boolean
  default_branch: string
  visibility: string
}

/**
 * GitLabFetcher — Obtiene archivos de pipelines CI desde la API de GitLab.
 *
 * Soporta:
 *   - Proyecto individual:  group/subgroup/project  (o solo el ID numérico)
 *   - Grupo completo:       --gitlab-group mi-empresa (itera todos los proyectos)
 *   - GitLab Self-Hosted:   --gitlab-url https://gitlab.empresa.com
 *
 * Autenticación: Personal Access Token (GITLAB_TOKEN o --token).
 * Permisos mínimos necesarios: api (read_repository para repos privados)
 */
export class GitLabFetcher {
  private http: AxiosInstance

  constructor(baseUrl = 'https://gitlab.com', token?: string) {
    // Normalizar la URL base para asegurar que usamos /api/v4
    const apiBase = baseUrl.replace(/\/+$/, '') + '/api/v4'
    this.http = axios.create({
      baseURL: apiBase,
      headers: {
        'Content-Type': 'application/json',
        ...(token ? {'PRIVATE-TOKEN': token} : {}),
      },
      timeout: 30_000,
    })
  }

  /**
   * Verifica que el token sea válido.
   */
  async verifyToken(): Promise<{username: string; name: string}> {
    const {data} = await this.http.get<{username: string; name: string}>('/user')
    return data
  }

  /**
   * Obtiene los archivos CI de un proyecto.
   * Intenta estos nombres de archivo en orden:
   *   1. .gitlab-ci.yml (el estándar)
   *   2. .gitlab-ci.yaml
   *   3. El campo ci_config_path del proyecto si está definido
   */
  async fetchCiFilesFromProject(
    projectIdOrPath: string | number,
  ): Promise<GitLabWorkflowFile[]> {
    const encodedId = typeof projectIdOrPath === 'string'
      ? encodeURIComponent(projectIdOrPath)
      : projectIdOrPath

    // Obtener info del proyecto para conocer el ci_config_path y la rama por defecto
    let project: {default_branch?: string; ci_config_path?: string}
    try {
      const {data} = await this.http.get<typeof project>(`/projects/${encodedId}`)
      project = data
    } catch {
      project = {default_branch: 'main', ci_config_path: undefined}
    }

    const ref = project.default_branch ?? 'main'
    const ciPaths = ['.gitlab-ci.yml', '.gitlab-ci.yaml']
    if (project.ci_config_path && !ciPaths.includes(project.ci_config_path)) {
      ciPaths.unshift(project.ci_config_path)
    }

    const results: GitLabWorkflowFile[] = []

    for (const ciPath of ciPaths) {
      try {
        const encodedPath = encodeURIComponent(ciPath)
        const {data} = await this.http.get<{content: string; encoding: string}>(
          `/projects/${encodedId}/repository/files/${encodedPath}`,
          {params: {ref}},
        )
        const content = data.encoding === 'base64'
          ? Buffer.from(data.content, 'base64').toString('utf8')
          : data.content
        results.push({file: ciPath, content})
        break // Tomamos el primero que existe
      } catch {
        // El archivo no existe con este nombre, intentar el siguiente
      }
    }

    return results
  }

  /**
   * Lista todos los proyectos de un grupo de GitLab (recursivo, paginado).
   */
  async listGroupProjects(
    group: string,
    options: {includeArchived?: boolean; includeSubgroups?: boolean} = {},
  ): Promise<GitLabProject[]> {
    const {includeArchived = false, includeSubgroups = true} = options
    const encodedGroup = encodeURIComponent(group)
    const projects: GitLabProject[] = []
    let page = 1
    const perPage = 100

    while (true) {
      const {data} = await this.http.get<GitLabProject[]>(
        `/groups/${encodedGroup}/projects`,
        {
          params: {
            per_page: perPage,
            page,
            include_subgroups: includeSubgroups,
            archived: includeArchived ? true : false,
            with_shared: false,
          },
        },
      )

      if (data.length === 0) break
      projects.push(...data.filter(p => includeArchived || !p.archived))
      if (data.length < perPage) break
      page++
    }

    return projects
  }

  /**
   * Obtiene pipelines CI de todos los proyectos de un grupo.
   * Retorna un mapa: proyecto → archivos de pipeline.
   */
  async fetchCiFilesFromGroup(
    group: string,
    options: {
      includeArchived?: boolean
      maxConcurrent?: number
      onProgress?: (done: number, total: number, project: string) => void
    } = {},
  ): Promise<Map<string, GitLabWorkflowFile[]>> {
    const {maxConcurrent = 5, onProgress} = options
    const projects = await this.listGroupProjects(group, {
      includeArchived: options.includeArchived,
    })
    const result = new Map<string, GitLabWorkflowFile[]>()

    for (let i = 0; i < projects.length; i += maxConcurrent) {
      const batch = projects.slice(i, i + maxConcurrent)
      await Promise.allSettled(
        batch.map(async project => {
          onProgress?.(i, projects.length, project.path_with_namespace)
          const files = await this.fetchCiFilesFromProject(project.path_with_namespace)
          if (files.length > 0) {
            result.set(project.path_with_namespace, files)
          }
        }),
      )
    }

    return result
  }

  /**
   * Obtiene detalles de un proyecto específico.
   */
  async getProject(projectIdOrPath: string | number): Promise<GitLabProject> {
    const encodedId = typeof projectIdOrPath === 'string'
      ? encodeURIComponent(projectIdOrPath)
      : projectIdOrPath
    const {data} = await this.http.get<GitLabProject>(`/projects/${encodedId}`)
    return data
  }
}
