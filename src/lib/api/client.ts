import axios, {type AxiosInstance, type AxiosError} from 'axios'

export interface Package {
  id: number
  name: string
  description: string | null
  type: 1 | 2 // 1=Infrastructure, 2=Pipeline
  status: 0 | 1 | 2 | 3 // pending, success, error, processing
  repository: string
  version?: string
  commit?: string
}

export interface PackageDetail extends Package {
  form: PackageConfig
  templates: Array<{file: string; content: string}>
}

export interface PackageConfig {
  name: string
  version: string
  type: 'pipeline' | 'infrastructure'
  description?: string
  template?: string
  file?: string
  language?: string
  blocks: Block[]
}

export interface Block {
  template: string
  name: string
  description?: string | null
  enabled?: boolean
  dependencies?: string[]
  fields: Field[]
  extra?: Extra[]
}

export interface Field {
  type: 'text' | 'switch' | 'select'
  name: string
  label: string
  rules?: string
  default?: string | boolean | number
  info?: string | null
  options?: Option[]
}

export interface Option {
  id: number
  label: string
  value: string
  dependencies?: string[]
}

export interface Extra {
  language: string
  file: string
  template: string
  route?: string
  dependencies?: string[]
}

export interface Deployment {
  id: number
  package_version_id: number
  platform: string
  namespace: string | null
  status: 'pending' | 'deployed' | 'failed'
  message: string | null
  created_at: string
}

export class AppApiClient {
  private http: AxiosInstance

  constructor(baseUrl: string, token?: string) {
    this.http = axios.create({
      baseURL: `${baseUrl}/api/cli`,
      headers: {
        'Content-Type': 'application/json',
        Accept: 'application/json',
        ...(token ? {Authorization: `Bearer ${token}`} : {}),
      },
      timeout: 30_000,
    })

    // Retry on network errors and 5xx
    this.http.interceptors.response.use(
      (response) => response,
      async (error: AxiosError) => {
        const status = error.response?.status
        if (status && status >= 500) {
          // Could add retry logic here
        }
        return Promise.reject(error)
      },
    )
  }

  auth = {
    login: async (email: string, password: string): Promise<{token: string; user: {name: string; email: string}}> => {
      const {data} = await this.http.post<{token: string; user: {name: string; email: string}}>('/auth', {
        email,
        password,
      })
      return data
    },

    logout: async (): Promise<void> => {
      await this.http.delete('/auth')
    },
  }

  packages = {
    list: async (): Promise<Package[]> => {
      const {data} = await this.http.get<Package[]>('/packages')
      return data
    },

    get: async (id: string | number): Promise<PackageDetail> => {
      const {data} = await this.http.get<PackageDetail>(`/packages/${id}`)
      return data
    },

    download: async (id: string | number): Promise<Buffer> => {
      const {data} = await this.http.get<ArrayBuffer>(`/packages/${id}/download`, {
        responseType: 'arraybuffer',
      })
      return Buffer.from(data)
    },
  }

  deployments = {
    create: async (payload: {
      package_version_id: number
      platform: string
      namespace?: string
      metadata?: Record<string, unknown>
    }): Promise<Deployment> => {
      const {data} = await this.http.post<Deployment>('/deployments', payload)
      return data
    },

    updateStatus: async (
      id: string | number,
      payload: {status: 'pending' | 'deployed' | 'failed'; message?: string},
    ): Promise<Deployment> => {
      const {data} = await this.http.patch<Deployment>(`/deployments/${id}/status`, payload)
      return data
    },
  }
}
