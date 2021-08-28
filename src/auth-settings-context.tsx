import React, { createContext, useContext } from 'react'
import { AuthCacheStrategy } from './cache-storage'
import { ChildrenProp } from './types/children-prop'

export type User = {
  [key: string]: any
}

export interface AuthEndpoints {
  authorizationEndpoint: string
  tokenEndpoint: string
}

export interface AuthSettings {
  endpoints: AuthEndpoints
  clientId: string
  redirectUri: string
  logoutRedirectUri: string
  scope: string
  audience?: string
  cacheStrategy: AuthCacheStrategy
  cachePrefix: string
}

const AuthSettingsContext = createContext<AuthSettings>({
  endpoints: {
    authorizationEndpoint: '',
    tokenEndpoint: '',
  },
  clientId: '',
  redirectUri: '',
  logoutRedirectUri: '',
  scope: '',
  cacheStrategy: 'localStorage',
  cachePrefix: '',
})

export const useAuthSettings = () => useContext(AuthSettingsContext)

type AuthSettingsProviderProps = {
  settings: AuthSettings
} & ChildrenProp

export const AuthSettingsProvider: React.FC<AuthSettingsProviderProps> = ({
  settings,
  children,
}) => {
  return (
    <AuthSettingsContext.Provider value={settings}>
      {children}
    </AuthSettingsContext.Provider>
  )
}
