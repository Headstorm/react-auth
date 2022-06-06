import React, { createContext, useContext } from 'react'
import { AuthCacheStrategy } from './cache-storage'
import { ChildrenProp } from './types/children-prop'

export type User = {
  [key: string]: any
}

export interface AuthSettings {
  authority: string
  clientId: string
  redirectUri: string
  postLogoutRedirectUri?: string
  scope: string
  audience?: string
  cacheStrategy: AuthCacheStrategy
  cachePrefix: string
}

const AuthSettingsContext = createContext<AuthSettings>({
  authority: '',
  clientId: '',
  redirectUri: '',
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
