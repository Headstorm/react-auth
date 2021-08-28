import React, { useMemo } from 'react'
import { AuthSettings, AuthSettingsProvider } from './auth-settings-context'
import { AuthCacheProvider } from './cache-context'
import { ChildrenProp } from './types/children-prop'
import { Optional } from './types/optional'

type AuthProviderProps = Optional<AuthSettings, 'cachePrefix'> & ChildrenProp

export const AuthProvider: React.FC<AuthProviderProps> = ({
  endpoints,
  clientId,
  redirectUri,
  logoutRedirectUri,
  scope,
  audience,
  cacheStrategy,
  cachePrefix = '',
  children,
}) => {
  const authSettings = useMemo<AuthSettings>(() => {
    return {
      endpoints: {
        authorizationEndpoint: endpoints.authorizationEndpoint,
        tokenEndpoint: endpoints.tokenEndpoint,
      },
      clientId,
      redirectUri,
      logoutRedirectUri,
      scope,
      audience,
      cacheStrategy,
      cachePrefix,
    }
  }, [
    cachePrefix,
    cacheStrategy,
    clientId,
    endpoints.authorizationEndpoint,
    endpoints.tokenEndpoint,
    logoutRedirectUri,
    redirectUri,
    scope,
  ])

  return (
    <AuthSettingsProvider settings={authSettings}>
      <AuthCacheProvider>{children}</AuthCacheProvider>
    </AuthSettingsProvider>
  )
}
