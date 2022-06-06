import React, { useMemo } from 'react'
import { AuthSettings, AuthSettingsProvider } from './auth-settings-context'
import { AuthCacheProvider } from './cache-context'
import { ChildrenProp } from './types/children-prop'
import { Optional } from './types/optional'

type AuthProviderProps = Optional<AuthSettings, 'cachePrefix'> & ChildrenProp

export const AuthProvider: React.FC<AuthProviderProps> = ({
  authority,
  clientId,
  redirectUri,
  postLogoutRedirectUri,
  scope,
  audience,
  cacheStrategy,
  cachePrefix = '',
  children,
}) => {
  const authSettings = useMemo<AuthSettings>(() => {
    return {
      authority,
      clientId,
      redirectUri,
      postLogoutRedirectUri,
      scope,
      audience,
      cacheStrategy,
      cachePrefix,
    }
  }, [cachePrefix, cacheStrategy, clientId, authority, redirectUri, scope])

  return (
    <AuthSettingsProvider settings={authSettings}>
      <AuthCacheProvider>{children}</AuthCacheProvider>
    </AuthSettingsProvider>
  )
}
