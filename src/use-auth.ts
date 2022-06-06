import { useCallback } from 'react'
import { useAuthSettings, User } from './auth-settings-context'
import { getAuthorizationRequest, refreshToken } from './auth-utils'
import { useAuthCache } from './cache-context'
import { useAuthCacheStorage } from './cache-storage'
import { AuthRequestState } from './callback-handler'
import { getOpenIDConfiguration } from './openid-configuration'

type GetAccessTokenSilentlyOptions = {
  scope?: string
}

type RedirectToLoginOptions = {
  loginSuccessRedirectUri?: string
}

export interface AuthState {
  isAuthenticated: boolean
  isLoading: boolean
  user: User | null
  getAccessTokenSilently: (
    options?: GetAccessTokenSilentlyOptions
  ) => Promise<string>
  redirectToLogin: (options?: RedirectToLoginOptions) => Promise<void>
  redirectToLogout: () => Promise<void>
  clearAuthCache: () => void
}

export const useAuth = (): AuthState => {
  const { cache, setAuthTokens, isLoading } = useAuthCache()

  const { setAuthRequestState, clearAuthCache } = useAuthCacheStorage()
  const authSettings = useAuthSettings()

  const redirectToLogin = useCallback(
    async (options?: RedirectToLoginOptions) => {
      const { state, codeVerifier, authRedirectUri } =
        await getAuthorizationRequest({ settings: authSettings })

      const authRequestState: AuthRequestState = {
        state,
        codeVerifier,
        loginSuccessRedirectUri:
          options?.loginSuccessRedirectUri ?? window.location.href,
      }
      setAuthRequestState(authRequestState)

      window.location.href = encodeURI(authRedirectUri)
      return
    },
    [authSettings, setAuthRequestState]
  )

  const redirectToLogout = useCallback(async () => {
    const openIdConfig = await getOpenIDConfiguration(authSettings.authority)

    const queryParams = []
    if (cache?.idToken) {
      queryParams.push(`id_token_hint=${cache.idToken}`)
    }

    if (authSettings.postLogoutRedirectUri) {
      queryParams.push(
        `post_logout_redirect_uri=${authSettings.postLogoutRedirectUri}`
      )
    }

    const queryParamString = queryParams.length
      ? `?${queryParams.join('&')}`
      : ''

    const logoutUri = openIdConfig.end_session_endpoint + queryParamString

    clearAuthCache()
    window.location.href = encodeURI(logoutUri)
  }, [authSettings, clearAuthCache, cache])

  const getAccessTokenSilently = useCallback(
    async (options?: GetAccessTokenSilentlyOptions) => {
      if (!cache) {
        await redirectToLogin()
        return ''
      }

      const scope = options?.scope || authSettings.scope
      const scopedAccessTokenDetails = cache.accessTokens[scope]

      const refreshThreshold = 60 // seconds
      const currentTimestamp = new Date().getTime() / 1000 // unix epoch in seconds

      if (
        scopedAccessTokenDetails &&
        scopedAccessTokenDetails.expireTime - currentTimestamp >
          refreshThreshold
      ) {
        return scopedAccessTokenDetails.token
      }

      // refresh the token
      try {
        const tokens = await refreshToken({
          refreshToken: cache.refreshToken,
          settings: authSettings,
          scope,
        })

        setAuthTokens(tokens)

        return tokens.accessToken
      } catch (error) {
        console.warn('Unable to refresh the access token', error)
        await redirectToLogin()
        return ''
      }
    },
    [authSettings, cache, redirectToLogin, setAuthTokens]
  )

  if (!cache) {
    return {
      isAuthenticated: false,
      isLoading,
      user: null,
      getAccessTokenSilently,
      redirectToLogin,
      redirectToLogout,
      clearAuthCache,
    }
  }

  return {
    isAuthenticated: true,
    isLoading,
    user: cache.user,
    getAccessTokenSilently,
    redirectToLogin,
    redirectToLogout,
    clearAuthCache,
  }
}
