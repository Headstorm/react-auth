import { useEffect, useState } from 'react'
import { useAuthSettings } from './auth-settings-context'
import { redeemToken } from './auth-utils'
import { useAuthCache } from './cache-context'
import { useAuthCacheStorage } from './cache-storage'

export interface AuthRequestState {
  state: string
  codeVerifier: string
  loginSuccessRedirectUri: string
}

export interface AuthCallbackError {
  error: string
  errorDescription: string
}

export const useAuthCallback = () => {
  const authSettings = useAuthSettings()
  const { setAuthTokens } = useAuthCache()
  const { getAuthRequestState, clearAuthRequestState } = useAuthCacheStorage()
  const [callbackError, setCallbackError] = useState<AuthCallbackError | null>(
    null
  )

  useEffect(() => {
    const urlSearchParams = new URLSearchParams(window.location.search)
    const params = Object.fromEntries(urlSearchParams.entries())

    const code: string | undefined = params.code
    const state: string | undefined = params.state
    const error: string | undefined = params.error
    const errorDescription: string | undefined = params.error_description

    if (error && errorDescription) {
      if (
        error === callbackError?.error &&
        errorDescription === callbackError?.errorDescription
      ) {
        return
      }

      setCallbackError({
        error: error,
        errorDescription: errorDescription,
      })
      return
    }

    if (!code || !state) {
      return
    }

    const requestState = getAuthRequestState<AuthRequestState>()

    if (!requestState) {
      return
    }

    if (state !== requestState.state) {
      setCallbackError({
        error: 'Invalid State',
        errorDescription:
          'State received does not match the previously generated state.',
      })
      return
    }

    ;(async () => {
      const tokens = await redeemToken({
        authCode: code,
        codeVerifier: requestState.codeVerifier,
        settings: authSettings,
      })

      if (!tokens) {
        return
      }

      setAuthTokens(tokens)
      clearAuthRequestState()
      window.location.replace(requestState.loginSuccessRedirectUri)
    })()
  }, [
    authSettings,
    setAuthTokens,
    getAuthRequestState,
    clearAuthRequestState,
    callbackError,
    setCallbackError,
  ])

  return callbackError
}
