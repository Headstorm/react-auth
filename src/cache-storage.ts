import { useCallback, useMemo } from 'react'
import { useAuthSettings } from './auth-settings-context'
import { AuthCache } from './cache-context'

export type AuthCacheStrategy = 'localStorage' | 'sessionStorage'

export const useAuthCacheStorage = () => {
  const { cacheStrategy, cachePrefix } = useAuthSettings()

  const { authCacheKey, authRequestStateKey } = useMemo(() => {
    const formattedCachePrefix = cachePrefix && `${cachePrefix}:`

    return {
      authCacheKey: formattedCachePrefix + 'auth',
      authRequestStateKey: formattedCachePrefix + 'auth:request',
    }
  }, [cachePrefix])

  const storage = useMemo(() => getAuthStorage(cacheStrategy), [cacheStrategy])

  const setAuthCache = useCallback(
    (authState: AuthCache) =>
      storage.setItem(authCacheKey, JSON.stringify(authState)),
    [authCacheKey, storage]
  )

  const clearAuthCache = useCallback(
    () => storage.removeItem(authCacheKey),
    [authCacheKey, storage]
  )

  const getAuthCache = useCallback(() => {
    const authJson = storage.getItem(authCacheKey)
    if (!authJson) {
      return null
    }

    try {
      return authJson ? (JSON.parse(authJson) as AuthCache) : null
    } catch (error) {
      console.error('Failed to load auth state from session storage', error)
      clearAuthCache()
      return null
    }
  }, [authCacheKey, clearAuthCache, storage])

  // request state is always stored in sessionStorage since it doesn't need to persist between browser sessions
  const setAuthRequestState = useCallback(
    <RequestStateType>(authRequestState: RequestStateType) => {
      sessionStorage.setItem(
        authRequestStateKey,
        JSON.stringify(authRequestState)
      )
    },
    [authRequestStateKey]
  )

  const getAuthRequestState = useCallback(<
    RequestStateType
  >(): RequestStateType | null => {
    const requestStateJson = sessionStorage.getItem(authRequestStateKey)
    sessionStorage.removeItem(authRequestStateKey)
    if (!requestStateJson) {
      return null
    }

    try {
      return requestStateJson
        ? (JSON.parse(requestStateJson) as RequestStateType)
        : null
    } catch (error) {
      console.error(
        'Failed to load auth request state from session storage',
        error
      )
      return null
    }
  }, [authRequestStateKey])

  const clearAuthRequestState = useCallback(
    () => sessionStorage.removeItem(authRequestStateKey),
    [authRequestStateKey]
  )

  return {
    getAuthCache,
    setAuthCache,
    clearAuthCache,
    setAuthRequestState,
    getAuthRequestState,
    clearAuthRequestState,
  }
}

interface AuthCacheStorage {
  getItem(key: string): string | null
  setItem(key: string, value: string): void
  removeItem(key: string): void
}

const getAuthStorage = (strategy: AuthCacheStrategy): AuthCacheStorage => {
  if (typeof window === 'undefined') {
    return {
      getItem() {
        return ''
      },
      setItem() {},
      removeItem() {},
    }
  }

  switch (strategy) {
    case 'localStorage':
      return localStorage
    case 'sessionStorage':
      return sessionStorage
  }
}
