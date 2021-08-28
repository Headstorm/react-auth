# React Auth

OAuth2 + OpenID connect client library for React with support for authorization code flow with PKCE.

## Getting Started
1. Wrap your application in an AuthProvider with the config of your auth server. You can optionally include an AuthGuard which prevents unauthenticated access to any page on your app expect for those explicitly listed.

```tsx
// pages/_app.tsx
export type ChildrenProp = { children: ReactNode }

const AdminAuth: React.FC<ChildrenProp> = ({ children }) => {
  const router = useRouter()

  const appUrl = process.env.NEXT_PUBLIC_APP_URL
  const tenantId = process.env.NEXT_PUBLIC_TENANT_ID
  
  const baseAuthUri = `https://login.microsoftonline.com/${tenantId}/oauth2/v2.0`

  return (
    <AuthProvider
      endpoints={{
        authorizationEndpoint: `${baseAuthUri}/authorize`,
        tokenEndpoint: `${baseAuthUri}/token`,
      }}
      clientId={process.env.NEXT_PUBLIC_CLIENT_ID as string}
      redirectUri={`${appUrl}/login/callback`}
      logoutRedirectUri={`${baseAuthUri}/logout?post_logout_redirect_uri=${appUrl}/logout/success`}
      scope={`openid profile email offline_access YOUR_CUSTOM_SCOPES`}
      cacheStrategy="localStorage"
    >
      <AuthGuard
        whitelistedPaths={['/login', '/login/callback', '/logout/success', '/logout']}
        currentPathName={router.pathname}
      >
        {children}
      </AuthGuard>
    </AuthProvider>
  )
}
```
*This example uses Next.js as a React framework and Azure AD as the OAuth server, but the same pattern applies regardless of Next.js or OAuth server.*

2. Create your /login/callback page to handle exchanging the authorization code for an access token.
```tsx
// pages/login/callback.tsx
const AuthCallback: React.FC = () => {
  const callbackError = useAuthCallback()
  const { redirectToLogin } = useAuth()

  if (!callbackError) {
    return null
  }

  return (
    <p>
      Login error - {callbackError.error} - {callbackError.errorDescription}
      <button type="button" onClick={() => redirectToLogin()}>
        Login
      </button>
    </p>
  )
}

export default AuthCallback
```

The `useAuthCallback()` hook will automatically look for the authorization code in the URL, exchange it for an access token, and redirect the user to their original destination.

3. Create a logout success page that the user should be redirected to once they've successfully logged out.
```tsx
const LogoutSuccess: React.FC = () => {
  const { isAuthenticated, isLoading } = useAuth()
  const router = useRouter()

  useEffect(() => {
    if (isAuthenticated) {
      router.push('/')
    }
  }, [isAuthenticated, router])

  if (!isLoading && !isAuthenticated) {
    return (
      <p>You've been logged out!</p>
    )
  }

  return null
}
```

4. The user is successfully authenticated! You can retrieve the access token by invoking the `getAccessTokenSilently()` function returned by the `useAuth()` hook.

Example using Apollo Client:
```tsx
export const AuthorizedApolloProvider: React.FC<Props> = ({ children }) => {
  const { isAuthenticated, getAccessTokenSilently } = useAuth()
  const client = useMemo(() => {
    const httpLink = createHttpLink({
      uri: process.env.NEXT_PUBLIC_GRAPHQL_URL,
    })

    const authLink = setContext(async () => {
      if (!isAuthenticated) {
        return {}
      }

      const token = await getAccessTokenSilently()
      return {
        headers: {
          Authorization: `Bearer ${token}`,
        },
      }
    })

    return new ApolloClient({
      link: authLink.concat(httpLink),
      cache: new InMemoryCache(),
    })
  }, [isAuthenticated, getAccessTokenSilently])

  return <ApolloProvider client={client}>{children}</ApolloProvider>
}
```

4. Optionally setup /login and /logout pages that redirects the user into the appropriate login/logout flows.
```tsx
// pages/login/index.tsx
const Login: React.FC = () => {
  const { isAuthenticated, redirectToLogin, isLoading } = useAuth()
  const router = useRouter()

  useEffect(() => {
    ;(async () => {
      if (isLoading) {
        return
      }

      if (isAuthenticated) {
        await router.push('/')
        return
      }

      await redirectToLogin()
    })()
  }, [isAuthenticated, isLoading, redirectToLogin, router])

  return null
}
```

```tsx
// pages/logout/index.tsx
const Logout: React.FC = () => {
  const { isAuthenticated, redirectToLogout, isLoading } = useAuth()
  const router = useRouter()

  useEffect(() => {
    ;(async () => {
      if (isLoading) {
        return
      }

      if (isAuthenticated) {
        await redirectToLogout()
        return
      }

      await router.push('/logout/success')
    })()
  }, [isAuthenticated, isLoading, redirectToLogout, router])

  return null
}
```
