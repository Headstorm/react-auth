import React, { useEffect, useMemo, useState } from 'react'
import { ChildrenProp } from './types/children-prop'
import { useAuth } from './use-auth'

type Props = {
  whitelistedPaths: string[]
  currentPathName: string
} & ChildrenProp

export const AuthGuard: React.FC<Props> = ({
  whitelistedPaths,
  currentPathName,
  children,
}) => {
  const { isAuthenticated, isLoading, redirectToLogin } = useAuth()
  const [isPathAllowed, setIsPathAllowed] = useState(isAuthenticated)

  const sanitizedWhitelistedPaths = useMemo(() => {
    return whitelistedPaths.map(sanitizePath)
  }, [whitelistedPaths])

  useEffect(() => {
    const pathName = sanitizePath(currentPathName)
    if (isAuthenticated || sanitizedWhitelistedPaths.includes(pathName)) {
      setIsPathAllowed(true)
      return
    }

    if (!isLoading) {
      ;(async () => await redirectToLogin())()
    }
  }, [
    isAuthenticated,
    isLoading,
    redirectToLogin,
    sanitizedWhitelistedPaths,
    currentPathName,
  ])

  if (!isPathAllowed) {
    return null
  }

  return <>{children}</>
}

function stripBeginningSlash(path: string): string {
  return path.startsWith('/') ? path.substr(1) : path
}

function sanitizePath(path: string): string {
  return stripBeginningSlash(path).toLowerCase()
}
