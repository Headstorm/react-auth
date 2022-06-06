type OpenIDConfiguration = {
  authorization_endpoint: string
  token_endpoint: string
  end_session_endpoint: string
}

type CachedOpenIDConfigurations = { [authority: string]: OpenIDConfiguration }

const cachedOpenIdConfigurations: CachedOpenIDConfigurations = {}

export async function getOpenIDConfiguration(
  authority: string
): Promise<OpenIDConfiguration> {
  if (!cachedOpenIdConfigurations[authority]) {
    cachedOpenIdConfigurations[authority] = await fetchOpenIDConfiguration(
      authority
    )
  }

  return cachedOpenIdConfigurations[authority]
}

async function fetchOpenIDConfiguration(
  authority: string
): Promise<OpenIDConfiguration> {
  const openIdConfigResponse = await fetch(
    `${authority}/.well-known/openid-configuration`
  )

  const openIdConfig: OpenIDConfiguration = await openIdConfigResponse.json()
  return openIdConfig
}
