class OpenIDConnectSequence < SequenceBase

  title 'OpenID Connect Sequence'
  description 'Verify OpenID Connect functionality of server.'
  modal_before_run

  preconditions 'Client must have ID token.' do
    !@instance.id_token.nil?
  end

  test 'OpenID Provider Configuration information properly returned.',
    'https://openid.net/specs/openid-connect-discovery-1_0.html',
    "Using the Issuer location discovered as described in Section 2 or by other means, the OpenID Provider's configuration information can be retrieved." do

    issuer = @instance.issuer.chomp('/')
    openid_configuration_url = issuer + '/.well-known/openid-configuration'
    @openid_configuration_response = LoggedRestClient.get(openid_configuration_url)
    assert_response_ok(@openid_configuration_response)
    @openid_configuration_response_headers = @openid_configuration_response.headers
    @openid_configuration_response_body = JSON.parse(@openid_configuration_response.body)

  end

  test 'JSON Web Key information properly returned.',
    'https://openid.net/specs/openid-connect-discovery-1_0.html',
    "jwks_uri REQUIRED. URL of the OP's JSON Web Key Set [JWK] document. This contains the signing key(s) the RP uses to validate signatures from the OP." do

    assert !@openid_configuration_response_body.nil?, 'no openid-configuration response body available'
    jwks_uri = @openid_configuration_response_body['jwks_uri']
    assert jwks_uri, 'openid-configuration response did not contain jwks_uri as required'
    @jwk_response = LoggedRestClient.get(jwks_uri)
    assert_response_ok(@jwk_response)
    @jwk_response_headers = @jwk_response.headers
    @jwk_response_body = JSON.parse(@jwk_response.body)
    assert @jwk_response_body.has_key?('keys') && @jwk_response_body['keys'].length > 0, 'JWK response does not have keys as required'
    key_info = @jwk_response_body['keys'][0]
    assert key_info.has_key?('n'), "JWK response does not have public key as required"
    @public_key = key_info['n']
    assert key_info.has_key?('alg'), "JWK response does not have alg as required"
    @alg = key_info['alg']

  end

  test 'Data returned from token exchange contains required OpenID Connect information.',
    'http://openid.net/specs/openid-connect-core-1_0.html#IDTokenValidation',
    'Clients MUST validate the ID Token in the Token Response' do

    assert !@public_key.nil?, 'no public key available'
    assert !@alg.nil?, 'no decryption algorithm available'
    @decoded_token = JWT.decode(@instance.id_token, @public_key, false, { algorithm: @alg }).reduce({}, :merge)
    assert @decoded_token, 'id_token could not be parsed as JWT'
    assert @decoded_token['iss'].chomp('/') == @instance.issuer.chomp('/'), 'id_token iss does not match provided issuer'
    assert @decoded_token['alg'] == @alg, 'id_token alg does not match JWK alg'
    assert @decoded_token['profile'] =~ URI::regexp, 'id_token profile is not a valid URL'

  end

end
