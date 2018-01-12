import hug
import jwt
import json
from hug_middleware_cors import CORSMiddleware
import requests
from jwt.algorithms import get_default_algorithms

api = hug.API(__name__)
api.http.add_middleware(CORSMiddleware(api))


def token_verify(token):
    access_token = token.replace('Bearer ', '')
    token_header = jwt.get_unverified_header(access_token)
    res = requests.get('http://localhost:5000/.well-known/openid-configuration')
    jwk_uri = res.json()['jwks_uri']
    res = requests.get(jwk_uri)
    jwk_keys = res.json()

    rsa = get_default_algorithms()['RS256']
    key = json.dumps(jwk_keys['keys'][0])
    public_key = rsa.from_jwk(key)

    try:
        result = jwt.decode(access_token, public_key, algorithms=[
                            token_header['alg']], audience='api1')
        return result
    except jwt.DecodeError:
        return False


token_key_authentication = hug.authentication.token(token_verify)


@hug.get('/identity', requires=token_key_authentication)
def root(user: hug.directives.user):
    print(user)
    return user
